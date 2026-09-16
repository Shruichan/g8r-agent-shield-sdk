"""
Core AgentShield class — wraps the G8R Console REST API.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from typing import Any, TypeVar

import structlog

from ._version import __version__ as _SDK_VERSION
from .receipts import (
    ReceiptVerificationConfig,
    ReceiptVerificationError,
    ReceiptVerifier,
    assert_receipt_transport,
    build_receipt_request,
)
from .redaction import redact_sensitive_data

try:
    import requests

    _HAS_REQUESTS = True
except ImportError:
    # Import succeeds without `requests` installed; AgentShield.__init__ raises
    # ImportError if instantiated. This lets dependent code import the types
    # (ComplianceMapping, PolicyDecision) without requiring `requests`.
    _HAS_REQUESTS = False

T = TypeVar("T")

# Module-level structured logger. Named `_LOGGER` to avoid colliding with the
# `_log` instance method on AgentShield.
_LOGGER: structlog.stdlib.BoundLogger = structlog.get_logger("g8r_shield")

# Identifies this SDK to the server in the User-Agent header. Lets the
# Console distinguish Python vs. TypeScript callers without polluting
# customer-controlled fields like agent_id. Derived from the installed
# distribution metadata (via `_version.py`) so it can't drift from
# pyproject.toml.
_SDK_USER_AGENT = f"g8r-shield-python/{_SDK_VERSION}"

# Single-retry backoff for transient network errors in _evaluate. Kept short
# so it doesn't add user-visible latency on the happy path or on hard failures.
_RETRY_BACKOFF_SECONDS = 0.5

_ENV_PEP_URL = "G8R_PEP_URL"
_ENV_CONSOLE_URL = "G8R_CONSOLE_URL"

# wrap() hops PEP POST /decide (the SDK facade on the same gateway as /proxy).
# /proxy forwards to a downstream URL; wrap() is decide-then-factory, so /decide
# is the one-hop policy path. Output post-hook stays PEP's job on /proxy.
_PEP_DECIDE_PATH = "/decide"

_OUTCOME_TO_DECISION = {
    "ALLOW": "allowed",
    "DENY": "blocked",
    "REQUIRE_APPROVAL": "escalated",
    "ERROR": "blocked",
}


def _reject_loopback(url: str, field: str) -> str:
    """Strip trailing slash; refuse empty and loopback targets."""
    cleaned = url.strip().rstrip("/")
    if not cleaned:
        raise ValueError(f"{field} is required")
    host = cleaned.lower()
    if (
        "://localhost" in host
        or "://127.0.0.1" in host
        or "://[::1]" in host
        or host.startswith("localhost")
        or host.startswith("127.0.0.1")
    ):
        raise ValueError(
            f"{field} must not target localhost. An SDK that ships prompts must "
            "fail closed rather than silently talk to 127.0.0.1."
        )
    return cleaned


# ── Ambient governance context (sub-agent lineage) ──────────────────────────
# Lineage — the session a call belongs to, plus the chain of agents above it —
# is propagated IMPLICITLY through nested agent calls via `contextvars`, so
# every hop is governed with chain awareness without the caller threading
# anything by hand. `wrap()` reads the ambient context, then extends it around
# the wrapped factory; anything that nests a further g8r_shield call inside
# inherits the extended chain and the same session.
#
# Trust model: this lineage is ADVISORY. Both the session id and the parent
# chain are SELF-ASSERTED by the caller — the Console records them as reported,
# it does not cryptographically verify them. Attestation-bound signing (so a
# child cannot forge or drop its ancestry) is a FUTURE addition; the two wire
# fields are deliberately additive + optional so that upgrade stays
# backward-compatible.


@dataclass(frozen=True)
class _GovernanceContext:
    """The lineage carried alongside a governed call.

    ``session_id`` — a stable id for one logical agent run, threaded across
    nested and multi-turn calls so the Console can stitch a run together.
    ``None`` until a run is established (a top-level ``wrap()``, an explicit
    ``AgentShield.run()`` scope, or a per-instance ``session_id`` default).

    ``agent_chain`` — the ancestor agent-id chain, ordered ROOT-FIRST with the
    IMMEDIATE PARENT LAST. Empty at the top level. Each ``wrap()`` appends its
    own ``agent_id`` before invoking the wrapped factory, so anything nested
    inside inherits the extended chain.

    Frozen and immutable: propagation only ever REPLACES the ambient value
    (via a `contextvars` token), never mutates it in place — so the single
    shared default instance below is safe.
    """

    session_id: str | None = None
    agent_chain: tuple[str, ...] = ()


# Process-wide ambient context. `contextvars` gives the isolation we need for
# free: each asyncio task and each fresh thread sees its own value, so
# concurrent agent runs never bleed lineage into one another. The default is
# the EMPTY context — an un-instrumented call behaves exactly as it did before
# this feature existed (no session, no parent chain on the wire).
_AMBIENT_CONTEXT: ContextVar[_GovernanceContext] = ContextVar(
    # B039 warns against mutable ContextVar defaults (a value shared across
    # contexts that one context could mutate for all). It does not apply here:
    # `_GovernanceContext` is a FROZEN dataclass, so the shared empty default is
    # immutable and read-only — propagation only ever REPLACES it via a token,
    # never mutates it — which is exactly the safe pattern B039 is protecting.
    "g8r_shield_governance_context",
    default=_GovernanceContext(),  # noqa: B039
)


class _RunScope:
    """Context manager that establishes an ambient governance scope for a block.

    Backs both :meth:`AgentShield.run` (group calls under one session) and
    :meth:`AgentShield.child` (declare a manual parent hop). Resolution happens
    on ENTER — reading the ambient context at the moment the block starts — and
    the previous ambient value is restored on EXIT via a `contextvars` token,
    so it is exception-safe and never leaks past the ``with`` block. A fresh
    scope is constructed per ``run()`` / ``child()`` call, so re-use is a
    non-issue.
    """

    __slots__ = ("_explicit_session", "_instance_session", "_push_agent", "_token")

    def __init__(
        self,
        *,
        explicit_session: str | None,
        instance_session: str | None,
        push_agent: str | None = None,
    ) -> None:
        self._explicit_session = explicit_session
        self._instance_session = instance_session
        self._push_agent = push_agent
        self._token: Token[_GovernanceContext] | None = None

    def __enter__(self) -> str:
        ctx = _AMBIENT_CONTEXT.get()
        # Session precedence: an explicit argument wins, then an active ambient
        # run is adopted (so nesting never splits a run), then the instance
        # default, then a freshly minted uuid4.
        session = (
            self._explicit_session or ctx.session_id or self._instance_session or str(uuid.uuid4())
        )
        # child() appends a parent hop; run() leaves the chain untouched.
        chain = ctx.agent_chain + (self._push_agent,) if self._push_agent else ctx.agent_chain
        self._token = _AMBIENT_CONTEXT.set(
            _GovernanceContext(session_id=session, agent_chain=chain)
        )
        return session

    def __exit__(self, *exc_info: object) -> None:
        # Restore the caller's ambient context. Guard against a double-exit
        # leaving a dangling token.
        if self._token is not None:
            _AMBIENT_CONTEXT.reset(self._token)
            self._token = None


@dataclass(frozen=True)
class ComplianceMapping:
    regulation: str
    control_id: str
    control_name: str
    description: str = ""


@dataclass(frozen=True)
class PolicyDecision:
    decision: str  # 'allowed' | 'blocked' | 'escalated'
    reason: str
    violated_rule: str | None
    requires_approval: bool
    session_revoked: bool
    compliance_mappings: list[ComplianceMapping] = field(default_factory=list)
    # Sensitive tokens stripped from the prompt by the local-first redaction
    # layer before it reached the gateway. Empty when the prompt was clean.
    # Parity with the TypeScript SDK's `PolicyCheckResult.redactedTokens`.
    redacted_tokens: list[str] = field(default_factory=list)
    # Verified compact JWS from check(). The current /log endpoint does not store it.
    decision_receipt: str | None = None

    @property
    def is_pending_registration(self) -> bool:
        """Whether this decision means "agent awaiting admin approval".

        v2 Consoles register agents trust-on-first-use: the FIRST call from
        an unknown ``agent_id`` auto-creates a pending registration in the
        Console's Approvals queue. What the SDK observes next depends on the
        server's pending-agent mode:

        * **flag** (the server default) — calls from the pending agent
          evaluate normally under policy while admins approve in the
          background. The caller sees ordinary decisions; this property
          stays False.
        * **block** — calls from the pending agent return ``blocked`` with
          ``requires_approval`` set until an admin approves it. On this
          path ``wrap()`` raises :class:`ShieldBlockedError`, which carries
          the same ``decision`` / ``requires_approval`` pair (and mirrors
          this property), so integrators can distinguish "awaiting admin
          approval in the Approvals queue" from "policy blocked".

        On v2, ``decision == "blocked"`` together with ``requires_approval``
        occurs ONLY for a pending registration in block mode — that
        conjunction IS the pending signal. An admin-DENIED agent comes back
        as ``blocked`` withOUT ``requires_approval``, so it correctly reads
        False here. Branch on this property, never on the human-readable
        ``reason`` string.
        """
        return self.decision == "blocked" and self.requires_approval


@dataclass(frozen=True)
class ShieldLogEntry:
    id: str
    decision: str
    timestamp: str


class ShieldBlockedError(Exception):
    """Raised when the G8R policy engine blocks or escalates a request."""

    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision.decision
        self.reason = decision.reason
        self.violated_rule = decision.violated_rule
        # Carried so handlers can evaluate the v2 pending-registration signal
        # (blocked + requires_approval) without re-fetching the decision —
        # see `is_pending_registration` below.
        self.requires_approval = decision.requires_approval
        self.session_revoked = decision.session_revoked
        self.compliance_mappings = decision.compliance_mappings

    @property
    def is_pending_registration(self) -> bool:
        """Mirror of :attr:`PolicyDecision.is_pending_registration`.

        True when this block means "agent awaiting admin approval in the
        Console's Approvals queue" (v2 trust-on-first-use registration,
        server in block mode) rather than a policy rejection. See the
        :class:`PolicyDecision` property for the full contract.
        """
        return self.decision == "blocked" and self.requires_approval


class ShieldConsoleError(RuntimeError):
    """Raised when the G8R Console returns a non-2xx HTTP response.

    The default string representation is intentionally generic — only the
    status code and a fixed message are exposed via ``str(exc)``. The raw
    response body is preserved on ``.detail`` for callers that explicitly
    opt into inspecting it (e.g. debug logging, error reporting tooling).

    This guards against unintentional disclosure when host frameworks
    surface exception messages to end users (Flask/FastAPI default error
    pages, Django DEBUG mode, generic 500 responses, etc.). A regression
    that lands an internal stack trace, a Cognito error payload, or a
    PII-shaped detail on the server side will not leak through the
    exception message.

    Inherits from :class:`RuntimeError` so existing ``except RuntimeError``
    catch-alls continue to handle the case without change.
    """

    def __init__(self, status_code: int | str, detail: str = "") -> None:
        super().__init__(f"[G8R Shield] Console returned HTTP {status_code}")
        self.status_code = status_code
        self.detail = detail


class ShieldConnectionError(RuntimeError):
    """Raised when the G8R Console is unreachable after the single retry.

    Distinguishes "couldn't reach the server" (connection refused, DNS
    failure, or timeout, even after one retry) from "the server said no"
    (:class:`ShieldConsoleError`). Callers that want to fail open on a
    transient network partition but fail closed on an explicit policy
    rejection can branch on the exception type.

    The message names the ``console_url`` and that a retry was attempted,
    but — unlike :class:`ShieldConsoleError` — there is no response body to
    carry, because the request never completed.

    Inherits from :class:`RuntimeError` so existing ``except RuntimeError``
    catch-alls continue to handle the case without change.
    """


class AgentShield:
    """
    Gate AI agent actions through the G8R policy engine.

    Every call to ``wrap()`` will:

    1. Redact the prompt locally (secrets/PII never leave the process raw).
    2. POST the redacted prompt to PEP ``/decide`` — the one policy hop.
       ``check()`` still hits Console ``/api/sdk/v1/check`` (the documented gap);
       wrap() does not.
    3. Record the interaction in the audit trail via Console ``/api/sdk/v1/log``
       (adjunct; never a second decision).
    4. Raise ``ShieldBlockedError`` if blocked (or if escalated and
       ``block_on_escalated=True``).
    5. Execute the factory callable and return its result if allowed
       (or if escalated and ``block_on_escalated=False``, the default).
       wrap() does not post-process the factory output — output governance is
       PEP ``/proxy``'s job.

    Instances are configured once at construction and are intended to be
    shared across threads / agent loops. All fields are write-once (enforced
    by ``__slots__``); the instance contains no mutable state.

    Args:
        tenant_id: The one hard-required field — identifies the tenant in the
            multi-tenant plane. Must be a non-empty string. No env fallback:
            tenant is call-site identity, not deployment config.
        pep_url: Base URL of the PEP gateway. Required: this argument OR
            ``G8R_PEP_URL``. No ``console_url`` fallback. Loopback is refused.
            wrap() hops ``POST {pep_url}/decide``.
        console_url: Base URL of your deployed G8R Console (audit ``/log`` and
            the ``check()`` gap). Required in effect, but resolved from this
            argument OR the ``G8R_CONSOLE_URL`` env var; construction fails if
            neither is set. Never defaults to localhost.
        api_key: Bearer token for the SDK check/log endpoints — the STATIC
            credential path (deployment shared secret). Required in effect
            unless ``credential_provider`` is supplied; resolved from this
            argument OR the ``G8R_API_KEY`` env var; construction fails if
            neither yields a non-empty value. Mutually exclusive with
            ``credential_provider``.
        credential_provider: Zero-argument callable returning the Bearer
            credential — the DYNAMIC path for short-lived tokens (e.g. an
            OIDC JWT minted via AWS workload identity). Invoked fresh for
            EVERY request (both ``/check`` and ``/log``) so a token that
            expires mid-session never goes stale inside a long-lived
            AgentShield instance. Mutually exclusive with an explicit
            ``api_key`` (``ValueError`` if both are passed); when supplied,
            the ``G8R_API_KEY`` env var is ignored. Provider failures raise
            ``ShieldConnectionError`` on the check path — fail closed, the
            wrapped LLM call never executes. The returned value is never
            logged.
        department: Functional department (e.g. 'Legal', 'Finance').
        user_id: Identifier of the end-user initiating the action.
        employee_name: Human-readable name for audit trail.
        ai_model: Model identifier (e.g. 'anthropic.claude-3-5-sonnet-20241022-v2:0').
        agent_id: Logical agent identifier registered in the G8R console.
        session_id: Optional per-instance default governance session id. When
            set, calls from this instance are grouped under it unless an
            enclosing ``run()`` scope or a propagated nested context supplies
            one (those take precedence). ``None`` (the default) means a session
            is established only when a ``run()`` scope or a top-level ``wrap()``
            mints one — a lone ``check()`` then sends no session, exactly as
            before. Governance lineage is ADVISORY / self-asserted (see the
            module-level note); it is sent, never used to decide.
        timeout: HTTP request timeout in seconds (default: 10.0).
        block_on_escalated: When True, ``wrap()`` raises ``ShieldBlockedError`` on
            escalated decisions instead of proceeding with a warning. Default
            False — matches the TypeScript SDK contract where escalated actions
            proceed pending out-of-band human review. Set True for stricter
            deployments (e.g. regulated-industry tenants) that prefer fail-closed.
    """

    __slots__ = (
        "_pep_url",
        "_console_url",
        "_api_key",
        "_credential_provider",
        "_tenant_id",
        "_department",
        "_user_id",
        "_employee_name",
        "_ai_model",
        "_agent_id",
        "_session_id",
        "_timeout",
        "_block_on_escalated",
        "_receipt_verifier",
    )

    def __init__(
        self,
        *,
        tenant_id: str,
        pep_url: str | None = None,
        console_url: str | None = None,
        api_key: str | None = None,
        department: str = "General",
        user_id: str = "unknown",
        employee_name: str | None = None,
        ai_model: str = "unknown",
        agent_id: str = "sdk-client",
        session_id: str | None = None,
        timeout: float = 10.0,
        block_on_escalated: bool = False,
        credential_provider: Callable[[], str] | None = None,
        receipt_verification: ReceiptVerificationConfig | None = None,
    ) -> None:
        if not _HAS_REQUESTS:
            raise ImportError(
                "g8r-shield requires 'requests'. Install it with: pip install requests"
            )

        if not tenant_id:
            raise ValueError("tenant_id is required")

        resolved_url = console_url or os.environ.get(_ENV_CONSOLE_URL)
        if not resolved_url:
            raise ValueError(
                "console_url is required. Pass console_url=... or set the G8R_CONSOLE_URL env var. "
                "An SDK that ships customer prompts and API keys must never default to localhost — "
                "a misconfigured agent would silently exfiltrate to whatever happens to be bound on "
                "127.0.0.1 in the runtime environment."
            )
        self._console_url = resolved_url.strip().rstrip("/")

        resolved_pep = pep_url or os.environ.get(_ENV_PEP_URL)
        if not resolved_pep:
            raise ValueError(
                "pep_url is required. Pass pep_url=... or set the G8R_PEP_URL env var. "
                "wrap() hops the PEP; there is no console_url fallback and no localhost default."
            )
        self._pep_url = _reject_loopback(resolved_pep, "pep_url")

        if credential_provider is not None and api_key is not None:
            # Two explicit credential sources is a config bug, not a
            # preference to guess at. Fail fast rather than silently
            # picking one and leaving the other dead.
            raise ValueError(
                "api_key and credential_provider are mutually exclusive. "
                "Pass the static shared secret OR a provider callable, not both."
            )
        self._credential_provider = credential_provider
        if credential_provider is not None:
            # Dynamic path: the provider is the sole credential source. The
            # G8R_API_KEY env var is deliberately NOT consulted — a stale
            # secret left in the deployment environment must never shadow
            # the short-lived tokens the caller opted into.
            self._api_key = ""
        else:
            self._api_key = api_key or os.environ.get("G8R_API_KEY") or ""
            if not self._api_key:
                raise ValueError(
                    "G8R API key is required. Pass api_key=... or set the G8R_API_KEY env var."
                )

        self._tenant_id = tenant_id
        self._department = department
        self._user_id = user_id
        self._employee_name = employee_name
        self._ai_model = ai_model
        self._agent_id = agent_id
        self._session_id = session_id
        self._timeout = timeout
        self._receipt_verifier = (
            ReceiptVerifier(receipt_verification) if receipt_verification is not None else None
        )
        if self._receipt_verifier is not None:
            assert_receipt_transport(self._pep_url)
            assert_receipt_transport(self._console_url)
        # Requiring approval is not permission to run the callback.
        self._block_on_escalated = self._receipt_verifier is not None or block_on_escalated

    def __repr__(self) -> str:
        # Deliberately omits api_key — never expose it in logs or repr output.
        # tenant_id is not secret; include it for operational clarity.
        return (
            f"AgentShield(pep_url={self._pep_url!r}, "
            f"console_url={self._console_url!r}, "
            f"tenant_id={self._tenant_id!r}, "
            f"agent_id={self._agent_id!r}, department={self._department!r})"
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def check(
        self,
        prompt: str,
        *,
        request_id: str | None = None,
        log: bool = True,
    ) -> PolicyDecision:
        """
        Evaluate a prompt against the policy engine without executing anything.

        Returns a :class:`PolicyDecision`. Does NOT raise on blocked/escalated —
        use the returned decision to decide what to do next.

        Governance lineage (``sessionId`` + ``parentAgents``) is read from the
        ambient context and SENT on both ``/check`` and ``/log`` when a run or
        nesting is in effect. Unlike ``wrap()``, ``check()`` is a POINT
        evaluation — it does not open a nested scope of its own. A lone
        ``check()`` outside any run sends neither field (backward-compatible).

        Args:
            prompt: The raw prompt or action string to evaluate.
            request_id: Explicit correlation id to stamp on this evaluation.
                When ``None`` (the default), a fresh uuid4 is minted per call.
                When provided, it is used verbatim on ``/check`` and — if
                ``log`` is True — the SAME id is threaded to ``/log`` so the
                policy decision and the audit line join end-to-end. ``wrap()``
                passes its own id here to correlate the whole invocation.
            log: Whether to record this evaluation in the audit trail. Default
                True so that direct ``check()`` calls don't create blind spots
                in the Console audit record. Pass ``log=False`` if you intend
                to follow up with ``wrap()`` for the same prompt — ``wrap()``
                logs internally and duplicate entries would result.

        Note: when called standalone with ``request_id=None``, each internal
        call (``_evaluate`` and ``_log``) mints its own id. Pass an explicit
        ``request_id`` (or use ``wrap()``) for single-id end-to-end
        correlation across check and log.
        """
        # Mint one id up front (when the caller didn't supply one) so the same
        # value stamps both /check and /log — otherwise _evaluate and _log each
        # mint their own and the two server-side lines can't be joined.
        if request_id is None:
            request_id = str(uuid.uuid4())
        decision = self._evaluate(prompt, request_id=request_id)
        if log:
            self._log(prompt, decision, request_id=request_id)
        return decision

    def wrap(self, factory: Callable[[], T], prompt: str) -> T:
        """
        Evaluate ``prompt`` through the policy engine, then call ``factory`` if allowed.

        Args:
            factory: Zero-argument callable that performs the LLM/agent action.
            prompt: The raw prompt or action string to evaluate.

        Returns:
            Whatever ``factory()`` returns.

        Raises:
            ShieldBlockedError: If the policy engine blocks the request. Escalated
                requests proceed (with a warning) by default, mirroring the
                TypeScript SDK contract. Set ``block_on_escalated=True`` at
                construction time to raise on escalated instead.

        Sub-agent lineage: ``wrap()`` reads the ambient governance context and
        governs this call under it — sending ``sessionId`` and the ancestor
        ``parentAgents`` chain — then, if the decision ALLOWS (or escalates and
        proceeds), runs ``factory()`` inside a scope that extends the chain with
        this instance's ``agent_id``. Any g8r_shield call nested inside
        ``factory()`` therefore inherits the SAME session and this agent as its
        immediate parent — with no manual instrumentation. A top-level
        ``wrap()`` (no enclosing run) mints a fresh session and sends an empty
        parent chain. Lineage is sent, never used to decide, and is advisory /
        self-asserted (see the module-level note).
        """
        # Generate a single request_id for this wrap() invocation and thread
        # it through both the policy check and the audit log so the two
        # server-side log lines can be joined end-to-end under a single
        # correlation id. Without this, each internal call mints its own uuid4
        # and the policy→action linkage is lost.
        request_id = str(uuid.uuid4())

        # ── Resolve governance lineage for this invocation ──────────────────
        # Inherit the session from the ambient context if a run is already in
        # flight, else this instance's default, else mint one — a top-level
        # wrap() always establishes a run. ``parent_agents`` is the chain of
        # everyone ABOVE this agent (empty at the top level); this agent is not
        # in it yet — it is appended only around factory() below.
        ambient = _AMBIENT_CONTEXT.get()
        session = ambient.session_id or self._session_id or str(uuid.uuid4())
        parent_agents = ambient.agent_chain

        # Pin the resolved session + parent chain as the ambient context for
        # THIS agent's own /check and /log, so the suppressed-log check() call
        # and the explicit _log() below both report the same session and
        # ancestry (a freshly minted session would otherwise be invisible to
        # them, since they read the ambient context). Restored unconditionally
        # in the finally — allow, deny, escalate, or raise — via token reset,
        # so lineage never leaks past the call that established it.
        eval_token = _AMBIENT_CONTEXT.set(
            _GovernanceContext(session_id=session, agent_chain=parent_agents)
        )
        try:
            # One PEP hop. Do NOT call check() — that POSTs Console /check on
            # the same prompt (the gap wrap() exists to close).
            decision = self._evaluate_pep(prompt, request_id=request_id)

            # Audit-log the attempt regardless of decision so it appears in the
            # Console audit trail. Done before enforcement so blocked decisions
            # are recorded even if downstream code never sees them.
            self._log(prompt, decision, request_id=request_id)

            if decision.decision == "allowed":
                return self._invoke_in_scope(
                    factory, session_id=session, parent_agents=parent_agents
                )

            if decision.decision == "blocked":
                if decision.session_revoked:
                    _LOGGER.warning(
                        "session_revoked",
                        tenant_id=self._tenant_id,
                        agent_id=self._agent_id,
                        reason=decision.reason,
                    )
                raise ShieldBlockedError(decision)

            if decision.decision == "escalated":
                if self._block_on_escalated:
                    # Strict mode — treat escalated like blocked. Caller opted
                    # in at construction time.
                    raise ShieldBlockedError(decision)
                _LOGGER.warning(
                    "action_escalated",
                    tenant_id=self._tenant_id,
                    agent_id=self._agent_id,
                    reason=decision.reason,
                )
                return self._invoke_in_scope(
                    factory, session_id=session, parent_agents=parent_agents
                )

            # Exhaustive switch: any decision value we don't recognise fails
            # CLOSED rather than silently proceeding to factory(). Mirrors the
            # TypeScript SDK's ts-pattern `.exhaustive()`. A future 4th decision
            # value surfaces here loudly instead of being treated as "allowed"
            # by omission.
            raise ShieldBlockedError(
                PolicyDecision(
                    decision=decision.decision,
                    reason=(
                        f"[G8R Shield] Unrecognised policy decision "
                        f"{decision.decision!r}; failing closed."
                    ),
                    violated_rule=decision.violated_rule,
                    requires_approval=decision.requires_approval,
                    session_revoked=decision.session_revoked,
                    compliance_mappings=decision.compliance_mappings,
                    redacted_tokens=decision.redacted_tokens,
                )
            )
        finally:
            # Restore the caller's ambient context. Even when factory() ran in
            # its own extended scope (already restored by _invoke_in_scope),
            # this unwinds the eval-time pin so nothing leaks to sibling calls.
            _AMBIENT_CONTEXT.reset(eval_token)

    def run(self, session_id: str | None = None) -> _RunScope:
        """Group a block of calls under one governance session, without ``wrap()``.

        Use as a context manager to establish (or adopt) an ambient session
        that every ``check()`` / ``wrap()`` inside the block reports under::

            with shield.run() as session_id:
                shield.check("step one")
                shield.wrap(lambda: call_llm(prompt), prompt)  # same session

        Resolution: an explicit ``session_id`` argument wins; otherwise an
        already-active ambient session is adopted (so nesting ``run()`` does not
        split a run), then this instance's default, then a freshly minted
        uuid4. The active session id is yielded for convenience. The agent
        chain is left untouched — ``run()`` establishes a session, not a
        parent hop. The previous ambient context is restored on exit, even on
        exception (contextvars token reset).
        """
        return _RunScope(explicit_session=session_id, instance_session=self._session_id)

    def child(self, agent_id: str) -> _RunScope:
        """Manually declare a nested agent hop, for nesting outside ``wrap()``.

        ``wrap()`` propagates lineage automatically; reach for ``child()`` only
        when a nested agent runs OUTSIDE a wrapped factory but should still be
        governed as a descendant::

            with shield.child(agent_id="planner"):
                shield.wrap(lambda: call_llm(prompt), prompt)  # parentAgents=[..., "planner"]

        Appends ``agent_id`` to the ambient chain (root-first, immediate-parent
        last) for the block, carrying the current session (minting one if none
        is active). The previous context is restored on exit, even on exception.
        """
        return _RunScope(
            explicit_session=None, instance_session=self._session_id, push_agent=agent_id
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _invoke_in_scope(
        self,
        factory: Callable[[], T],
        *,
        session_id: str,
        parent_agents: tuple[str, ...],
    ) -> T:
        """Run ``factory()`` with the ambient context extended by this agent.

        Sets the ambient governance context to the resolved session plus the
        parent chain with this instance's ``agent_id`` APPENDED (root-first,
        immediate-parent last), so any g8r_shield call nested inside
        ``factory()`` inherits the same session and this agent as its immediate
        parent. The previous context is restored on exit — even if
        ``factory()`` raises — via `contextvars` token reset.
        """
        nested_token = _AMBIENT_CONTEXT.set(
            _GovernanceContext(
                session_id=session_id,
                agent_chain=parent_agents + (self._agent_id,),
            )
        )
        try:
            return factory()
        finally:
            _AMBIENT_CONTEXT.reset(nested_token)

    def _lineage_fields(self) -> dict[str, Any]:
        """Build the additive lineage fragment for an outbound request body.

        Reads the ambient governance context and folds in this instance's
        ``session_id`` default. Both fields are OPTIONAL on the wire and are
        OMITTED when empty, so a call with no run and no nesting sends exactly
        the body it sent before this feature existed (backward-compatible):

        * ``sessionId`` — the ambient session, else the instance default;
          absent when neither is set.
        * ``parentAgents`` — the ancestor chain (root-first, immediate-parent
          last); absent at the top level.

        Sent only; lineage never influences the policy decision.
        """
        ctx = _AMBIENT_CONTEXT.get()
        fields: dict[str, Any] = {}
        session_id = ctx.session_id or self._session_id
        if session_id:
            fields["sessionId"] = session_id
        if ctx.agent_chain:
            fields["parentAgents"] = list(ctx.agent_chain)
        return fields

    def _bearer_credential(self) -> str:
        """Resolve the Bearer value for ONE outbound request.

        Static path: the api_key resolved at construction. Dynamic path: the
        credential_provider is invoked fresh on every call — never cached —
        so short-lived tokens (OIDC JWTs from AWS workload identity) stay
        valid across a long-lived AgentShield instance.

        A provider failure is wrapped in :class:`ShieldConnectionError`
        rather than surfaced raw: like a connection failure, the request
        never completed and there is no server response to carry — and on
        the check path the caller fails CLOSED (the wrapped LLM call never
        runs) instead of proceeding unevaluated. The provider's exception is
        chained as ``__cause__``; its message is deliberately kept out of
        ours, and the returned credential is never logged.
        """
        if self._credential_provider is None:
            return self._api_key
        try:
            return self._credential_provider()
        except Exception as exc:
            raise ShieldConnectionError(
                "[G8R Shield] credential_provider raised while resolving the "
                "Bearer credential; failing closed. See __cause__ for the "
                "underlying error."
            ) from exc

    def _prepare_receipt_request(
        self, endpoint: str, payload: dict[str, Any],
        headers: dict[str, str | bytes], request_id: str,
    ) -> dict[str, Any] | None:
        if self._receipt_verifier is None:
            return None
        wire_headers = {
            name: value.decode("ascii") if isinstance(value, bytes) else value
            for name, value in headers.items()
        }
        request = build_receipt_request(
            endpoint=endpoint, tenant_id=self._tenant_id, agent_id=self._agent_id,
            request_id=request_id, headers=wire_headers, body=payload,
        )
        headers["X-G8R-Receipt-Nonce"] = request["nonce"]
        headers["X-G8R-Receipt-Version"] = "1"
        return request

    def _verified_policy_decision(
        self, data: Any, request: dict[str, Any], tokens: list[str],
    ) -> PolicyDecision:
        if self._receipt_verifier is None:
            raise ReceiptVerificationError("Receipt verifier is required")
        receipt = self._receipt_verifier.verify_response(data, request)
        decision = receipt.decision
        return PolicyDecision(
            decision=decision["decision"], reason=decision["reason"],
            violated_rule=decision["violatedRule"],
            requires_approval=decision["requiresApproval"],
            session_revoked=decision["sessionRevoked"],
            compliance_mappings=[ComplianceMapping(
                regulation=m["regulation"], control_id=m["controlId"],
                control_name=m["controlName"], description=m["description"],
            ) for m in decision["complianceMappings"]],
            redacted_tokens=tokens, decision_receipt=receipt.token,
        )

    def _evaluate(self, prompt: str, request_id: str | None = None) -> PolicyDecision:
        # `request_id` is generated per-call by default. `wrap()` passes its
        # own value so /check and /log share a single correlation id.
        if request_id is None:
            request_id = str(uuid.uuid4())
        # Local-first redaction (local-first VPC layer): strip signing keys,
        # custodial ids, and high-entropy material BEFORE the prompt leaves
        # the process — the gateway only ever sees the redacted form. Parity
        # with the TypeScript SDK's check() path.
        redaction = redact_sensitive_data(prompt)
        url = f"{self._console_url}/api/sdk/v1/check"
        # Annotated as `dict[str, str | bytes]` — `requests.post`'s
        # `headers` parameter is typed as `MutableMapping[str, str | bytes]`
        # under mypy 2.1+ with the latest `types-requests` stubs.
        # `dict[str, str]` is NOT assignable to that (MutableMapping is
        # invariant in value type), so we declare the literal at the
        # widened type. Pre-existing fix surfaced when CI bumped mypy
        # from 1.19 → 2.1.0 and requests stubs from 2.32 → 2.34.
        #
        # The credential is resolved once per REQUEST (before the retry
        # loop): the retry re-sends the same request, and a provider
        # failure is a local credential problem — retrying the provider
        # here would just mask misconfiguration. _bearer_credential
        # raises ShieldConnectionError itself on provider failure, so
        # the check path fails closed before anything goes on the wire.
        headers: dict[str, str | bytes] = {
            "Authorization": f"Bearer {self._bearer_credential()}",
            "Content-Type": "application/json",
            "User-Agent": _SDK_USER_AGENT,
        }
        # NOTE: employeeName is deliberately NOT sent on /check. It is an
        # audit-trail label that belongs only on /log (where it falls back to
        # user_id). Keeping it off /check matches the TypeScript SDK, which
        # never sent it, so both SDKs put the same field set on the wire.
        payload: dict[str, Any] = {
            "input": redaction.redacted,
            "tenantId": self._tenant_id,
            "requestId": request_id,
            "department": self._department,
            "userId": self._user_id,
            "aiModel": self._ai_model,
            "agentId": self._agent_id,
            # Additive sub-agent lineage — sessionId + parentAgents when a run
            # or nesting is in effect; absent otherwise (see `_lineage_fields`).
            **self._lineage_fields(),
        }

        # Single retry on transient network failures. Hard failures (4xx HTTP
        # responses, including 401/403) are surfaced immediately — retrying
        # those is just doubling the user-visible latency.
        receipt_request = self._prepare_receipt_request(
            "/api/sdk/v1/check", payload, headers, request_id,
        )
        response = None
        last_exc: Exception | None = None
        for attempt in range(2):
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=self._timeout)
                response.raise_for_status()
                break
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                last_exc = exc
                if attempt == 0:
                    time.sleep(_RETRY_BACKOFF_SECONDS)
                    continue
                # Named type so callers can tell "couldn't reach the server"
                # apart from "the server said no" (ShieldConsoleError).
                # Subclasses RuntimeError, so existing catch-alls still fire.
                raise ShieldConnectionError(
                    f"[G8R Shield] Could not connect to console at {self._console_url} "
                    f"after retry. Is the console running?"
                ) from exc
            except requests.exceptions.HTTPError as exc:
                # `response` is bound when raise_for_status fires. The raw
                # body is preserved on `.detail` for opt-in inspection but
                # is NOT included in `str(exc)` — host frameworks that
                # surface exception messages to end users would otherwise
                # echo internal error detail (stack traces, auth payloads,
                # PII shapes from upstream services). See
                # `ShieldConsoleError` for the threat-model rationale.
                status = response.status_code if response is not None else "?"
                body = response.text if response is not None else ""
                raise ShieldConsoleError(status, body) from exc

        # Defensive: should never reach here without `response` bound, but
        # appease the type checker for the case where the loop body changes.
        if response is None:
            raise ShieldConnectionError(
                f"[G8R Shield] Could not connect to console at {self._console_url}"
            ) from last_exc

        data = response.json()
        if receipt_request is not None:
            return self._verified_policy_decision(data, receipt_request, redaction.tokens_replaced)
        mappings = [
            ComplianceMapping(
                regulation=m.get("regulation", ""),
                control_id=m.get("controlId", ""),
                control_name=m.get("controlName", ""),
                description=m.get("description", ""),
            )
            for m in data.get("complianceMappings", [])
        ]
        return PolicyDecision(
            decision=data.get("decision", "blocked"),
            reason=data.get("reason", ""),
            violated_rule=data.get("violatedRule"),
            requires_approval=data.get("requiresApproval", False),
            session_revoked=data.get("sessionRevoked", False),
            compliance_mappings=mappings,
            redacted_tokens=redaction.tokens_replaced,
        )

    def _evaluate_pep(self, prompt: str, request_id: str) -> PolicyDecision:
        """One-hop policy evaluation at PEP POST /decide. Fail-closed on miss."""
        redaction = redact_sensitive_data(prompt)
        url = f"{self._pep_url}{_PEP_DECIDE_PATH}"
        lineage = self._lineage_fields()
        headers: dict[str, str | bytes] = {
            "Authorization": f"Bearer {self._bearer_credential()}",
            "Content-Type": "application/json",
            "User-Agent": _SDK_USER_AGENT,
            "X-GF-Tenant-ID": self._tenant_id,
            "X-GF-Agent-ID": self._agent_id,
            "x-gf-department": self._department,
        }
        parents = lineage.get("parentAgents") or []
        if parents:
            # SDK chain is root-first, immediate parent last. PEP x-gf-agent-chain
            # is nearest-parent-first.
            headers["x-gf-agent-chain"] = ",".join(reversed(list(parents)))
            headers["x-gf-parent-agent-id"] = parents[-1]
        session = lineage.get("sessionId")
        if session:
            headers["x-gf-session-id"] = str(session)
        payload: dict[str, Any] = {
            "downstream_url": "sdk://wrap",
            "method": "POST",
            "action_hint": "llm_prompt",
            "target_hint": "llm_prompt",
            "body": {"prompt": redaction.redacted},
            "correlation_id": request_id,
            "action_type": "tool_call",
            # Additive lineage (headers are what PEP /decide reads; these
            # fields are ignored by ProxyRequest and kept for wrap() tests /
            # operators inspecting the hop). GATE stays advisory.
            **lineage,
        }

        receipt_request = self._prepare_receipt_request(
            "/decide", payload, headers, request_id,
        )
        response = None
        last_exc: Exception | None = None
        for attempt in range(2):
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=self._timeout)
                response.raise_for_status()
                break
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                last_exc = exc
                if attempt == 0:
                    time.sleep(_RETRY_BACKOFF_SECONDS)
                    continue
                raise ShieldConnectionError(
                    f"[G8R Shield] Could not connect to PEP at {self._pep_url} "
                    f"after retry. Is the PEP running?"
                ) from exc
            except requests.exceptions.HTTPError as exc:
                status = response.status_code if response is not None else "?"
                body = response.text if response is not None else ""
                raise ShieldConsoleError(status, body) from exc

        if response is None:
            raise ShieldConnectionError(
                f"[G8R Shield] Could not connect to PEP at {self._pep_url}"
            ) from last_exc

        data = response.json() if response.content else {}
        if receipt_request is not None:
            return self._verified_policy_decision(data, receipt_request, redaction.tokens_replaced)
        raw_decision = data.get("decision")
        # Live PEP /decide: {decision: {outcome, reason_code, ...}}. A string
        # `decision` is the Console /check shape — wrap() must not depend on it.
        if isinstance(raw_decision, dict):
            inner = raw_decision
            outcome = str(inner.get("outcome") or "").upper()
            mapped = _OUTCOME_TO_DECISION.get(outcome, "blocked")
            reason_code = str(inner.get("reason_code") or "")
            reason = str(inner.get("explanation") or reason_code or "")
            rules = inner.get("matched_rule_ids") or []
            violated = rules[0] if isinstance(rules, list) and rules else None
            requires_approval = mapped == "escalated"
            session_revoked = "KILL" in reason_code.upper()
        else:
            mapped = str(raw_decision or "blocked")
            reason = str(data.get("reason") or "")
            violated = data.get("violatedRule")
            requires_approval = bool(data.get("requiresApproval", False))
            session_revoked = bool(data.get("sessionRevoked", False))
        mappings = [
            ComplianceMapping(
                regulation=m.get("regulation", ""),
                control_id=m.get("controlId", ""),
                control_name=m.get("controlName", ""),
                description=m.get("description", ""),
            )
            for m in data.get("complianceMappings", [])
        ]
        return PolicyDecision(
            decision=mapped,
            reason=reason,
            violated_rule=violated,
            requires_approval=requires_approval,
            session_revoked=session_revoked,
            compliance_mappings=mappings,
            redacted_tokens=redaction.tokens_replaced,
        )

    def _log(
        self,
        prompt: str,
        decision: PolicyDecision,
        *,
        request_id: str | None = None,
    ) -> ShieldLogEntry | None:
        """
        POST the interaction to ``/api/sdk/v1/log`` so it lands in the Console
        audit trail. Failures are warned, not raised — a logging outage must
        never break the user's LLM call or mask the decision path.

        ``request_id`` is generated per-call by default. ``wrap()`` passes
        its own value so /check and /log share a single correlation id.
        """
        if request_id is None:
            request_id = str(uuid.uuid4())
        url = f"{self._console_url}/api/sdk/v1/log"
        # Redact before the audit-log POST too: the raw prompt with secrets
        # must never leave the process via ANY endpoint — /check or /log.
        payload: dict[str, Any] = {
            "input": redact_sensitive_data(prompt).redacted,
            "tenantId": self._tenant_id,
            "requestId": request_id,
            "userId": self._user_id,
            "department": self._department,
            "aiModel": self._ai_model,
            "agentId": self._agent_id,
            "employeeName": self._employee_name or self._user_id,
            "decision": decision.decision,
            "reason": decision.reason,
            "violatedRule": decision.violated_rule,
            "requiresApproval": decision.requires_approval,
            "complianceMappings": [
                {
                    "regulation": m.regulation,
                    "controlId": m.control_id,
                    "controlName": m.control_name,
                    "description": m.description,
                }
                for m in decision.compliance_mappings
            ],
            # Additive sub-agent lineage — same session + parent chain the
            # matching /check reported; absent when no run/nesting is active.
            **self._lineage_fields(),
        }

        try:
            # Header construction lives INSIDE the try: resolving the
            # credential can raise (a credential_provider failure surfaces
            # as ShieldConnectionError), and on the audit-log path that is
            # a logging failure like any other — warned below, never
            # raised. See `_evaluate` for the rationale on the
            # `dict[str, str | bytes]` annotation.
            headers: dict[str, str | bytes] = {
                "Authorization": f"Bearer {self._bearer_credential()}",
                "Content-Type": "application/json",
                "User-Agent": _SDK_USER_AGENT,
            }
            response = requests.post(url, json=payload, headers=headers, timeout=self._timeout)
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            # Catch broadly — JSONDecodeError, unexpected requests internals,
            # anything. Logging must never interrupt the decision path.
            # (Exception, not BaseException, so KeyboardInterrupt / SystemExit
            # still propagate cleanly.)
            _LOGGER.error(
                "log_failed",
                tenant_id=self._tenant_id,
                request_id=request_id,
                agent_id=self._agent_id,
                error=str(exc),
            )
            return None

        return ShieldLogEntry(
            id=data.get("id", ""),
            decision=data.get("decision", ""),
            timestamp=data.get("timestamp", ""),
        )
