"""Google ADK integration — govern every tool call and (optionally) every prompt.

Install:  pip install "g8r-shield[adk]"

    from g8r_shield import AgentShield
    from g8r_shield.adk import ShieldPlugin

    shield = AgentShield(
        tenant_id=...,
        pep_url=...,
        console_url=...,
        api_key=...,
        agent_id="support-bot",
    )

    runner = Runner(
        agent=root_agent,
        app_name="support",
        session_service=session_service,
        plugins=[ShieldPlugin(shield)],      # ONE line governs the whole agent tree
    )

WHY A PLUGIN AND NOT PER-AGENT CALLBACKS
ADK plugins are registered once on the Runner and apply to every agent, sub-agent and tool in
the tree — including agents added later. Per-agent ``before_tool_callback`` wiring has to be
repeated on each agent, and anything a developer forgets to wire is silently ungoverned. A
plugin cannot be forgotten, which is the property a security control needs.

WHAT IS ENFORCED WHERE
``before_tool_callback`` is the primary gate: returning a dict SHORT-CIRCUITS the tool, so the
side effect never happens and the model receives the denial as the tool result. Prompt gating
(``before_model_callback``) is available but OFF by default — it evaluates every model turn,
which roughly doubles policy traffic; tool calls are where irreversible actions live.

FAIL-CLOSED BY DEFAULT
If the control plane is unreachable or errors, the tool is BLOCKED. That matches the rest of
the product (the PDP client fails closed to REQUIRE_APPROVAL) and is the only defensible
default for a security control: an outage must not silently become an allow-all. Set
``fail_open=True`` only with eyes open, and expect to justify it in an audit.
"""
from __future__ import annotations

import asyncio
import contextlib
import uuid
from typing import TYPE_CHECKING, Any

from .redaction import redact_sensitive_data
from .shield import (
    AgentShield,
    ShieldConnectionError,
    ShieldConsoleError,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from google.adk.agents.callback_context import CallbackContext
    from google.adk.models.llm_request import LlmRequest
    from google.adk.models.llm_response import LlmResponse
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext

try:  # google-adk is an EXTRA: importing g8r_shield must never require it.
    from google.adk.plugins.base_plugin import BasePlugin
except ImportError as _exc:  # pragma: no cover - exercised by the import-guard test
    raise ImportError(
        "g8r_shield.adk requires the Google ADK. Install it with:\n"
        '    pip install "g8r-shield[adk]"'
    ) from _exc


__all__ = ["ShieldPlugin"]

# Marker on every denial the plugin returns, so an operator grepping agent transcripts can
# tell a policy block apart from a tool's own error string.
DENIAL_MARKER = "g8r_shield.blocked"


class ShieldPlugin(BasePlugin):  # type: ignore[misc]
    """Governs an entire ADK agent tree through one Agent Shield policy engine."""

    def __init__(
        self,
        shield: AgentShield,
        *,
        name: str = "g8r_shield",
        gate_tools: bool = True,
        gate_prompts: bool = False,
        fail_open: bool = False,
        redact: bool = True,
    ) -> None:
        super().__init__(name=name)
        self._shield = shield
        self._gate_tools = gate_tools
        self._gate_prompts = gate_prompts
        self._fail_open = fail_open
        self._redact = redact

    # -- helpers ---------------------------------------------------------------------------

    def _describe_tool(self, tool: BaseTool, tool_args: dict[str, Any]) -> str:
        """Render the action for policy evaluation.

        The PDP scans this string (it lands in ``action.intent`` -> ``GovernedEvent``), so it
        must carry enough of the request to be judged — but arguments are attacker- and
        user-influenced and may hold secrets or PII. Redact BEFORE it leaves the process; the
        control plane keeps prompt/argument content out of the audit body by contract, and this
        keeps it out of the request too.
        """
        rendered = f"{getattr(tool, 'name', tool.__class__.__name__)}({tool_args!r})"
        if self._redact:
            rendered = redact_sensitive_data(rendered).redacted
        return rendered

    @staticmethod
    def _lineage(tool_context: ToolContext) -> tuple[str | None, list[str]]:
        """Map ADK's invocation identity onto the SDK's governance lineage.

        ``invocation_id`` is stable for one logical agent run, which is exactly the SDK's
        ``session_id``. ``branch`` is ADK's agent hierarchy path (``root.child.grandchild``),
        which is the parent chain ROOT-FIRST — the same ordering the SDK expects.
        """
        session_id = getattr(tool_context, "invocation_id", None)
        branch = getattr(tool_context, "branch", None) or ""
        chain = [seg for seg in branch.split(".") if seg]
        # The current agent is the actor, not its own ancestor.
        current = getattr(tool_context, "agent_name", None)
        if chain and current and chain[-1] == current:
            chain = chain[:-1]
        return session_id, chain

    async def _check(
        self, description: str, session_id: str | None, chain: list[str] | None = None
    ) -> Any:
        """Evaluate off the event loop, inside the right lineage scope.

        The SDK client is synchronous (``requests``). Calling it directly from an async ADK
        hook would block the entire event loop for the duration of the round trip — under any
        concurrency that stalls every other agent in the process. ``to_thread`` also copies the
        current contextvars, so the scopes opened below are visible in the worker thread and
        are discarded with it.

        The whole scope stack is opened and unwound INSIDE one callable: ``_RunScope`` restores
        the previous ambient value with a contextvars token, and a token may only be reset in
        the context that set it. Spanning ``before_run``/``after_run`` would risk resetting in a
        different task; keeping it in one coroutine cannot.
        """

        def _blocking() -> Any:
            with contextlib.ExitStack() as stack:
                stack.enter_context(self._shield.run(session_id=session_id))
                for parent in chain or []:
                    stack.enter_context(self._shield.child(parent))
                request_id = str(uuid.uuid4())
                decision = self._shield._evaluate_pep(description, request_id)
                self._shield._log(description, decision, request_id=request_id)
                return decision

        return await asyncio.to_thread(_blocking)

    def _denial(self, reason: str, rule: str | None, *, pending: bool = False) -> dict[str, Any]:
        """The dict returned to ADK in place of the tool result.

        Shaped to be legible to BOTH the model (so it explains itself to the user instead of
        retrying blindly) and a human reading the transcript.
        """
        return {
            "error": DENIAL_MARKER,
            "status": "pending_approval" if pending else "blocked",
            "message": (
                "This action was blocked by your organisation's AI governance policy."
                if not pending
                else "This action requires human approval before it can run."
            ),
            "reason": reason,
            "violated_rule": rule,
        }

    def _on_error(self, exc: Exception) -> dict[str, Any] | None:
        if self._fail_open:
            return None  # explicit operator choice; the call proceeds ungoverned
        return self._denial(
            f"policy engine unavailable ({type(exc).__name__}) — failing closed",
            rule=None,
        )

    # -- hooks -----------------------------------------------------------------------------

    async def before_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
    ) -> dict[str, Any] | None:
        """Returning non-None short-circuits the tool: the side effect never happens."""
        if not self._gate_tools:
            return None

        session_id, chain = self._lineage(tool_context)
        description = self._describe_tool(tool, tool_args)

        try:
            decision = await self._check(description, session_id, chain)
        except (ShieldConnectionError, ShieldConsoleError) as exc:
            return self._on_error(exc)

        # A revoked session is a hard stop regardless of the verdict: the credential behind
        # this run was withdrawn mid-flight, so nothing it asks for should still execute.
        if getattr(decision, "session_revoked", False):
            return self._denial("session revoked", decision.violated_rule)
        if decision.decision == "allowed":
            return None
        if decision.requires_approval or decision.is_pending_registration:
            return self._denial(decision.reason, decision.violated_rule, pending=True)
        return self._denial(decision.reason, decision.violated_rule)

    async def before_model_callback(
        self,
        *,
        callback_context: CallbackContext,
        llm_request: LlmRequest,
    ) -> LlmResponse | None:
        """Optional prompt gate. OFF by default — see the module docstring."""
        if not self._gate_prompts:
            return None

        text = _last_user_text(llm_request)
        if not text:
            return None
        if self._redact:
            text = redact_sensitive_data(text).redacted

        session_id = getattr(callback_context, "invocation_id", None)
        try:
            decision = await self._check(text, session_id)
        except (ShieldConnectionError, ShieldConsoleError) as exc:
            if self._fail_open:
                return None
            return _refusal_response(
                f"Blocked: policy engine unavailable ({type(exc).__name__}) — failing closed."
            )

        if decision.decision == "allowed":
            return None
        return _refusal_response(
            f"Blocked by AI governance policy: {decision.reason}"
        )


def _last_user_text(llm_request: LlmRequest) -> str:
    """Best-effort extraction of the newest user turn, tolerant of ADK shape changes."""
    contents = getattr(llm_request, "contents", None) or []
    for content in reversed(list(contents)):
        if getattr(content, "role", None) not in (None, "user"):
            continue
        parts = getattr(content, "parts", None) or []
        text = " ".join(p.text for p in parts if getattr(p, "text", None))
        if text.strip():
            return text
    return ""


def _refusal_response(message: str) -> LlmResponse:
    from google.adk.models.llm_response import LlmResponse
    from google.genai import types

    return LlmResponse(
        content=types.Content(role="model", parts=[types.Part(text=message)])
    )
