"""ShieldPlugin behaviour against the real google-adk types.

These assert the properties a security control has to have, each in BOTH directions:
allow proceeds AND block short-circuits; a control-plane outage blocks by default AND proceeds
only when fail_open is explicitly set. A test that only ever sees the happy path would pass
against a plugin that never blocks anything.
"""
from __future__ import annotations

import asyncio
import types as pytypes

import pytest

adk = pytest.importorskip("google.adk", reason="ADK extra not installed")

import responses  # noqa: E402

from g8r_shield.adk import DENIAL_MARKER, ShieldPlugin  # noqa: E402
from g8r_shield.shield import (  # noqa: E402
    PolicyDecision,
    ShieldConnectionError,
)

from .conftest import (  # noqa: E402
    DECIDE_URL,
    LOG_URL,
    log_response,
    pep_blocked_response,
)


def _decision(kind: str = "allowed", **kw) -> PolicyDecision:
    return PolicyDecision(
        decision=kind,
        reason=kw.pop("reason", "permit"),
        violated_rule=kw.pop("violated_rule", None),
        requires_approval=kw.pop("requires_approval", False),
        session_revoked=kw.pop("session_revoked", False),
        **kw,
    )


class _FakeShield:
    """Stands in for AgentShield: records what it was asked, returns a scripted verdict.

    Implements wrap()'s PEP hop (``_evaluate_pep``), not Console ``check()``.
    A regression that still calls ``check()`` leaves ``checked`` empty.
    """

    def __init__(self, result=None, raises: Exception | None = None):
        self._result = result if result is not None else _decision("allowed")
        self._raises = raises
        self.checked: list[str] = []

    def run(self, session_id=None):
        self.session_id = session_id
        import contextlib

        return contextlib.nullcontext()

    def child(self, agent_id):
        self.children = getattr(self, "children", []) + [agent_id]
        import contextlib

        return contextlib.nullcontext()

    def _evaluate_pep(self, prompt, request_id):
        self.checked.append(prompt)
        if self._raises:
            raise self._raises
        return self._result

    def _log(self, prompt, decision, *, request_id=None):
        return None


class _Tool:
    name = "transfer_funds"


def _tool_ctx(invocation_id="inv-1", branch="root.planner.payments", agent_name="payments"):
    return pytypes.SimpleNamespace(
        invocation_id=invocation_id, branch=branch, agent_name=agent_name
    )


def _call(plugin, shield, args=None):
    return asyncio.run(
        plugin.before_tool_callback(
            tool=_Tool(), tool_args=args or {"amount": 5000}, tool_context=_tool_ctx()
        )
    )


# --- the core contract, both directions -----------------------------------------------------

def test_allowed_tool_proceeds():
    shield = _FakeShield(_decision("allowed"))
    assert _call(ShieldPlugin(shield), shield) is None, "None lets ADK run the tool"


def test_blocked_tool_short_circuits():
    shield = _FakeShield(_decision("blocked", reason="PII egress", violated_rule="policy7"))
    out = _call(ShieldPlugin(shield), shield)
    assert out is not None, "a block MUST return a dict so the tool never executes"
    assert out["error"] == DENIAL_MARKER
    assert out["status"] == "blocked"
    assert out["reason"] == "PII egress"
    assert out["violated_rule"] == "policy7"


def test_escalated_tool_reports_pending_approval():
    shield = _FakeShield(_decision("escalated", requires_approval=True, reason="needs sign-off"))
    out = _call(ShieldPlugin(shield), shield)
    assert out["status"] == "pending_approval"


def test_revoked_session_blocks_even_when_allowed():
    # The verdict says allow, but the credential behind the run was withdrawn mid-flight.
    shield = _FakeShield(_decision("allowed", session_revoked=True))
    out = _call(ShieldPlugin(shield), shield)
    assert out is not None and out["status"] == "blocked"


# --- outage posture --------------------------------------------------------------------------

def test_control_plane_outage_fails_closed_by_default():
    shield = _FakeShield(raises=ShieldConnectionError("boom"))
    out = _call(ShieldPlugin(shield), shield)
    assert out is not None, "an unreachable policy engine must NOT become allow-all"
    assert "failing closed" in out["reason"]


def test_fail_open_is_opt_in():
    shield = _FakeShield(raises=ShieldConnectionError("boom"))
    assert _call(ShieldPlugin(shield, fail_open=True), shield) is None


# --- what leaves the process -------------------------------------------------------------------

def test_high_entropy_secrets_are_stripped_before_evaluation():
    """Credentials must not leave the process; the ACTION still must be judgeable."""
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    shield = _FakeShield()
    _call(ShieldPlugin(shield), shield, args={"aws_secret": secret})
    sent = shield.checked[0]
    assert secret not in sent, "a high-entropy secret must not leave the process"
    assert "transfer_funds" in sent, "the action itself still has to be judgeable"


def test_pii_is_stripped_before_evaluation_like_wrap():
    """Parity with wrap() / TypeScript: SSN/email/card never leave the process.

    PACK_PII_EGRESS on the PDP is a PEP/gateway control (raw prompt at the hop).
    SDK clients redact PII locally first; the action name stays judgeable.
    """
    shield = _FakeShield()
    _call(ShieldPlugin(shield), shield, args={"note": "ssn 578-14-1830"})
    sent = shield.checked[0]
    assert "578-14-1830" not in sent
    assert "[REDACTED:SSN]" in sent
    assert "transfer_funds" in sent


def test_redaction_can_be_disabled():
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    shield = _FakeShield()
    _call(ShieldPlugin(shield, redact=False), shield, args={"aws_secret": secret})
    assert secret in shield.checked[0]


def test_lineage_maps_branch_to_parent_chain_excluding_self():
    shield = _FakeShield()
    _call(ShieldPlugin(shield), shield)
    assert shield.session_id == "inv-1"
    # branch is root.planner.payments and the acting agent is 'payments' — it is not its own parent
    assert shield.children == ["root", "planner"]


def test_gating_can_be_disabled():
    shield = _FakeShield(_decision("blocked"))
    assert _call(ShieldPlugin(shield, gate_tools=False), shield) is None
    assert shield.checked == [], "disabled gate must not call the policy engine at all"


def test_plugin_uses_evaluate_pep_not_check():
    """_FakeShield has no check(). A hop through Console /check leaves checked empty."""
    shield = _FakeShield()
    assert _call(ShieldPlugin(shield), shield) is None
    assert shield.checked, "ShieldPlugin must call _evaluate_pep"


@responses.activate
def test_plugin_hops_pep_decide_not_console_check(shield):
    """A real AgentShield hops wrap's PEP /decide, not Console /check.

    wrap() would raise ShieldBlockedError here. The plugin needs the PolicyDecision
    so it can return a denial dict and short-circuit the tool.
    """
    responses.add(responses.POST, DECIDE_URL, json=pep_blocked_response(), status=200)
    responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

    out = _call(ShieldPlugin(shield), shield)

    assert out is not None, "a PEP DENY must short-circuit the tool"
    assert out["error"] == DENIAL_MARKER
    assert out["status"] == "blocked"
    assert responses.calls[0].request.url == DECIDE_URL
    assert responses.calls[1].request.url == LOG_URL
    assert all("/api/sdk/v1/check" not in (c.request.url or "") for c in responses.calls)
