"""
Tests for g8r_shield.shield.

Covers:
- Construction & defaults (env-var fallback, api-key warning, slots, repr)
- check()  — return shape, audit logging by default, log=False opt-out
- wrap()   — allowed/blocked/escalated dispatch, sessionRevoked propagation,
             block_on_escalated strict mode, audit log called pre-enforcement,
             log failures swallowed
- _evaluate retry — single retry on ConnectionError/Timeout, no retry on 4xx
- Value object immutability — frozen=True on dataclasses
- Payload shape — User-Agent header, employee_name fallback to user_id,
                  compliance mappings serialization
- credential_provider — per-request invocation on /check AND /log, mutual
                        exclusion with api_key, fail-closed provider errors
- is_pending_registration — v2 pending-registration truth table on
                            PolicyDecision and ShieldBlockedError
- sub-agent lineage — ambient session + parent-agent chain propagation through
                      wrap()/run()/child(); back-compat when unused; contextvars
                      isolation across async tasks
"""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError

import pytest
import requests
import responses
from structlog.testing import capture_logs

import g8r_shield
from g8r_shield import (
    AgentShield,
    ComplianceMapping,
    PolicyDecision,
    ShieldBlockedError,
    ShieldConnectionError,
    ShieldConsoleError,
    ShieldLogEntry,
)

from .conftest import (
    CHECK_URL,
    CONSOLE_URL,
    DECIDE_URL,
    LOG_URL,
    PEP_URL,
    allowed_response,
    blocked_response,
    denied_registration_response,
    escalated_response,
    kill_switch_response,
    log_response,
    pending_registration_response,
    pep_allowed_response,
    pep_blocked_response,
    pep_escalated_response,
    pep_kill_switch_response,
)

# ════════════════════════════════════════════════════════════════════════════
# Construction
# ════════════════════════════════════════════════════════════════════════════


class TestConstruction:
    def test_defaults_applied(self):
        s = AgentShield(tenant_id="t1", pep_url=PEP_URL, console_url="http://x", api_key="k")
        assert s._department == "General"
        assert s._user_id == "unknown"
        assert s._ai_model == "unknown"
        assert s._agent_id == "sdk-client"
        assert s._timeout == 10.0
        assert s._block_on_escalated is False

    def test_console_url_env_fallback(self, monkeypatch):
        monkeypatch.setenv("G8R_CONSOLE_URL", "https://env.example.com/")
        monkeypatch.setenv("G8R_API_KEY", "env-key")
        s = AgentShield(tenant_id="t1", pep_url=PEP_URL)
        # Trailing slash should be stripped.
        assert s._console_url == "https://env.example.com"
        assert s._api_key == "env-key"

    def test_explicit_args_override_env(self, monkeypatch):
        monkeypatch.setenv("G8R_CONSOLE_URL", "https://env.example.com")
        monkeypatch.setenv("G8R_API_KEY", "env-key")
        s = AgentShield(
            tenant_id="t1",
            pep_url=PEP_URL,
            console_url="https://explicit.example.com",
            api_key="explicit-key",
        )
        assert s._console_url == "https://explicit.example.com"
        assert s._api_key == "explicit-key"

    def test_raises_when_no_api_key(self, monkeypatch):
        monkeypatch.delenv("G8R_API_KEY", raising=False)
        with pytest.raises(ValueError, match="G8R API key is required"):
            AgentShield(tenant_id="t1", pep_url=PEP_URL, console_url="http://x")

    def test_raises_when_no_tenant_id(self):
        """Empty tenant_id must fail-fast at construction."""
        with pytest.raises(ValueError, match="tenant_id is required"):
            AgentShield(tenant_id="", pep_url=PEP_URL, console_url="http://x", api_key="k")

    def test_raises_when_no_pep_url(self, monkeypatch):
        monkeypatch.delenv("G8R_PEP_URL", raising=False)
        with pytest.raises(ValueError, match="pep_url is required"):
            AgentShield(tenant_id="t1", console_url="https://c.example.com", api_key="k")

    def test_pep_url_env_fallback(self, monkeypatch):
        monkeypatch.setenv("G8R_PEP_URL", "https://pep.env.example/")
        s = AgentShield(tenant_id="t1", console_url="https://c.example.com", api_key="k")
        assert s._pep_url == "https://pep.env.example"

    def test_pep_url_rejects_localhost(self):
        with pytest.raises(ValueError, match="localhost"):
            AgentShield(
                tenant_id="t1",
                pep_url="http://localhost:8083",
                console_url="https://c.example.com",
                api_key="k",
            )

    def test_raises_when_no_console_url(self, monkeypatch):
        # Fail-closed: no implicit localhost default. A misconfigured agent
        # must not silently POST prompts + API keys to 127.0.0.1.
        monkeypatch.delenv("G8R_CONSOLE_URL", raising=False)
        with pytest.raises(ValueError, match="console_url is required"):
            AgentShield(tenant_id="t1", pep_url=PEP_URL, api_key="k")

    def test_timeout_accepts_float(self):
        s = AgentShield(tenant_id="t1", pep_url=PEP_URL, console_url="http://x", api_key="k", timeout=2.5)
        assert s._timeout == 2.5

    def test_slots_blocks_ad_hoc_attributes(self, shield):
        with pytest.raises(AttributeError):
            shield.new_attr = "should fail"  # type: ignore[attr-defined]

    def test_slots_declared_with_expected_fields(self):
        assert set(AgentShield.__slots__) == {
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
        }


# ════════════════════════════════════════════════════════════════════════════
# __repr__
# ════════════════════════════════════════════════════════════════════════════


class TestRepr:
    def test_repr_includes_safe_fields(self, shield):
        out = repr(shield)
        assert "AgentShield" in out
        assert CONSOLE_URL in out
        assert "test-agent" in out
        assert "Engineering" in out

    def test_repr_omits_api_key(self, shield):
        # The fixture's api_key is sk-shield-test-key. Must NOT appear in repr.
        assert "sk-shield-test-key" not in repr(shield)
        assert "api_key" not in repr(shield)


# ════════════════════════════════════════════════════════════════════════════
# check()
# ════════════════════════════════════════════════════════════════════════════


class TestCheck:
    @responses.activate
    def test_returns_policy_decision_on_allowed(self, shield):
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        decision = shield.check("Safe prompt")

        assert isinstance(decision, PolicyDecision)
        assert decision.decision == "allowed"
        assert decision.violated_rule is None
        assert decision.session_revoked is False

    @responses.activate
    def test_parses_blocked_with_session_revoked(self, shield):
        responses.add(responses.POST, CHECK_URL, json=kill_switch_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        decision = shield.check("Pull partner compensation report")

        assert decision.decision == "blocked"
        assert decision.session_revoked is True
        assert decision.violated_rule == "Sensitive Data Egress"

    @responses.activate
    def test_logs_by_default(self, shield):
        """check() with default log=True hits both /check and /log."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.check("Safe prompt")

        assert len(responses.calls) == 2
        assert responses.calls[0].request.url == CHECK_URL
        assert responses.calls[1].request.url == LOG_URL

    @responses.activate
    def test_log_false_skips_audit(self, shield):
        """check(prompt, log=False) hits /check but NOT /log."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        shield.check("Safe prompt", log=False)

        assert len(responses.calls) == 1
        assert responses.calls[0].request.url == CHECK_URL

    @responses.activate
    def test_compliance_mappings_parsed(self, shield):
        responses.add(responses.POST, CHECK_URL, json=blocked_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        decision = shield.check("test prompt")

        assert len(decision.compliance_mappings) == 1
        m = decision.compliance_mappings[0]
        assert m.regulation == "GDPR"
        assert m.control_id == "GDPR Art. 5(1)(f)"
        assert m.description.startswith("Personal data")

    @responses.activate
    def test_does_not_raise_on_blocked(self, shield):
        """check() returns the decision; does NOT raise. Caller decides."""
        responses.add(responses.POST, CHECK_URL, json=blocked_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        decision = shield.check("blocked prompt", log=False)

        assert decision.decision == "blocked"  # no raise

    @responses.activate
    def test_check_does_not_send_x_gf_department_header(self, shield):
        """Console /check uses JSON department. x-gf-department is PEP-only."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        shield.check("test", log=False)

        req = responses.calls[0].request
        assert req.url == CHECK_URL
        assert "x-gf-department" not in req.headers
        body = json.loads(req.body)
        assert body["department"] == "Engineering"


# ════════════════════════════════════════════════════════════════════════════
# wrap()
# ════════════════════════════════════════════════════════════════════════════


class TestWrap:
    @responses.activate
    def test_allowed_calls_factory_and_returns_result(self, shield):
        responses.add(responses.POST, DECIDE_URL, json=pep_allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        result = shield.wrap(lambda: "factory-result", "safe prompt")

        assert result == "factory-result"
        assert all("/api/sdk/v1/check" not in (c.request.url or "") for c in responses.calls)

    @responses.activate
    def test_wrap_decide_sends_x_gf_department_from_constructor(self, shield):
        """PEP /decide reads x-gf-department for cost metering.

        PEP Actor has no user header. x-gf-model-id is an upstream RESPONSE
        header. User and model stay on Console /log only.
        """
        responses.add(responses.POST, DECIDE_URL, json=pep_allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.wrap(lambda: "ok", "safe prompt")

        decide = responses.calls[0].request
        log = responses.calls[1].request
        assert decide.url == DECIDE_URL
        assert log.url == LOG_URL
        assert decide.headers["x-gf-department"] == "Engineering"
        assert decide.headers["X-GF-Tenant-ID"] == "tenant-test"
        assert decide.headers["X-GF-Agent-ID"] == "test-agent"
        assert decide.headers.get("x-gf-session-id")
        assert "x-gf-user-id" not in decide.headers
        assert "x-gf-model-id" not in decide.headers
        log_body = json.loads(log.body)
        assert log_body["userId"] == "usr_TEST_001"
        assert log_body["aiModel"] == "test-model"

    @responses.activate
    def test_wrap_decide_defaults_x_gf_department_to_general(self):
        s = AgentShield(
            tenant_id="t1",
            pep_url=PEP_URL,
            console_url=CONSOLE_URL,
            api_key="k",
        )
        responses.add(responses.POST, DECIDE_URL, json=pep_allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        s.wrap(lambda: "ok", "safe prompt")

        assert responses.calls[0].request.headers["x-gf-department"] == "General"

    @responses.activate
    def test_blocked_raises_shield_blocked_error(self, shield):
        responses.add(responses.POST, DECIDE_URL, json=pep_blocked_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        with pytest.raises(ShieldBlockedError) as exc_info:
            shield.wrap(lambda: "never returned", "bad prompt")

        assert exc_info.value.violated_rule == "PII Protection Guard"
        assert exc_info.value.session_revoked is False

    @responses.activate
    def test_blocked_factory_never_called(self, shield, mocker):
        responses.add(responses.POST, DECIDE_URL, json=pep_blocked_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        factory = mocker.Mock(return_value="never")
        with pytest.raises(ShieldBlockedError):
            shield.wrap(factory, "bad prompt")

        factory.assert_not_called()

    @responses.activate
    def test_kill_switch_propagates_session_revoked_on_error(self, shield):
        responses.add(responses.POST, DECIDE_URL, json=pep_kill_switch_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        with capture_logs() as logs, pytest.raises(ShieldBlockedError) as exc_info:
            shield.wrap(lambda: None, "Pull partner compensation")

        assert exc_info.value.session_revoked is True
        kill_logs = [e for e in logs if e.get("event") == "session_revoked"]
        assert len(kill_logs) == 1
        assert kill_logs[0]["agent_id"] == shield._agent_id
        assert kill_logs[0]["log_level"] == "warning"

    @responses.activate
    def test_escalated_default_warns_and_proceeds(self, shield, mocker):
        """Default config: escalated → emit structured warning + invoke factory."""
        responses.add(responses.POST, DECIDE_URL, json=pep_escalated_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        factory = mocker.Mock(return_value="approved-result")
        with capture_logs() as logs:
            result = shield.wrap(factory, "DROP TABLE users")

        assert result == "approved-result"
        factory.assert_called_once()
        esc_logs = [e for e in logs if e.get("event") == "action_escalated"]
        assert len(esc_logs) == 1
        assert esc_logs[0]["agent_id"] == shield._agent_id
        assert esc_logs[0]["log_level"] == "warning"
        assert "Destructive operation" in esc_logs[0]["reason"]

    @responses.activate
    def test_escalated_with_block_on_escalated_raises(self, strict_shield, mocker):
        """Strict config: escalated → raise instead of proceeding."""
        responses.add(responses.POST, DECIDE_URL, json=pep_escalated_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        factory = mocker.Mock()
        with pytest.raises(ShieldBlockedError) as exc_info:
            strict_shield.wrap(factory, "DROP TABLE users")

        assert exc_info.value.decision == "escalated"
        factory.assert_not_called()

    @responses.activate
    def test_log_called_before_enforcement(self, shield, mocker):
        """Audit log fires BEFORE the block — blocked decisions are still recorded."""
        responses.add(responses.POST, DECIDE_URL, json=pep_blocked_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        with pytest.raises(ShieldBlockedError):
            shield.wrap(lambda: None, "bad prompt")

        # Two calls: /decide then /log. Order matters — log must precede the raise.
        assert len(responses.calls) == 2
        assert responses.calls[0].request.url == DECIDE_URL
        assert responses.calls[1].request.url == LOG_URL

    @responses.activate
    def test_log_exception_swallowed(self, shield, mocker):
        """_log raising arbitrary Exception must not interrupt the decision path."""
        responses.add(responses.POST, DECIDE_URL, json=pep_allowed_response(), status=200)
        # Make the log endpoint return invalid JSON, triggering ValueError on parse.
        responses.add(responses.POST, LOG_URL, body="not-json-at-all", status=200)

        # Factory should still run; ValueError from _log is swallowed via the
        # broad `except Exception` (issue #1 from the SDK review).
        with capture_logs() as logs:
            result = shield.wrap(lambda: "ok", "safe prompt")

        assert result == "ok"
        fail_logs = [e for e in logs if e.get("event") == "log_failed"]
        assert len(fail_logs) == 1
        assert fail_logs[0]["agent_id"] == shield._agent_id
        assert fail_logs[0]["log_level"] == "error"
        assert "error" in fail_logs[0]

    @responses.activate
    def test_log_http_error_swallowed(self, shield):
        """_log getting a 500 must not interrupt the decision path either."""
        responses.add(responses.POST, DECIDE_URL, json=pep_allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json={"error": "boom"}, status=500)

        with capture_logs() as logs:
            result = shield.wrap(lambda: "ok", "safe prompt")

        assert result == "ok"
        fail_logs = [e for e in logs if e.get("event") == "log_failed"]
        assert len(fail_logs) == 1
        assert fail_logs[0]["log_level"] == "error"


# ════════════════════════════════════════════════════════════════════════════
# Retry on transient network errors
# ════════════════════════════════════════════════════════════════════════════


class TestRetry:
    @responses.activate
    def test_retries_once_on_connection_error(self, shield, mocker):
        """First call raises ConnectionError; second succeeds."""
        mocker.patch("g8r_shield.shield.time.sleep")  # don't actually sleep
        responses.add(
            responses.POST,
            CHECK_URL,
            body=requests.exceptions.ConnectionError("simulated transient"),
        )
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        decision = shield.check("test", log=False)

        assert decision.decision == "allowed"
        assert len(responses.calls) == 2  # one retry consumed

    @responses.activate
    def test_retries_once_on_timeout(self, shield, mocker):
        mocker.patch("g8r_shield.shield.time.sleep")
        responses.add(
            responses.POST,
            CHECK_URL,
            body=requests.exceptions.Timeout("simulated timeout"),
        )
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        decision = shield.check("test", log=False)

        assert decision.decision == "allowed"
        assert len(responses.calls) == 2

    @responses.activate
    def test_raises_after_second_failure(self, shield, mocker):
        """Both attempts fail → RuntimeError, no third attempt."""
        mocker.patch("g8r_shield.shield.time.sleep")
        responses.add(
            responses.POST,
            CHECK_URL,
            body=requests.exceptions.ConnectionError("simulated"),
        )
        responses.add(
            responses.POST,
            CHECK_URL,
            body=requests.exceptions.ConnectionError("simulated again"),
        )

        with pytest.raises(RuntimeError, match="after retry"):
            shield.check("test", log=False)

        assert len(responses.calls) == 2

    @responses.activate
    def test_no_retry_on_http_4xx(self, shield, mocker):
        """4xx is a client error; retrying just doubles latency. Surface immediately."""
        sleep_spy = mocker.patch("g8r_shield.shield.time.sleep")
        responses.add(responses.POST, CHECK_URL, json={"error": "unauthorized"}, status=401)

        with pytest.raises(RuntimeError, match="HTTP 401"):
            shield.check("test", log=False)

        assert len(responses.calls) == 1
        sleep_spy.assert_not_called()

    @responses.activate
    def test_no_retry_on_http_5xx(self, shield, mocker):
        """5xx is a server error. Current policy: surface immediately (no retry)."""
        sleep_spy = mocker.patch("g8r_shield.shield.time.sleep")
        responses.add(responses.POST, CHECK_URL, json={"error": "boom"}, status=500)

        with pytest.raises(RuntimeError, match="HTTP 500"):
            shield.check("test", log=False)

        assert len(responses.calls) == 1
        sleep_spy.assert_not_called()


# ════════════════════════════════════════════════════════════════════════════
# ShieldConsoleError — typed HTTP exception (security audit M1)
# ════════════════════════════════════════════════════════════════════════════


class TestShieldConsoleError:
    """The HTTP error path raises a typed ShieldConsoleError so host
    frameworks that surface exception messages don't leak the raw
    server response body."""

    @responses.activate
    def test_raises_typed_exception_with_status_and_detail(self, shield):
        secret_payload = "Internal stack trace: AccessDenied at line 42 (token=AKIA...)"
        responses.add(responses.POST, CHECK_URL, body=secret_payload, status=403)

        with pytest.raises(ShieldConsoleError) as exc_info:
            shield.check("test", log=False)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail == secret_payload

    @responses.activate
    def test_str_does_not_leak_response_body(self, shield):
        """str(exc) must NOT contain the raw response body — that's the
        attack surface that frameworks surface to end users by default."""
        secret_payload = "leaky-token-9f8e7d6c-not-for-end-users"
        responses.add(responses.POST, CHECK_URL, body=secret_payload, status=500)

        with pytest.raises(ShieldConsoleError) as exc_info:
            shield.check("test", log=False)

        rendered = str(exc_info.value)
        assert secret_payload not in rendered
        assert "HTTP 500" in rendered

    @responses.activate
    def test_backward_compatible_with_runtimeerror_catchers(self, shield):
        """Existing `except RuntimeError:` catch-alls must continue to fire."""
        responses.add(responses.POST, CHECK_URL, body="err", status=401)

        with pytest.raises(RuntimeError):
            shield.check("test", log=False)

    def test_constructor_accepts_status_code_only(self):
        """Detail is optional; constructing with just a status code is valid."""
        exc = ShieldConsoleError(503)
        assert exc.status_code == 503
        assert exc.detail == ""
        assert "HTTP 503" in str(exc)

    def test_is_subclass_of_runtimeerror(self):
        """Inheritance contract: existing RuntimeError catches must still trip."""
        assert issubclass(ShieldConsoleError, RuntimeError)


# ════════════════════════════════════════════════════════════════════════════
# Value-object immutability (frozen dataclasses)
# ════════════════════════════════════════════════════════════════════════════


class TestValueObjectImmutability:
    def test_compliance_mapping_frozen(self):
        m = ComplianceMapping(
            regulation="GDPR", control_id="Art. 5", control_name="x", description="y"
        )
        with pytest.raises(FrozenInstanceError):
            m.regulation = "changed"  # type: ignore[misc]

    def test_policy_decision_frozen(self):
        d = PolicyDecision(
            decision="allowed",
            reason="ok",
            violated_rule=None,
            requires_approval=False,
            session_revoked=False,
        )
        with pytest.raises(FrozenInstanceError):
            d.decision = "blocked"  # type: ignore[misc]

    def test_shield_log_entry_frozen(self):
        e = ShieldLogEntry(id="x", decision="allowed", timestamp="2026-05-08T00:00:00Z")
        with pytest.raises(FrozenInstanceError):
            e.id = "changed"  # type: ignore[misc]


# ════════════════════════════════════════════════════════════════════════════
# Payload shape — headers, employee_name fallback, mappings serialization
# ════════════════════════════════════════════════════════════════════════════


class TestPayloadShape:
    @responses.activate
    def test_user_agent_header_on_check(self, shield):
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        shield.check("test", log=False)

        assert responses.calls[0].request.headers["User-Agent"].startswith("g8r-shield-python/")

    @responses.activate
    def test_user_agent_header_on_log(self, shield):
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.check("test")

        assert responses.calls[1].request.headers["User-Agent"].startswith("g8r-shield-python/")

    @responses.activate
    def test_bearer_auth_header(self, shield):
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        shield.check("test", log=False)

        assert responses.calls[0].request.headers["Authorization"] == "Bearer sk-shield-test-key"

    @responses.activate
    def test_employee_name_falls_back_to_user_id_in_log_payload(self):
        """When employee_name is None, log payload uses user_id."""

        s = AgentShield(
            tenant_id="tenant-test", pep_url=PEP_URL,
            console_url=CONSOLE_URL,
            api_key="sk-test",
            user_id="usr_999",
            employee_name=None,  # explicit None
        )
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        s.check("test")

        body = json.loads(responses.calls[1].request.body)
        assert body["employeeName"] == "usr_999"

    @responses.activate
    def test_employee_name_used_when_set_in_log_payload(self, shield):

        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.check("test")

        log_body = responses.calls[1].request.body
        body = json.loads(log_body)
        assert body["employeeName"] == "Test User"

    @responses.activate
    def test_compliance_mappings_serialized_in_log_payload(self, shield):

        responses.add(responses.POST, CHECK_URL, json=blocked_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.check("test")

        log_body = json.loads(responses.calls[1].request.body)
        assert len(log_body["complianceMappings"]) == 1
        m = log_body["complianceMappings"][0]
        assert m["regulation"] == "GDPR"
        assert m["controlId"] == "GDPR Art. 5(1)(f)"
        assert m["controlName"] == "Integrity & Confidentiality"
        assert "description" in m

    @responses.activate
    def test_check_payload_never_includes_employee_name_even_when_set(self, shield):
        """Canonical parity: employeeName is an audit-trail label sent ONLY on
        /log, never on /check — matching the TypeScript SDK, which never sent
        it. The fixture sets employee_name='Test User'; it must not appear on
        /check."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        shield.check("test", log=False)

        body = json.loads(responses.calls[0].request.body)
        assert "employeeName" not in body

    @responses.activate
    def test_check_payload_omits_employee_name_when_none(self):
        s = AgentShield(
            tenant_id="tenant-test", pep_url=PEP_URL,
            console_url=CONSOLE_URL,
            api_key="sk-test",
            user_id="usr_x",
            employee_name=None,
        )
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        s.check("test", log=False)

        body = json.loads(responses.calls[0].request.body)
        # The /check payload never carries employeeName (vs. the /log payload,
        # which falls back to user_id). Canonical cross-SDK contract.
        assert "employeeName" not in body

    @responses.activate
    def test_outbound_payload_includes_tenant_and_request_id(self, shield):
        """Both /check and /log payloads must carry tenantId and a UUID requestId.

        Ensures every outbound request from the SDK is attributable to a
        tenant and traceable via request_id end-to-end.
        """
        import uuid as _uuid

        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.check("safe prompt")

        check_body = json.loads(responses.calls[0].request.body)
        log_body = json.loads(responses.calls[1].request.body)

        # tenantId is the constant from the fixture; requestId is fresh per call.
        assert check_body["tenantId"] == "tenant-test"
        assert log_body["tenantId"] == "tenant-test"

        assert "requestId" in check_body
        assert "requestId" in log_body
        # Verify UUID4 shape — _uuid.UUID() raises ValueError on a malformed string.
        _uuid.UUID(check_body["requestId"])
        _uuid.UUID(log_body["requestId"])
        # Canonical parity: standalone check() mints ONE request_id up front and
        # threads it through both /check and /log so the policy decision and its
        # audit line correlate end-to-end — the same single-id behavior wrap()
        # relies on. (Previously each internal call minted its own id.)
        assert check_body["requestId"] == log_body["requestId"]

    @responses.activate
    def test_wrap_uses_single_request_id_for_check_and_log(self, shield):
        """wrap() emits the same request_id to /check and /log.

        End-to-end correlation requires that a single shield.wrap() invocation
        produces ONE request_id, threaded through both the policy evaluation
        and the audit log. Before this fix, _evaluate and _log each minted
        their own uuid4 so the two server-side log lines could not be joined.
        """
        responses.add(responses.POST, DECIDE_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.wrap(lambda: "ok", "prompt")

        assert len(responses.calls) == 2
        check_body = json.loads(responses.calls[0].request.body)
        log_body = json.loads(responses.calls[1].request.body)

        assert check_body.get("correlation_id") == log_body["requestId"]


# ════════════════════════════════════════════════════════════════════════════
# Default-on-malformed-response (fail-closed)
# ════════════════════════════════════════════════════════════════════════════


class TestFailClosed:
    @responses.activate
    def test_missing_decision_field_defaults_to_blocked(self, shield):
        """If the server response is missing `decision`, we default to blocked."""
        # Response with no `decision` field at all — server bug / proxy mangling.
        responses.add(responses.POST, CHECK_URL, json={}, status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        decision = shield.check("test", log=False)

        assert decision.decision == "blocked"  # fail-closed


# ════════════════════════════════════════════════════════════════════════════
# check(request_id=...) — explicit correlation id knob
# ════════════════════════════════════════════════════════════════════════════


class TestCheckRequestId:
    @responses.activate
    def test_explicit_request_id_used_verbatim_on_check(self, shield):
        """A caller-supplied request_id is stamped verbatim on /check."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        shield.check("test", request_id="fixed-corr-id-123", log=False)

        body = json.loads(responses.calls[0].request.body)
        assert body["requestId"] == "fixed-corr-id-123"

    @responses.activate
    def test_explicit_request_id_shared_across_check_and_log(self, shield):
        """When request_id is supplied AND log=True, the SAME id lands on both
        /check and /log — that is what makes check() self-correlating."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.check("test", request_id="corr-abc")

        check_body = json.loads(responses.calls[0].request.body)
        log_body = json.loads(responses.calls[1].request.body)
        assert check_body["requestId"] == "corr-abc"
        assert log_body["requestId"] == "corr-abc"

    @responses.activate
    def test_default_check_still_correlates_check_and_log(self, shield):
        """With no explicit id, check() still mints ONE id and shares it across
        /check and /log (canonical behavior)."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.check("test")

        check_body = json.loads(responses.calls[0].request.body)
        log_body = json.loads(responses.calls[1].request.body)
        assert check_body["requestId"] == log_body["requestId"]

    def test_request_id_and_log_are_keyword_only(self):
        """Canonical signature: check(prompt, *, request_id=None, log=True).
        Passing log/request_id positionally must fail — guards the wire
        contract against a positional-arg regression."""
        import inspect

        sig = inspect.signature(AgentShield.check)
        params = sig.parameters
        assert params["request_id"].kind is inspect.Parameter.KEYWORD_ONLY
        assert params["log"].kind is inspect.Parameter.KEYWORD_ONLY


# ════════════════════════════════════════════════════════════════════════════
# ShieldConnectionError — named unreachable-console type (canonical)
# ════════════════════════════════════════════════════════════════════════════


class TestShieldConnectionError:
    """The Console-unreachable path (connection refused / timeout, even after
    the single retry) raises a NAMED ShieldConnectionError so callers can tell
    'couldn't reach the server' apart from 'the server said no'
    (ShieldConsoleError)."""

    @responses.activate
    def test_raises_named_connection_error_after_retry(self, shield, mocker):
        mocker.patch("g8r_shield.shield.time.sleep")
        responses.add(
            responses.POST,
            CHECK_URL,
            body=requests.exceptions.ConnectionError("down"),
        )
        responses.add(
            responses.POST,
            CHECK_URL,
            body=requests.exceptions.ConnectionError("still down"),
        )

        with pytest.raises(ShieldConnectionError) as exc_info:
            shield.check("test", log=False)

        # Message names the console_url and the retry, but carries no body.
        assert CONSOLE_URL in str(exc_info.value)
        assert "after retry" in str(exc_info.value)

    @responses.activate
    def test_connection_error_on_timeout(self, shield, mocker):
        mocker.patch("g8r_shield.shield.time.sleep")
        responses.add(responses.POST, CHECK_URL, body=requests.exceptions.Timeout("t"))
        responses.add(responses.POST, CHECK_URL, body=requests.exceptions.Timeout("t"))

        with pytest.raises(ShieldConnectionError):
            shield.check("test", log=False)

    def test_is_subclass_of_runtimeerror(self):
        """except RuntimeError catch-alls must still trip on the new type."""
        assert issubclass(ShieldConnectionError, RuntimeError)

    @responses.activate
    def test_backward_compatible_runtimeerror_catch(self, shield, mocker):
        mocker.patch("g8r_shield.shield.time.sleep")
        responses.add(responses.POST, CHECK_URL, body=requests.exceptions.ConnectionError("x"))
        responses.add(responses.POST, CHECK_URL, body=requests.exceptions.ConnectionError("x"))

        with pytest.raises(RuntimeError, match="after retry"):
            shield.check("test", log=False)

    def test_distinct_from_console_error(self):
        """The two console-failure types are not in each other's hierarchy, so
        `except ShieldConsoleError` never swallows an unreachable-console error
        (and vice versa)."""
        assert not issubclass(ShieldConnectionError, ShieldConsoleError)
        assert not issubclass(ShieldConsoleError, ShieldConnectionError)


# ════════════════════════════════════════════════════════════════════════════
# wrap() — exhaustive decision switch (fail-closed on unknown decision)
# ════════════════════════════════════════════════════════════════════════════


class TestWrapExhaustive:
    @responses.activate
    def test_unrecognized_decision_fails_closed(self, shield, mocker):
        """A decision value the SDK doesn't know about must NOT fall through to
        the factory. It raises ShieldBlockedError — mirrors the TS SDK's
        ts-pattern .exhaustive()."""
        weird = {
            "decision": "quarantined",  # not allowed/blocked/escalated
            "reason": "novel decision from a newer console",
            "violatedRule": None,
            "requiresApproval": False,
            "sessionRevoked": False,
            "complianceMappings": [],
        }
        responses.add(responses.POST, DECIDE_URL, json=weird, status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        factory = mocker.Mock(return_value="should-not-run")
        with pytest.raises(ShieldBlockedError) as exc_info:
            shield.wrap(factory, "prompt")

        factory.assert_not_called()
        assert exc_info.value.decision == "quarantined"

    @responses.activate
    def test_unrecognized_decision_still_audit_logged(self, shield, mocker):
        """Even the fail-closed unknown-decision path logs before raising."""
        weird = {
            "decision": "quarantined",
            "reason": "novel",
            "violatedRule": None,
            "requiresApproval": False,
            "sessionRevoked": False,
            "complianceMappings": [],
        }
        responses.add(responses.POST, DECIDE_URL, json=weird, status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        with pytest.raises(ShieldBlockedError):
            shield.wrap(lambda: None, "prompt")

        # /check then /log both fired before the raise.
        assert len(responses.calls) == 2
        assert responses.calls[1].request.url == LOG_URL


# ════════════════════════════════════════════════════════════════════════════
# wrap() ↔ check() single-call-graph parity
# ════════════════════════════════════════════════════════════════════════════


class TestWrapRoutesThroughCheck:
    @responses.activate
    def test_wrap_emits_exactly_one_log_line(self, shield):
        """wrap() reuses check(log=False) then logs once explicitly — so a
        wrap() invocation produces exactly ONE /log entry, not two."""
        responses.add(responses.POST, DECIDE_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.wrap(lambda: "ok", "prompt")

        log_calls = [c for c in responses.calls if c.request.url == LOG_URL]
        check_calls = [c for c in responses.calls if c.request.url == DECIDE_URL]
        assert len(check_calls) == 1
        assert len(log_calls) == 1

    @responses.activate
    def test_wrap_check_and_log_omit_employee_name_on_check_only(self, shield):
        """Through wrap(): /check omits employeeName, /log carries it."""
        responses.add(responses.POST, DECIDE_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.wrap(lambda: "ok", "prompt")

        check_body = json.loads(responses.calls[0].request.body)
        log_body = json.loads(responses.calls[1].request.body)
        assert "employeeName" not in check_body
        assert log_body["employeeName"] == "Test User"


# ════════════════════════════════════════════════════════════════════════════
# credential_provider — per-request dynamic Bearer credentials (v2 OIDC path)
# ════════════════════════════════════════════════════════════════════════════


class TestCredentialProvider:
    """The dynamic credential path: a zero-argument callable resolved fresh
    for EVERY outbound request (both /check and /log), so short-lived OIDC
    JWTs (e.g. AWS workload identity) never go stale inside a long-lived
    AgentShield instance. Mutually exclusive with an explicit api_key;
    provider failures fail CLOSED on the check path."""

    @staticmethod
    def _provider_shield(provider) -> AgentShield:
        return AgentShield(
            tenant_id="tenant-test", pep_url=PEP_URL,
            console_url=CONSOLE_URL,
            credential_provider=provider,
        )

    def test_constructs_without_api_key_or_env(self, monkeypatch):
        """The provider alone satisfies the credential requirement — no
        api_key argument, no G8R_API_KEY env var."""
        monkeypatch.delenv("G8R_API_KEY", raising=False)
        s = self._provider_shield(lambda: "jwt-abc")
        assert s._credential_provider is not None

    def test_explicit_api_key_and_provider_raises(self):
        """Two explicit credential sources is a config bug — fail fast."""
        with pytest.raises(ValueError, match="mutually exclusive"):
            AgentShield(
                tenant_id="t1", pep_url=PEP_URL,
                console_url=CONSOLE_URL,
                api_key="sk-static",
                credential_provider=lambda: "jwt-abc",
            )

    @responses.activate
    def test_provider_wins_over_env_api_key(self, monkeypatch):
        """A stale G8R_API_KEY left in the deployment env must never shadow
        the provider the caller opted into."""
        monkeypatch.setenv("G8R_API_KEY", "stale-env-secret")
        s = self._provider_shield(lambda: "jwt-abc")
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        s.check("test", log=False)

        auth = responses.calls[0].request.headers["Authorization"]
        assert auth == "Bearer jwt-abc"
        assert "stale-env-secret" not in auth

    @responses.activate
    def test_provider_called_per_request_on_check_and_log(self):
        """One check() with logging = two requests = two provider calls, and
        each request carries the value the provider returned for IT — proof
        the credential is resolved per request, never cached."""
        tokens = iter(["jwt-first", "jwt-second"])
        calls = []

        def provider() -> str:
            token = next(tokens)
            calls.append(token)
            return token

        s = self._provider_shield(provider)
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        s.check("test")

        assert calls == ["jwt-first", "jwt-second"]
        assert responses.calls[0].request.url == CHECK_URL
        assert responses.calls[0].request.headers["Authorization"] == "Bearer jwt-first"
        assert responses.calls[1].request.url == LOG_URL
        assert responses.calls[1].request.headers["Authorization"] == "Bearer jwt-second"

    @responses.activate
    def test_provider_exception_fails_closed_factory_never_called(self, mocker):
        """A provider failure on the check path raises ShieldConnectionError
        BEFORE anything goes on the wire — the wrapped LLM call must not
        proceed unevaluated."""

        def provider() -> str:
            raise RuntimeError("token endpoint unreachable")

        s = self._provider_shield(provider)
        factory = mocker.Mock(return_value="never")

        with pytest.raises(ShieldConnectionError):
            s.wrap(factory, "prompt")

        factory.assert_not_called()
        assert len(responses.calls) == 0  # nothing reached the console

    def test_provider_exception_message_not_leaked(self):
        """The provider's own message could carry token material; it lives on
        __cause__ (opt-in), never in str(exc)."""

        def provider() -> str:
            raise RuntimeError("secret-jwt-material-do-not-echo")

        s = self._provider_shield(provider)

        with pytest.raises(ShieldConnectionError) as exc_info:
            s.check("test", log=False)

        assert "secret-jwt-material-do-not-echo" not in str(exc_info.value)
        assert isinstance(exc_info.value.__cause__, RuntimeError)

    @responses.activate
    def test_provider_failure_on_log_path_is_swallowed(self):
        """A provider that fails only when /log resolves its credential is a
        logging failure like any other — warned, never raised, decision path
        intact."""
        outcomes = iter(["jwt-ok"])  # first call succeeds, second exhausts → StopIteration

        s = self._provider_shield(lambda: next(outcomes))
        responses.add(responses.POST, DECIDE_URL, json=allowed_response(), status=200)

        with capture_logs() as logs:
            result = s.wrap(lambda: "ok", "safe prompt")

        assert result == "ok"
        fail_logs = [e for e in logs if e.get("event") == "log_failed"]
        assert len(fail_logs) == 1
        assert fail_logs[0]["log_level"] == "error"

    def test_provider_error_backward_compatible_runtimeerror_catch(self):
        """except RuntimeError catch-alls must still trip on provider failure
        (ShieldConnectionError subclasses RuntimeError)."""

        def provider() -> str:
            raise ValueError("bad token config")

        s = self._provider_shield(provider)

        with pytest.raises(RuntimeError, match="failing closed"):
            s.check("test", log=False)


# ════════════════════════════════════════════════════════════════════════════
# is_pending_registration — v2 trust-on-first-use pending signal
# ════════════════════════════════════════════════════════════════════════════


class TestIsPendingRegistration:
    """The v2 detection rule: decision=='blocked' AND requires_approval is
    the ONLY conjunction a pending registration (server in block mode)
    produces. Everything else — plain policy blocks, admin-denied agents,
    escalations — must read False. Logic branches on the flags, never on
    the human-readable reason string."""

    @staticmethod
    def _decision(decision: str, requires_approval: bool) -> PolicyDecision:
        return PolicyDecision(
            decision=decision,
            reason="",
            violated_rule=None,
            requires_approval=requires_approval,
            session_revoked=False,
        )

    def test_blocked_with_requires_approval_is_pending(self):
        assert self._decision("blocked", True).is_pending_registration is True

    def test_blocked_without_requires_approval_is_not_pending(self):
        """Plain policy block — and the admin-DENIED registration shape."""
        assert self._decision("blocked", False).is_pending_registration is False

    def test_escalated_with_requires_approval_is_not_pending(self):
        """Escalations carry requiresApproval too; without 'blocked' they are
        human-in-the-loop review, not a pending registration."""
        assert self._decision("escalated", True).is_pending_registration is False

    def test_allowed_is_not_pending(self):
        assert self._decision("allowed", False).is_pending_registration is False

    @responses.activate
    def test_pending_response_parsed_from_wire(self, shield):
        responses.add(responses.POST, CHECK_URL, json=pending_registration_response(), status=200)

        decision = shield.check("first call from a new agent", log=False)

        assert decision.is_pending_registration is True

    @responses.activate
    def test_denied_response_parsed_from_wire(self, shield):
        """Admin-denied: blocked, requiresApproval False — NOT pending, even
        though the reason string mentions registration."""
        responses.add(responses.POST, CHECK_URL, json=denied_registration_response(), status=200)

        decision = shield.check("call from a denied agent", log=False)

        assert decision.decision == "blocked"
        assert decision.is_pending_registration is False

    @responses.activate
    def test_wrap_raises_blocked_error_carrying_pending_signal(self, shield, mocker):
        """Block mode: wrap() raises ShieldBlockedError with requires_approval
        and the mirrored property, so handlers can branch 'awaiting admin
        approval' vs. 'policy blocked' without a second round-trip."""
        responses.add(responses.POST, DECIDE_URL, json=pending_registration_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        factory = mocker.Mock()
        with pytest.raises(ShieldBlockedError) as exc_info:
            shield.wrap(factory, "first call from a new agent")

        factory.assert_not_called()
        assert exc_info.value.requires_approval is True
        assert exc_info.value.is_pending_registration is True

    @responses.activate
    def test_wrap_ordinary_block_is_not_pending(self, shield):
        """A plain policy block through wrap() must not masquerade as a
        pending registration."""
        responses.add(responses.POST, DECIDE_URL, json=blocked_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        with pytest.raises(ShieldBlockedError) as exc_info:
            shield.wrap(lambda: None, "bad prompt")

        assert exc_info.value.requires_approval is False
        assert exc_info.value.is_pending_registration is False

    def test_property_is_read_only_on_decision(self):
        d = self._decision("blocked", True)
        with pytest.raises(FrozenInstanceError):
            d.is_pending_registration = False  # type: ignore[misc]


# ════════════════════════════════════════════════════════════════════════════
# Canonical parity / contract test
# ════════════════════════════════════════════════════════════════════════════


class TestCanonicalContract:
    """Asserts the AgentShield surface matches the canonical cross-SDK
    contract EXACTLY: the constructor field set + defaults, required/optional
    split, method signatures, the error taxonomy, and the synchronized
    version. If any of these drift, Python↔TypeScript parity is broken and
    this test fails loudly."""

    CANONICAL_VERSION = "0.6.0"

    def test_constructor_exposes_exactly_the_canonical_fields(self):
        import inspect

        sig = inspect.signature(AgentShield.__init__)
        params = {name for name in sig.parameters if name != "self"}
        assert params == {
            "tenant_id",
            "pep_url",
            "console_url",
            "api_key",
            "department",
            "user_id",
            "employee_name",
            "ai_model",
            "agent_id",
            "session_id",
            "timeout",
            "block_on_escalated",
            "credential_provider",
            "receipt_verification",
        }

    def test_constructor_params_are_keyword_only(self):
        """Every field is keyword-only — there are no positional required
        args (tenant_id is required but still keyword-only, so callers can't
        accidentally pass a secret positionally)."""
        import inspect

        sig = inspect.signature(AgentShield.__init__)
        for name, p in sig.parameters.items():
            if name == "self":
                continue
            assert p.kind is inspect.Parameter.KEYWORD_ONLY, name

    def test_canonical_defaults(self):
        """The DEFAULTED actor fields carry the exact canonical defaults."""
        import inspect

        defaults = {
            name: p.default
            for name, p in inspect.signature(AgentShield.__init__).parameters.items()
        }
        assert defaults["console_url"] is None
        assert defaults["api_key"] is None
        assert defaults["department"] == "General"
        assert defaults["user_id"] == "unknown"
        assert defaults["employee_name"] is None
        assert defaults["ai_model"] == "unknown"
        assert defaults["agent_id"] == "sdk-client"
        assert defaults["session_id"] is None
        assert defaults["timeout"] == 10.0
        assert defaults["block_on_escalated"] is False
        assert defaults["credential_provider"] is None
        assert defaults["receipt_verification"] is None

    def test_tenant_id_is_the_sole_hard_required_field(self):
        """tenant_id has no default; everything else does (env-fallback fields
        default to None and resolve at runtime)."""
        import inspect

        params = inspect.signature(AgentShield.__init__).parameters
        assert params["tenant_id"].default is inspect.Parameter.empty
        for name, p in params.items():
            if name in ("self", "tenant_id"):
                continue
            assert p.default is not inspect.Parameter.empty, name

    def test_check_signature_is_canonical(self):
        import inspect

        params = inspect.signature(AgentShield.check).parameters
        assert list(params) == ["self", "prompt", "request_id", "log"]
        assert params["request_id"].kind is inspect.Parameter.KEYWORD_ONLY
        assert params["request_id"].default is None
        assert params["log"].kind is inspect.Parameter.KEYWORD_ONLY
        assert params["log"].default is True

    def test_wrap_signature_is_canonical(self):
        import inspect

        params = inspect.signature(AgentShield.wrap).parameters
        # Python: wrap(self, factory, prompt)
        assert list(params) == ["self", "factory", "prompt"]

    def test_log_is_internal_not_public(self):
        """_log is underscore-prefixed (internal) and not exported."""
        assert hasattr(AgentShield, "_log")
        assert "_log" not in g8r_shield.__all__

    def test_error_taxonomy(self):
        """The three canonical error types exist with the canonical hierarchy:
        ShieldBlockedError (Exception), ShieldConsoleError (RuntimeError),
        ShieldConnectionError (RuntimeError)."""
        assert issubclass(ShieldBlockedError, Exception)
        assert not issubclass(ShieldBlockedError, RuntimeError)
        assert issubclass(ShieldConsoleError, RuntimeError)
        assert issubclass(ShieldConnectionError, RuntimeError)

    def test_all_three_error_types_exported(self):
        for name in ("ShieldBlockedError", "ShieldConsoleError", "ShieldConnectionError"):
            assert name in g8r_shield.__all__

    def test_console_error_message_never_leaks_body(self):
        """The security-critical rule: the console error message exposes only
        the status, never the raw body."""
        exc = ShieldConsoleError(500, detail="secret-token-leak")
        assert "secret-token-leak" not in str(exc)
        assert "HTTP 500" in str(exc)
        assert exc.detail == "secret-token-leak"  # available for opt-in inspection

    def test_version_is_canonical(self):
        """Both SDKs land on the SAME 0.6.0 (lockstep) so 'are these in
        parity?' is a version-equality check in CI."""
        assert g8r_shield.__version__ == self.CANONICAL_VERSION

    def test_user_agent_reflects_canonical_version(self):
        from g8r_shield.shield import _SDK_USER_AGENT

        expected_ua = f"g8r-shield-python/{self.CANONICAL_VERSION}"
        assert expected_ua == _SDK_USER_AGENT

    def test_repr_never_exposes_api_key(self):
        """Contract: api_key must never appear in repr/str."""
        s = AgentShield(
            tenant_id="t1", pep_url=PEP_URL,
            console_url="https://c.example.com",
            api_key="sk-super-secret-abc123",
        )
        assert "sk-super-secret-abc123" not in repr(s)
        assert "api_key" not in repr(s)


# ════════════════════════════════════════════════════════════════════════════
# Sub-agent lineage — ambient session + parent-agent chain propagation
# ════════════════════════════════════════════════════════════════════════════
#
# The wire contract adds two OPTIONAL, additive fields to /check and /log:
#   - sessionId: str        — stable id for a logical agent run
#   - parentAgents: str[]   — ancestor agent-id chain, ROOT-first, absent at top
# Both are SENT, never used to decide. Absent/empty when no run or nesting is in
# effect, so un-instrumented code behaves exactly as before this feature.


def _lineage_shield(agent_id: str = "test-agent", **kwargs) -> AgentShield:
    """Build a shield against the mock console with a given agent_id."""
    return AgentShield(
        tenant_id="tenant-test", pep_url=PEP_URL,
        console_url=CONSOLE_URL,
        api_key="sk-shield-test-key",
        agent_id=agent_id,
        **kwargs,
    )


def _check_bodies() -> list[dict]:
    """Parsed request bodies of Console /check calls, in order."""
    return [json.loads(c.request.body) for c in responses.calls if c.request.url == CHECK_URL]


def _decide_bodies() -> list[dict]:
    """Parsed request bodies of wrap() PEP /decide hops, in order."""
    return [json.loads(c.request.body) for c in responses.calls if c.request.url == DECIDE_URL]


class TestLineageTopLevel:
    @responses.activate
    def test_top_level_wrap_sends_session_and_empty_parents(self, shield):
        """A top-level wrap() mints a fresh sessionId (threaded to /check AND
        /log) and sends NO ancestors — the canonical top-of-tree wire shape."""
        import uuid as _uuid

        responses.add(responses.POST, DECIDE_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.wrap(lambda: "ok", "prompt")

        check_body = json.loads(responses.calls[0].request.body)
        log_body = json.loads(responses.calls[1].request.body)

        assert "sessionId" in check_body
        _uuid.UUID(check_body["sessionId"])  # well-formed uuid4 (raises otherwise)
        # Same session on both legs so the Console can stitch the run together.
        assert check_body["sessionId"] == log_body["sessionId"]
        # No ancestors at the top level (absent on the wire).
        assert check_body.get("parentAgents", []) == []
        assert log_body.get("parentAgents", []) == []

    @responses.activate
    def test_lone_check_omits_lineage_fields(self, shield):
        """Back-compat: a lone check() with no run/nesting and no instance
        session sends NEITHER field — byte-for-byte the pre-lineage payload."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.check("prompt")

        check_body = json.loads(responses.calls[0].request.body)
        log_body = json.loads(responses.calls[1].request.body)
        for body in (check_body, log_body):
            assert "sessionId" not in body
            assert "parentAgents" not in body

    @responses.activate
    def test_instance_session_id_used_by_lone_check(self):
        """A per-instance session_id default is sent by a standalone check(),
        even without a run() scope — still no parentAgents (no nesting)."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        s = _lineage_shield(session_id="run-inst-1")

        s.check("prompt", log=False)

        body = json.loads(responses.calls[0].request.body)
        assert body["sessionId"] == "run-inst-1"
        assert "parentAgents" not in body

    @responses.activate
    def test_ambient_session_beats_instance_default(self):
        """When both are set, an active run() session wins over the instance
        default (ambient precedence)."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        s = _lineage_shield(session_id="inst-default")

        with s.run(session_id="ambient-win"):
            s.check("prompt", log=False)

        body = json.loads(responses.calls[0].request.body)
        assert body["sessionId"] == "ambient-win"


class TestLineageNested:
    @responses.activate
    def test_nested_wrap_inherits_session_and_reports_parent(self):
        """A wrap() nested inside a parent wrap()'s factory sends the SAME
        session and parentAgents == [parent_agent_id]."""
        responses.add(responses.POST, DECIDE_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        parent = _lineage_shield(agent_id="parent-agent")
        child = _lineage_shield(agent_id="child-agent")

        result = parent.wrap(
            lambda: child.wrap(lambda: "child-ok", "child prompt"),
            "parent prompt",
        )
        assert result == "child-ok"

        # /check calls in order: parent, then child (nested inside the factory).
        parent_check, child_check = _decide_bodies()
        child_log = json.loads(responses.calls[3].request.body)

        assert child_check["sessionId"] == parent_check["sessionId"]  # same run
        assert child_check["parentAgents"] == ["parent-agent"]  # sole ancestor
        assert child_log["parentAgents"] == ["parent-agent"]  # also on /log
        assert parent_check.get("parentAgents", []) == []  # parent had none

    @responses.activate
    def test_two_levels_deep_chain_is_root_first(self):
        """root -> mid -> leaf: the leaf sends parentAgents == [root, mid]
        (root-first, immediate-parent last); all three share one session."""
        responses.add(responses.POST, DECIDE_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        root = _lineage_shield(agent_id="root")
        mid = _lineage_shield(agent_id="mid")
        leaf = _lineage_shield(agent_id="leaf")

        root.wrap(
            lambda: mid.wrap(
                lambda: leaf.wrap(lambda: "leaf-ok", "leaf prompt"),
                "mid prompt",
            ),
            "root prompt",
        )

        root_check, mid_check, leaf_check = _decide_bodies()
        assert mid_check["parentAgents"] == ["root"]
        assert leaf_check["parentAgents"] == ["root", "mid"]
        assert mid_check["sessionId"] == root_check["sessionId"]
        assert leaf_check["sessionId"] == root_check["sessionId"]

    @responses.activate
    def test_escalated_proceed_path_also_nests_lineage(self):
        """The escalated-but-proceed path runs factory() inside the extended
        scope too, so a call nested under an escalated action still inherits the
        chain."""
        responses.add(responses.POST, DECIDE_URL, json=escalated_response(), status=200)
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        parent = _lineage_shield(agent_id="esc-parent")
        child = _lineage_shield(agent_id="esc-child")

        # Default block_on_escalated=False → escalated proceeds and runs factory.
        parent.wrap(lambda: child.check("nested", log=False), "destructive")

        # The nested child /check is the last one recorded.
        assert _check_bodies()[-1]["parentAgents"] == ["esc-parent"]


class TestLineageRunScope:
    @responses.activate
    def test_run_groups_calls_under_one_session(self, shield):
        """Calls inside a run() block share one ambient session — without any
        wrap(). run() establishes a session, not a parent hop."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        with shield.run() as session_id:
            shield.check("one", log=False)
            shield.check("two", log=False)

        one, two = _check_bodies()
        assert one["sessionId"] == session_id
        assert two["sessionId"] == session_id
        assert "parentAgents" not in one

    @responses.activate
    def test_run_accepts_explicit_session_id(self, shield):
        """An explicit run(session_id=...) is used verbatim and yielded."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        with shield.run(session_id="run-fixed-42") as sid:
            assert sid == "run-fixed-42"
            shield.check("x", log=False)

        assert _check_bodies()[0]["sessionId"] == "run-fixed-42"

    @responses.activate
    def test_wrap_inside_run_adopts_run_session(self, shield):
        """A wrap() inside a run() adopts the run's session rather than minting
        a fresh one — multi-turn calls stay under one run id."""
        responses.add(responses.POST, DECIDE_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        with shield.run(session_id="grp-1"):
            shield.wrap(lambda: "ok", "prompt")

        assert _decide_bodies()[0]["sessionId"] == "grp-1"

    @responses.activate
    def test_nested_run_does_not_split_session(self, shield):
        """An inner run() with no explicit id adopts the outer run's session."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        with shield.run() as outer, shield.run() as inner:
            assert inner == outer
            shield.check("x", log=False)

        assert _check_bodies()[0]["sessionId"] == outer


class TestLineageChild:
    @responses.activate
    def test_child_pushes_manual_parent_hop(self, shield):
        """child(agent_id=...) declares a manual parent hop: calls inside see
        that agent as their sole ancestor, under a minted session."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        with shield.child(agent_id="planner"):
            shield.check("x", log=False)

        body = _check_bodies()[0]
        assert body["parentAgents"] == ["planner"]
        assert "sessionId" in body  # a session is minted to carry the hop

    @responses.activate
    def test_child_hops_stack_root_first(self, shield):
        """Stacked child() scopes accumulate root-first, immediate-parent last."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        with shield.child(agent_id="root"), shield.child(agent_id="mid"):
            shield.check("x", log=False)

        assert _check_bodies()[0]["parentAgents"] == ["root", "mid"]


class TestLineageContextRestoration:
    @responses.activate
    def test_context_restored_after_allowed_wrap(self, shield):
        """After a top-level wrap(), the ambient context is back to empty — a
        subsequent lone check() inherits neither session nor chain."""
        responses.add(responses.POST, DECIDE_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.wrap(lambda: "ok", "prompt")
        shield.check("after", log=False)

        after = _check_bodies()[-1]
        assert "sessionId" not in after
        assert "parentAgents" not in after

    @responses.activate
    def test_context_restored_after_denied_wrap(self, shield):
        """Even when wrap() denies (raises), the eval-time context pin is
        unwound — a follow-up check() sends no lineage."""
        responses.add(responses.POST, DECIDE_URL, json=blocked_response(), status=200)
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        with pytest.raises(ShieldBlockedError):
            shield.wrap(lambda: None, "bad prompt")

        # A blocked check() does not raise; reuse it to inspect the payload.
        shield.check("after", log=False)
        after = _check_bodies()[-1]
        assert "sessionId" not in after
        assert "parentAgents" not in after

    @responses.activate
    def test_context_restored_when_factory_raises(self, shield):
        """If factory() raises, the nested scope is still unwound (finally)."""
        responses.add(responses.POST, DECIDE_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        def boom():
            raise ValueError("kaboom")

        with pytest.raises(ValueError, match="kaboom"):
            shield.wrap(boom, "prompt")

        shield.check("after", log=False)
        assert "sessionId" not in _check_bodies()[-1]


class TestLineageAsyncIsolation:
    @responses.activate
    def test_contextvars_isolate_across_async_tasks(self, shield):
        """Two concurrent asyncio tasks each open their own run() session; the
        ambient session must not leak between them. contextvars are task-local,
        so the SDK is safe under async fan-out even though its transport is
        synchronous (`requests`)."""
        import asyncio

        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        async def one(tag: str) -> tuple[str, str]:
            with shield.run(session_id=f"sess-{tag}"):
                # Yield so the tasks interleave between establishing the session
                # and using it; a shared ambient would cross the sessions here.
                await asyncio.sleep(0)
                shield.check("p", log=False)
                # No await between check() and this read, so calls[-1] is ours.
                sent = json.loads(responses.calls[-1].request.body)["sessionId"]
                return tag, sent

        async def main() -> dict[str, str]:
            return dict(await asyncio.gather(one("A"), one("B")))

        results = asyncio.run(main())
        assert results["A"] == "sess-A"  # each task kept its own session
        assert results["B"] == "sess-B"
