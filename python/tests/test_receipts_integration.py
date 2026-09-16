"""Run these in the SDK checkout after installing [dev,receipts]."""
from __future__ import annotations

import copy
import json
import time
import uuid

import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from g8r_shield import (
    AgentShield,
    ReceiptVerificationConfig,
    ReceiptVerificationError,
    ShieldBlockedError,
)
from g8r_shield.receipts import (
    ALGORITHM,
    RECEIPT_TYPE,
    base64url,
    build_receipt_request,
    canonical_json,
    request_hash,
)

KEY = Ed25519PrivateKey.generate()
PUBLIC = KEY.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()
VERIFICATION = ReceiptVerificationConfig("integration-authority", "integration-sdk", {"test": PUBLIC})
CONFIG = dict(tenant_id="test-tenant", agent_id="test-agent", api_key="test-credential",
              pep_url="https://pep.example.test", console_url="https://console.example.test",
              receipt_verification=VERIFICATION)


def decision(outcome="allowed"):
    return dict(decision=outcome, reason="SDK integration test", violatedRule=None,
                requiresApproval=outcome == "escalated", sessionRevoked=False, complianceMappings=[])


def sign(request, result, algorithm=ALGORITHM):
    now = int(time.time())
    header = dict(alg=algorithm, typ=RECEIPT_TYPE, kid="test")
    claims = dict(version=1, iss=VERIFICATION.issuer, aud=VERIFICATION.audience,
                  iat=now, exp=now + 30, jti=str(uuid.uuid4()), nonce=request["nonce"],
                  tenantId=request["tenantId"], agentId=request["agentId"], requestId=request["requestId"],
                  requestHash=request_hash(request), decision=result)
    message = base64url(canonical_json(header)) + "." + base64url(canonical_json(claims))
    return message + "." + base64url(KEY.sign(message.encode("ascii")))


def install_transport(monkeypatch, make):
    seen = []

    def post(url, *, json, headers, timeout):
        if url.endswith("/api/sdk/v1/log"):
            value = dict(id="log", decision="allowed", timestamp="test")
        else:
            endpoint = "/decide" if url.endswith("/decide") else "/api/sdk/v1/check"
            assert headers["X-G8R-Receipt-Version"] == "1"
            assert len(headers["X-G8R-Receipt-Nonce"]) == 43
            request = build_receipt_request(
                endpoint=endpoint, tenant_id=CONFIG["tenant_id"], agent_id=CONFIG["agent_id"],
                request_id=json["correlation_id"] if endpoint == "/decide" else json["requestId"],
                headers=headers, body=json, nonce=headers["X-G8R-Receipt-Nonce"],
            )
            seen.append(copy.deepcopy(request))
            value = make(request, len(seen))
        response = requests.Response()
        response.status_code = 200
        response._content = canonical_json(value)
        return response

    monkeypatch.setattr(requests, "post", post)
    return seen


def test_signed_allow_executes_once(monkeypatch):
    install_transport(monkeypatch, lambda r, _: dict(receipt=sign(r, decision())))
    called = []
    result = AgentShield(**CONFIG).wrap(lambda: called.append(True) or "done", "demo:allow")
    assert result == "done" and called == [True]


@pytest.mark.parametrize("outcome", ["blocked", "escalated"])
def test_deny_and_approval_never_execute(monkeypatch, outcome):
    install_transport(monkeypatch, lambda r, _: dict(receipt=sign(r, decision(outcome)), decision="allowed"))
    called = []
    with pytest.raises(ShieldBlockedError):
        AgentShield(**CONFIG, block_on_escalated=False).wrap(lambda: called.append(True), "demo:allow")
    assert not called


def test_check_returns_verified_deny_and_receipt(monkeypatch):
    install_transport(monkeypatch, lambda r, _: dict(receipt=sign(r, decision("blocked"))))
    result = AgentShield(**CONFIG).check("demo:deny")
    assert result.decision == "blocked"
    assert result.decision_receipt is not None and len(result.decision_receipt.split(".")) == 3


@pytest.mark.parametrize("fault", ["missing", "wrong-request", "tampered", "wrong-algorithm", "contradictory-allow"])
def test_invalid_receipt_never_executes(monkeypatch, fault):
    def response(request, _):
        if fault == "missing":
            return dict(decision="allowed")
        bound = copy.deepcopy(request)
        if fault == "wrong-request":
            bound["body"]["body"]["prompt"] = "different prompt"
        result = decision()
        if fault == "contradictory-allow":
            result["requiresApproval"] = True
        token = sign(bound, result, "EdDSA" if fault == "wrong-algorithm" else ALGORITHM)
        if fault == "tampered":
            parts = token.split(".")
            parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
            token = ".".join(parts)
        return dict(receipt=token, decision="allowed")

    install_transport(monkeypatch, response)
    called = []
    with pytest.raises(ReceiptVerificationError):
        AgentShield(**CONFIG).wrap(lambda: called.append(True), "demo:allow")
    assert not called


def test_reused_request_id_gets_fresh_nonce(monkeypatch):
    seen = install_transport(monkeypatch, lambda r, _: dict(receipt=sign(r, decision())))
    shield = AgentShield(**CONFIG)
    shield.check("demo:allow", request_id="same-request-id", log=False)
    shield.check("demo:allow", request_id="same-request-id", log=False)
    assert seen[0]["requestId"] == seen[1]["requestId"]
    assert seen[0]["nonce"] != seen[1]["nonce"]


@pytest.mark.parametrize("method", ["check", "wrap"])
def test_transient_retry_reuses_binding(monkeypatch, method):
    def response(request, index):
        if index == 1:
            raise requests.exceptions.ConnectionError("simulated network interruption")
        return dict(receipt=sign(request, decision()))

    seen = install_transport(monkeypatch, response)
    shield = AgentShield(**CONFIG)
    if method == "check":
        shield.check("demo:allow", log=False)
    else:
        shield.wrap(lambda: "done", "demo:allow")
    assert len(seen) == 2 and seen[0] == seen[1]


def test_binding_contains_only_redacted_input(monkeypatch):
    seen = install_transport(monkeypatch, lambda r, _: dict(receipt=sign(r, decision())))
    AgentShield(**CONFIG).wrap(lambda: "done", "SSN: 123-45-6789")
    assert "123-45-6789" not in json.dumps(seen[0])


def test_legacy_mode_still_unsigned_and_advisory(monkeypatch):
    seen = []

    def post(url, *, json, headers, timeout):
        seen.append(headers)
        value = (dict(decision=dict(outcome="REQUIRE_APPROVAL", explanation="legacy advisory"))
                 if url.endswith("/decide") else dict(id="log", decision="allowed", timestamp="test"))
        response = requests.Response()
        response.status_code = 200
        response._content = canonical_json(value)
        return response

    monkeypatch.setattr(requests, "post", post)
    legacy = {key: value for key, value in CONFIG.items() if key != "receipt_verification"}
    assert AgentShield(**legacy).wrap(lambda: "legacy", "demo:allow") == "legacy"
    assert all("X-G8R-Receipt-Nonce" not in headers for headers in seen)


@pytest.mark.parametrize("field", ["pep_url", "console_url"])
def test_signed_mode_requires_https(field):
    with pytest.raises(ReceiptVerificationError):
        AgentShield(**{**CONFIG, field: "http://example.test"})
