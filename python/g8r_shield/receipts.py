"""Verify signed policy decisions using the v1 receipt format.

Ed25519 comes from cryptography. This module handles the request binding and
receipt checks, not the signature algorithm itself. See the protocol in docs/.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, NoReturn, cast
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ALGORITHM = "Ed25519"
RECEIPT_TYPE = "g8r-decision-receipt+jwt"
DOMAIN = b"g8r:decision-request:v1\x00"
MAX_TOKEN_BYTES = 65_536
MAX_JSON_BYTES = 1_048_576
MAX_DEPTH = 32
MAX_NODES = 100_000
MAX_SAFE_INTEGER = 9_007_199_254_740_991
ENDPOINTS = ("/decide", "/api/sdk/v1/check")
_KID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_B64 = re.compile(r"[A-Za-z0-9_-]+\Z")
_JTI = re.compile(r"[A-Za-z0-9._-]{16,128}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_REQUEST_FIELDS = {
    "version", "method", "endpoint", "nonce", "tenantId", "agentId",
    "requestId", "governanceHeaders", "body",
}
_CLAIM_FIELDS = {
    "version", "iss", "aud", "iat", "exp", "jti", "nonce", "tenantId",
    "agentId", "requestId", "requestHash", "decision",
}
_DECISION_FIELDS = {
    "decision", "reason", "violatedRule", "requiresApproval",
    "sessionRevoked", "complianceMappings",
}


class ReceiptVerificationError(RuntimeError):
    """A receipt was rejected. Keep tokens and request bodies out of error messages."""


def _fail(message: str) -> NoReturn:
    raise ReceiptVerificationError(message)


def _object(value: Any, fields: set[str] | None = None) -> dict[str, Any]:
    if type(value) is not dict or (fields is not None and set(value) != fields):
        _fail("Invalid object fields")
    return cast(dict[str, Any], value)


def _text(value: Any, maximum: int = 256, *, empty: bool = False) -> str:
    if type(value) is not str:
        _fail("Expected string")
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeError:
        _fail("Invalid Unicode")
    if size > maximum or (not empty and size == 0):
        _fail("Invalid string length")
    return value


def _integer(value: Any, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("Invalid integer")
    return value


def canonical_json(value: Any) -> bytes:
    """Encode the supported RFC 8785 subset: safe integers, no floats.

    Sort keys by UTF-16 code units so Python and TypeScript hash the same bytes.
    Keep strings unchanged, and reject cycles or data above the size limits.
    """
    active: set[int] = set()
    nodes = 0
    size = 0
    output: list[str] = []

    def emit(text: str) -> None:
        nonlocal size
        size += len(text.encode("utf-8"))
        if size > MAX_JSON_BYTES:
            _fail("JSON too large")
        output.append(text)

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            _fail("JSON structure limit exceeded")
        if item is None:
            emit("null")
        elif type(item) is bool:
            emit("true" if item else "false")
        elif type(item) is int:
            _integer(item, -MAX_SAFE_INTEGER, MAX_SAFE_INTEGER)
            emit(str(item))
        elif type(item) is str:
            _text(item, MAX_JSON_BYTES, empty=True)
            emit(json.dumps(item, ensure_ascii=False, separators=(",", ":")))
        elif type(item) in (dict, list):
            if len(item) > MAX_NODES:
                _fail("JSON structure limit exceeded")
            identity = id(item)
            if identity in active:
                _fail("Cyclic JSON")
            active.add(identity)
            try:
                if type(item) is list:
                    emit("[")
                    for index, child in enumerate(item):
                        if index:
                            emit(",")
                        visit(child, depth + 1)
                    emit("]")
                else:
                    for key in item:
                        _text(key, MAX_JSON_BYTES, empty=True)
                    keys = sorted(item, key=lambda key: key.encode("utf-16-be"))
                    emit("{")
                    for index, key in enumerate(keys):
                        if index:
                            emit(",")
                        visit(key, depth + 1)
                        emit(":")
                        visit(item[key], depth + 1)
                    emit("}")
            finally:
                active.remove(identity)
        else:
            _fail("Unsupported JSON value; only safe integers are accepted")

    visit(value, 0)
    return "".join(output).encode("utf-8")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("Duplicate JSON member")
        result[key] = value
    return result


def parse_json(data: bytes, *, canonical: bool = False) -> Any:
    """Parse JSON without accepting duplicate keys or unsupported values."""
    if len(data) > MAX_JSON_BYTES:
        _fail("JSON too large")
    try:
        value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=_pairs)
        normalized = canonical_json(value)
        if canonical and normalized != data:
            _fail("Noncanonical signed JSON")
        return value
    except ReceiptVerificationError:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ReceiptVerificationError("Malformed JSON") from exc


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode(segment: Any, maximum: int) -> bytes:
    if type(segment) is not str or len(segment) > maximum or not _B64.fullmatch(segment):
        _fail("Malformed base64url")
    try:
        decoded = base64.urlsafe_b64decode(segment + "=" * ((-len(segment)) % 4))
    except ValueError as exc:
        raise ReceiptVerificationError("Malformed base64url") from exc
    if base64url(decoded) != segment:
        _fail("Noncanonical base64url")
    return decoded


def _nonce(value: Any) -> str:
    if type(value) is not str or len(value) != 43 or len(_decode(value, 43)) != 32:
        _fail("Invalid request nonce")
    return value


def validate_request(request: Any) -> dict[str, Any]:
    obj = _object(request, _REQUEST_FIELDS)
    if type(obj["version"]) is not int or obj["version"] != 1:
        _fail("Unsupported request version")
    if obj["method"] != "POST" or obj["endpoint"] not in ENDPOINTS:
        _fail("Unsupported request endpoint")
    _nonce(obj["nonce"])
    for name in ("tenantId", "agentId", "requestId"):
        _text(obj[name])
    headers = _object(obj["governanceHeaders"])
    for name, value in headers.items():
        if not re.fullmatch(r"x-gf-[a-z0-9-]+", name):
            _fail("Unexpected governance header")
        _text(value, 8192)
        if not re.fullmatch(r"[\x20-\x7e]+", value) or value != value.strip():
            _fail("Invalid governance header value")
    body = _object(obj["body"])
    if obj["endpoint"] == "/decide":
        if (headers.get("x-gf-tenant-id") != obj["tenantId"]
                or headers.get("x-gf-agent-id") != obj["agentId"]
                or body.get("correlation_id") != obj["requestId"]):
            _fail("Inconsistent PEP request identity")
    else:
        if any(body.get(key) != obj[key] for key in ("tenantId", "agentId", "requestId")):
            _fail("Inconsistent Console request identity")
    canonical_json(obj)
    return obj


def build_receipt_request(
    *, endpoint: str, tenant_id: str, agent_id: str, request_id: str,
    headers: Mapping[str, str], body: dict[str, Any], nonce: str | None = None,
) -> dict[str, Any]:
    """Copy the request and give it a fresh challenge. Leave credentials out.

    Send the challenge as X-G8R-Receipt-Nonce and set X-G8R-Receipt-Version to 1.
    A retry keeps this snapshot; a new evaluation gets a new challenge.
    """
    governance: dict[str, str] = {}
    for name, value in headers.items():
        if type(name) is not str:
            _fail("Invalid header name")
        lowered = name.lower()
        if lowered.startswith("x-gf-"):
            if lowered in governance:
                _fail("Duplicate governance header")
            governance[lowered] = value
    request = {
        "version": 1, "method": "POST", "endpoint": endpoint,
        "nonce": secrets.token_urlsafe(32) if nonce is None else nonce,
        "tenantId": tenant_id, "agentId": agent_id, "requestId": request_id,
        "governanceHeaders": governance, "body": body,
    }
    validate_request(request)
    return _object(parse_json(canonical_json(request)))


def request_hash(request: dict[str, Any]) -> str:
    validate_request(request)
    return hashlib.sha256(DOMAIN + canonical_json(request)).hexdigest()


def validate_decision(value: Any) -> dict[str, Any]:
    obj = _object(value, _DECISION_FIELDS)
    if obj["decision"] not in ("allowed", "blocked", "escalated"):
        _fail("Unknown policy decision")
    _text(obj["reason"], 4096, empty=True)
    if obj["violatedRule"] is not None:
        _text(obj["violatedRule"])
    if type(obj["requiresApproval"]) is not bool or type(obj["sessionRevoked"]) is not bool:
        _fail("Invalid decision flags")
    if (obj["decision"] == "allowed" and (obj["requiresApproval"] or obj["sessionRevoked"])):
        _fail("Contradictory allow decision")
    if obj["decision"] == "escalated" and not obj["requiresApproval"]:
        _fail("Escalated decision requires approval")
    if obj["sessionRevoked"] and (obj["decision"] != "blocked" or obj["requiresApproval"]):
        _fail("Contradictory revoked decision")
    mappings = obj["complianceMappings"]
    if type(mappings) is not list or len(mappings) > 64:
        _fail("Invalid compliance mappings")
    fields = {"regulation", "controlId", "controlName", "description"}
    for mapping in mappings:
        _object(mapping, fields)
        for text in mapping.values():
            _text(text, 1024, empty=True)
    return obj


def assert_receipt_transport(url: str) -> None:
    """Keep HTTPS required. A signature does not encrypt the request."""
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment or parsed.query
                or any(char in url for char in "\r\n\t")):
            _fail("Receipt verification requires HTTPS URLs without credentials, query, or fragment")
        _ = parsed.port
    except (ValueError, TypeError) as exc:
        raise ReceiptVerificationError("Invalid HTTPS URL") from exc


@dataclass(frozen=True)
class ReceiptVerificationConfig:
    issuer: str
    audience: str
    public_keys: Mapping[str, str]
    clock_skew_seconds: int = 5
    max_lifetime_seconds: int = 60


@dataclass(frozen=True, init=False)
class VerifiedReceipt:
    token: str
    _claims_json: bytes = field(repr=False)

    def __init__(self, token: str, claims: dict[str, Any]) -> None:
        object.__setattr__(self, "token", token)
        object.__setattr__(self, "_claims_json", canonical_json(claims))

    @property
    def claims(self) -> dict[str, Any]:
        return _object(parse_json(self._claims_json))

    @property
    def decision(self) -> dict[str, Any]:
        return _object(self.claims["decision"])


class ReceiptVerifier:
    """Verify with a copy of the configured public keys.

    Keys in a response are not trusted. This checks who signed the decision and
    which request it belongs to, not whether the policy evaluation was correct.
    """

    def __init__(self, config: ReceiptVerificationConfig) -> None:
        if not isinstance(config, ReceiptVerificationConfig):
            _fail("Expected ReceiptVerificationConfig")
        self._issuer = _text(config.issuer)
        self._audience = _text(config.audience)
        self._skew = _integer(config.clock_skew_seconds, 0, 30)
        self._lifetime = _integer(config.max_lifetime_seconds, 1, 300)
        if not isinstance(config.public_keys, Mapping) or not 1 <= len(config.public_keys) <= 32:
            _fail("Configure 1 to 32 trusted public keys")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
        except ImportError as exc:
            raise ReceiptVerificationError("Install g8r-shield[receipts] to verify receipts") from exc
        self._keys: dict[str, Ed25519PublicKey] = {}
        for kid, pem in config.public_keys.items():
            if type(kid) is not str or not _KID.fullmatch(kid):
                _fail("Invalid trusted key identifier")
            _text(pem, 4096)
            if not re.fullmatch(r"-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----", pem.strip()):
                _fail("Only public SPKI PEM keys are accepted")
            try:
                key = load_pem_public_key(pem.encode("ascii"))
            except (ValueError, UnicodeError, TypeError) as exc:
                raise ReceiptVerificationError("Invalid trusted public key") from exc
            if not isinstance(key, Ed25519PublicKey):
                _fail("Trusted keys must be Ed25519")
            self._keys[kid] = key

    def verify_response(
        self, response: Any, request: dict[str, Any], *, now: int | None = None,
    ) -> VerifiedReceipt:
        if type(response) is not dict or "receipt" not in response:
            _fail("Signed decision receipt is required")
        return self.verify(response["receipt"], request, now=now)

    def verify(
        self, token: Any, request: dict[str, Any], *, now: int | None = None,
    ) -> VerifiedReceipt:
        try:
            return self._verify(token, request, now=now)
        except ReceiptVerificationError:
            raise
        except Exception as exc:
            raise ReceiptVerificationError("Receipt verification failed") from exc

    def _verify(
        self, token: Any, request: dict[str, Any], *, now: int | None,
    ) -> VerifiedReceipt:
        if type(token) is not str or len(token) > MAX_TOKEN_BYTES:
            _fail("Invalid receipt size or type")
        parts = token.split(".")
        if len(parts) != 3:
            _fail("Expected compact JWS")
        header_segment, payload_segment, signature_segment = parts
        header = _object(parse_json(_decode(header_segment, 2048), canonical=True),
                         {"alg", "typ", "kid"})
        if header["alg"] != ALGORITHM or header["typ"] != RECEIPT_TYPE:
            _fail("Unsupported receipt algorithm or type")
        kid = header["kid"]
        if type(kid) is not str or not _KID.fullmatch(kid) or kid not in self._keys:
            _fail("Unknown signing key")
        signature = _decode(signature_segment, 128)
        if len(signature) != 64:
            _fail("Invalid Ed25519 signature length")
        payload_bytes = _decode(payload_segment, MAX_TOKEN_BYTES)
        signing_input = (header_segment + "." + payload_segment).encode("ascii")
        self._keys[kid].verify(signature, signing_input)
        claims = _object(parse_json(payload_bytes, canonical=True), _CLAIM_FIELDS)
        if type(claims["version"]) is not int or claims["version"] != 1:
            _fail("Unsupported receipt version")
        if claims["iss"] != self._issuer or claims["aud"] != self._audience:
            _fail("Receipt issuer or audience mismatch")
        _text(claims["jti"], 128)
        if not _JTI.fullmatch(claims["jti"]):
            _fail("Receipt identifier too short")
        issued = _integer(claims["iat"], 0, MAX_SAFE_INTEGER)
        expires = _integer(claims["exp"], 0, MAX_SAFE_INTEGER)
        current = _integer(int(time.time()) if now is None else now, 0, MAX_SAFE_INTEGER)
        if (expires <= issued or expires - issued > self._lifetime
                or issued - current > self._skew or current - expires >= self._skew):
            _fail("Receipt is expired, not yet valid, or exceeds lifetime policy")
        validate_request(request)
        for name in ("tenantId", "agentId", "requestId", "nonce"):
            if claims[name] != request[name] or type(claims[name]) is not str:
                _fail("Receipt request binding mismatch")
        digest = claims["requestHash"]
        if type(digest) is not str or not _HASH.fullmatch(digest):
            _fail("Invalid request digest")
        if not secrets.compare_digest(digest, request_hash(request)):
            _fail("Receipt request digest mismatch")
        validate_decision(claims["decision"])
        return VerifiedReceipt(token=token, claims=claims)
