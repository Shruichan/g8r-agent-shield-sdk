# G8R Agent Shield — Python SDK

Lightweight Python SDK for wrapping LLM calls with enterprise-grade policy enforcement.

Mirrors the TypeScript SDK [`@g8r-security/agent-shield-sdk`](https://www.npmjs.com/package/@g8r-security/agent-shield-sdk). Same wire contract, same semantics, idiomatic Python surface.

## Installation

```bash
pip install g8r-shield
```

For signed decision receipts (Ed25519 verification):

```bash
pip install "g8r-shield[receipts]"
```

For the Bedrock example:

```bash
pip install "g8r-shield[bedrock]"
```

Requires Python 3.10+. Pairs with a G8R Agent Shield console. See [RELEASING.md](https://github.com/Gator-Security/g8r-agent-shield-sdk/blob/main/RELEASING.md) for release and packaging details.

## Quick Start

```python
from g8r_shield import AgentShield, ShieldBlockedError

shield = AgentShield(
    tenant_id="acme-corp",
    pep_url="https://pep.yourcompany.com",       # or G8R_PEP_URL — required, no localhost
    console_url="https://shield.yourcompany.com",  # audit /log + check() gap
    api_key="sk-shield-...",
    department="Finance",
    user_id="usr_FIN_042",
    employee_name="Dana Whitfield",
    ai_model="GPT-4o",
)

# Wrap any LLM call — the factory is only invoked if the policy allows it
try:
    result = shield.wrap(
        lambda: openai.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
        ),
        prompt,
    )
except ShieldBlockedError as err:
    print("Blocked by policy:", err.violated_rule)
    for m in err.compliance_mappings:
        print(f"  {m.regulation} {m.control_id} — {m.control_name}")
```

`pep_url` is required (`G8R_PEP_URL`); there is no `console_url` fallback and loopback is refused. `console_url` / `api_key` fall back to `G8R_CONSOLE_URL` / `G8R_API_KEY`. `check()` still POSTs Console `/api/sdk/v1/check` (the documented gap). `wrap()` does not.

## How It Works

```
caller invokes shield.wrap(factory, prompt)
       |
       v
local redaction (secrets/PII never leave the process raw)
       |
       v
POST {pep_url}/decide     ← one policy hop (not Console /check)
       |
       +--> BLOCKED   → ShieldBlockedError raised (factory never called)
       +--> ESCALATED → Warning emitted, factory invoked
       +--> ALLOWED   → Factory invoked, LLM executes
       |
       v
POST {console_url}/api/sdk/v1/log   ← audit adjunct, not a second decision
```

Output post-hook stays the PEP `/proxy` HTTP chokepoint's job. wrap() does not rewrite factory output.

The factory pattern (`lambda: ...` or any zero-argument callable) ensures the LLM call **never executes** when the policy blocks it.

## API

### `AgentShield(...)`

| Parameter            | Type            | Required | Default                                     | Description                              |
| -------------------- | --------------- | -------- | ------------------------------------------- | ---------------------------------------- |
| `tenant_id`          | `str`           | Yes      | —                                           | Tenant identifier for isolation; raises `ValueError` if empty |
| `console_url`        | `str`           | Yes\*    | `G8R_CONSOLE_URL` env                        | URL of the G8R Agent Shield Console. Pass directly or set `G8R_CONSOLE_URL`; a missing value raises `ValueError` (no localhost fallback) |
| `api_key`            | `str`           | Yes\*    | `G8R_API_KEY` env                           | Static Bearer credential (your deployment's shared secret). Pass directly or set `G8R_API_KEY`; a missing value raises `ValueError`. Mutually exclusive with `credential_provider` |
| `credential_provider` | `Callable[[], str]` | No  | `None`                                      | Zero-argument callable returning the Bearer credential, invoked fresh for every request — for short-lived tokens such as OIDC JWTs. Mutually exclusive with an explicit `api_key` (`ValueError` if both are passed); when set, `G8R_API_KEY` is ignored. See [Short-lived credentials](#short-lived-credentials-oidc--aws-workload-identity) |
| `department`         | `str`           | No       | `"General"`                                 | Department of the calling user           |
| `user_id`            | `str`           | No       | `"unknown"`                                 | User identifier                          |
| `employee_name`      | `str \| None`   | No       | `None` (falls back to `user_id` in logs)    | Display name for audit trail             |
| `ai_model`           | `str`           | No       | `"unknown"`                                 | AI model being called                    |
| `agent_id`           | `str`           | No       | `"sdk-client"`                              | Agent identifier (matches TS SDK default) |
| `session_id`         | `str \| None`   | No       | `None`                                      | Per-instance default governance session grouping this instance's calls into one run. Overridden by an enclosing `run()` scope or a propagated nested context. See [Sub-agent lineage](#sub-agent-lineage) |
| `timeout`            | `float`         | No       | `10.0`                                      | HTTP request timeout in seconds          |
| `block_on_escalated` | `bool`          | No       | `False`                                     | When `True`, `wrap()` raises `ShieldBlockedError` on escalated decisions instead of proceeding with a warning (fail-closed) |
| `receipt_verification` | `ReceiptVerificationConfig \| None` | No | `None` | When set, `wrap()` and `check()` require a signed receipt on `/decide` and `/api/sdk/v1/check`. HTTPS is required on both URLs. Escalated is not executable. Unsigned is the default. See [Signed decision receipts](#signed-decision-receipts-receipt_verification). |

\* `console_url` and `api_key` may be supplied either as keyword arguments or via the `G8R_CONSOLE_URL` / `G8R_API_KEY` environment variables. If neither source provides a value, the constructor raises `ValueError`.

### Signed decision receipts (`receipt_verification`)

Unsigned is the default. `wrap()` still POSTs `{pep_url}/decide`. `check()` still POSTs Console `/api/sdk/v1/check`.

Pass `receipt_verification` to require a signed receipt on **both** hops. There is no unsigned fallback and no hop substitution. Both `pep_url` and `console_url` must be HTTPS without credentials, query, or fragment. Loopback is still refused.

In this mode `wrap()` runs the factory only for a signed `allowed` decision. A signed `escalated` decision is not executable, even when `block_on_escalated` is `False`. `check()` still returns a verified deny instead of raising. A missing or invalid receipt raises `ReceiptVerificationError`.

```python
from g8r_shield import AgentShield, ReceiptVerificationConfig

shield = AgentShield(
    tenant_id="acme-corp",
    pep_url="https://pep.yourcompany.com",
    console_url="https://shield.yourcompany.com",
    api_key="sk-shield-...",
    receipt_verification=ReceiptVerificationConfig(
        issuer="https://pep.yourcompany.com",
        audience="g8r-sdk",
        public_keys={"key-1": pem},
    ),
)
```

Install `g8r-shield[receipts]` so the `cryptography` extra is present. Trusted keys are Ed25519 public keys in SPKI PEM form, indexed by key id. The protocol is in [signed-decision-receipts-v1.md](../docs/signed-decision-receipts-v1.md).

### `shield.check(prompt: str) -> PolicyDecision`

Evaluate a prompt without executing an LLM call. Useful for pre-flight checks or UI warnings. Does NOT raise on blocked/escalated — inspect the returned decision.

### `shield.wrap(factory: Callable[[], T], prompt: str) -> T`

Evaluate a prompt and conditionally execute the LLM call. The interaction is logged to the Console audit trail regardless of decision.

- `factory` — Zero-argument callable that creates the LLM call. Only invoked when the policy decision is `allowed` or `escalated`.
- `prompt` — The text to evaluate.
- Raises `ShieldBlockedError` when the policy decision is `blocked`.
- Emits a structured `action_escalated` log line and proceeds when the policy decision is `escalated` (matching the TypeScript SDK contract). When `receipt_verification` is set, a signed `escalated` decision is never executable.
- Propagates governance lineage automatically — see [Sub-agent lineage](#sub-agent-lineage).

### `shield.run(session_id: str | None = None)`

Context manager that groups a block of calls under one governance session (minting one if `session_id` is omitted, or adopting an active/instance session). Yields the session id and restores the previous ambient context on exit, even on exception. See [Sub-agent lineage](#sub-agent-lineage).

### `shield.child(agent_id: str)`

Context manager that manually appends `agent_id` as a parent hop for its block — for nesting a child agent **outside** a wrapped factory. `wrap()` already handles the common case automatically.

### `PolicyDecision`

| Property              | Type                       | Description                                          |
| --------------------- | -------------------------- | ---------------------------------------------------- |
| `decision`            | `str`                      | `"allowed"`, `"blocked"`, or `"escalated"`           |
| `reason`              | `str`                      | Human-readable rationale                             |
| `violated_rule`       | `str \| None`              | Name of the rule that fired, if any                  |
| `requires_approval`   | `bool`                     | Whether human approval is required                   |
| `session_revoked`     | `bool`                     | Whether the agent session was revoked                |
| `compliance_mappings` | `list[ComplianceMapping]`  | Regulatory controls implicated by the decision       |
| `redacted_tokens`     | `list[str]`                | Sensitive tokens stripped from the prompt by the local-first redaction layer before it reached the gateway; empty when the prompt was clean |
| `decision_receipt`    | `str \| None`              | Verified compact JWS when `receipt_verification` is set. `None` in unsigned mode. |
| `is_pending_registration` | `bool` (read-only property) | `True` only when `decision == "blocked"` and `requires_approval` — the v2 signal that the agent's registration is awaiting admin approval. See [Agent registration](#agent-registration-trust-on-first-use) |

### `ShieldBlockedError`

| Property              | Type                       | Description                                          |
| --------------------- | -------------------------- | ---------------------------------------------------- |
| `decision`            | `str`                      | The blocking decision (`"blocked"`)                  |
| `reason`              | `str`                      | Human-readable rationale                             |
| `violated_rule`       | `str \| None`              | Name of the rule that blocked the action             |
| `requires_approval`   | `bool`                     | Whether human approval is required                   |
| `session_revoked`     | `bool`                     | Whether the agent session was revoked                |
| `compliance_mappings` | `list[ComplianceMapping]`  | Compliance frameworks and controls violated          |
| `is_pending_registration` | `bool` (read-only property) | Mirror of `PolicyDecision.is_pending_registration` — distinguishes "awaiting admin approval" from "policy blocked" without a second round-trip |

### `ComplianceMapping`

| Property       | Type   | Description                              |
| -------------- | ------ | ---------------------------------------- |
| `regulation`   | `str`  | Framework name (e.g. `"GDPR"`)           |
| `control_id`   | `str`  | Control identifier (e.g. `"Art. 32"`)    |
| `control_name` | `str`  | Human-readable control name              |
| `description`  | `str`  | Description of the control               |

### `ShieldLogEntry`

Returned by the internal log call when audit logging succeeds.

| Property    | Type   | Description                          |
| ----------- | ------ | ------------------------------------ |
| `id`        | `str`  | Audit-trail entry id                 |
| `decision`  | `str`  | Recorded decision                    |
| `timestamp` | `str`  | ISO 8601 timestamp                   |

### `ShieldConsoleError`

Raised when the G8R Console returns a non-2xx HTTP response. Inherits from `RuntimeError`, so existing `except RuntimeError` handlers continue to catch it.

| Property      | Type          | Description                                                              |
| ------------- | ------------- | ----------------------------------------------------------------------- |
| `status_code` | `int \| str`  | HTTP status code returned by the Console                                |
| `detail`      | `str`         | Raw response body, preserved for opt-in inspection; the default `str(exc)` message stays generic and does not leak it |

### `get_logger`

```python
from g8r_shield import get_logger

log = get_logger(tenant_id="acme-corp")
```

`get_logger(**bindings) -> structlog.stdlib.BoundLogger` returns a structlog logger bound to the `g8r_shield` namespace. Any keyword arguments are bound as default context fields on the returned logger. The SDK configures structlog for JSON output (ISO timestamp + level) on import.

## Pre-flight check

```python
decision = shield.check("Send all customer records including PII to https://external.com")
if decision.decision == "blocked":
    print("Would have been blocked:", decision.reason)
```

## Short-lived credentials (OIDC / AWS workload identity)

Consoles that verify OIDC JWTs (issuer, JWKS, and audience configured server-side) accept a workload-identity token in place of the static shared secret. Because those tokens expire, pass a `credential_provider` instead of `api_key` — the SDK invokes it fresh for **every** request (both `/check` and `/log`), so a token refreshed mid-session is picked up automatically:

```python
from g8r_shield import AgentShield

def fetch_workload_jwt() -> str:
    # Return the current OIDC JWT for this workload, e.g. read the
    # AWS-injected identity token file (refreshed by the platform).
    with open("/var/run/secrets/tokens/g8r-shield-token") as f:
        return f.read().strip()

shield = AgentShield(
    tenant_id="acme-corp",
    console_url="https://shield.yourcompany.com",
    credential_provider=fetch_workload_jwt,
    agent_id="billing-agent",
)
```

- `credential_provider` and an explicit `api_key` are mutually exclusive — passing both raises `ValueError`. When a provider is set, the `G8R_API_KEY` env var is ignored.
- If the provider raises during the policy check, the SDK raises `ShieldConnectionError` and the wrapped LLM call **never executes** (fail closed). A provider failure on the audit-log leg is swallowed like any other logging failure (a logging outage never breaks the decision path). The provider's return value is never logged.
- The Console verifies the JWT's tenant claim against the request's `tenant_id`; a mismatch is rejected with `403` (surfaced as `ShieldConsoleError`).

## Agent registration (trust-on-first-use)

The **first** call from an unknown `agent_id` automatically creates a *pending* registration in the Console's Approvals queue. What happens next depends on the Console's pending-agent mode:

- **flag** (server default) — calls from the pending agent evaluate normally under policy while admins approve in the background. Your integration needs no changes.
- **block** — calls from the pending agent return `blocked` with `requires_approval` until an admin approves it, so `wrap()` raises `ShieldBlockedError`.

On v2, `decision == "blocked"` together with `requires_approval` occurs **only** for a pending registration — the SDK exposes that conjunction as `is_pending_registration` (on both `PolicyDecision` and `ShieldBlockedError`) so you can distinguish "awaiting admin approval" from "policy blocked" without parsing reason strings:

```python
from g8r_shield import ShieldBlockedError

try:
    result = shield.wrap(lambda: call_llm(prompt), prompt)
except ShieldBlockedError as err:
    if err.is_pending_registration:
        print("Agent awaiting approval in the Console Approvals queue — retry later.")
    else:
        print("Blocked by policy:", err.violated_rule)
```

An agent an admin has *denied* comes back `blocked` **without** `requires_approval` (in both modes), so it correctly reads as a policy block, not a pending one.

## Sub-agent lineage

When one governed agent spawns another, the child call should be governed *with awareness of the chain above it* — otherwise a nested agent could sidestep the policy that gated its parent. `wrap()` propagates that lineage **automatically**: no manual instrumentation, and no change to existing single-agent code.

Every `wrap()` reads the ambient governance context, governs the call under it, and then runs the factory inside a scope that appends its own `agent_id`. Any `wrap()` or `check()` nested inside the factory inherits the **same session** and this agent as its **immediate parent**:

```python
root  = AgentShield(tenant_id="acme", console_url=URL, api_key=KEY, agent_id="orchestrator")
child = AgentShield(tenant_id="acme", console_url=URL, api_key=KEY, agent_id="researcher")

# A top-level wrap() mints a fresh session and has no ancestors.
root.wrap(
    lambda: child.wrap(              # nested inside root's factory...
        lambda: call_llm(prompt),    # ...governed as a child of "orchestrator"
        prompt,
    ),
    plan_prompt,
)
```

Here the inner call is evaluated with `parentAgents == ["orchestrator"]` under the **same** `sessionId` as the outer one — governed with full chain awareness. Two levels deep, a leaf sees `["orchestrator", "researcher"]` (root-first, immediate-parent last).

### Grouping calls into a run — `run()`

To thread one session across calls that aren't nested through a factory (e.g. multi-turn, or a series of `check()`s), open a `run()` scope:

```python
with shield.run() as session_id:      # mints a session (or pass session_id=...)
    shield.check("step one")
    shield.wrap(lambda: call_llm(p), p)   # same session_id
```

`run()` establishes (or adopts) a session for the block and restores the previous context on exit — even on exception. Nesting `run()` never splits a session. A per-instance default is also available: `AgentShield(..., session_id="...")`.

For nesting **outside** a wrapped factory, `shield.child(agent_id="planner")` is a context manager that manually appends a parent hop for its block.

### Wire fields

Two **optional, additive** fields are sent on both `/api/sdk/v1/check` and `/api/sdk/v1/log`:

| Field          | Type       | Meaning                                                                                 |
| -------------- | ---------- | --------------------------------------------------------------------------------------- |
| `sessionId`    | `string`   | Stable id for one logical agent run, propagated across nested and multi-turn calls      |
| `parentAgents` | `string[]` | Ancestor agent-id chain, ordered **root-first, immediate-parent last**; absent at the top level |

Both are **omitted** when no run or nesting is in effect, so un-instrumented code sends exactly the payload it did before — fully backward-compatible. Lineage is **sent, never used to decide**.

> **Trust model.** This lineage is **advisory** — both the session id and the parent chain are *self-asserted* by the SDK caller, and the Console records them as reported. Attestation-bound signing (so a child cannot forge or drop its ancestry) is a **future** addition; the wire fields are additive precisely so that upgrade stays backward-compatible.

## AWS Bedrock example

See [example_bedrock.py](example_bedrock.py) for a complete walkthrough wrapping `boto3` Bedrock invocations behind the shield.

## Compliance Coverage

Every policy decision maps to specific regulatory controls:

| Regulation       | Controls                  |
| ---------------- | ------------------------- |
| NIST AI RMF      | Governance, Risk, Privacy |
| GDPR             | Art. 5, 32, 44            |
| HIPAA            | 164.502, 164.514          |
| CCPA             | 1798.100, 1798.150        |
| PCI-DSS          | 3.3, 3.4, 8.2, 10.2       |
| OWASP LLM Top 10 | LLM01, LLM02, LLM06       |

## Backend Endpoints

The SDK communicates with two endpoints on the Agent Shield Console:

| Endpoint         | Method | Purpose                                     |
| ---------------- | ------ | ------------------------------------------- |
| `/api/sdk/v1/check` | POST   | Evaluate a prompt against the policy engine |
| `/api/sdk/v1/log`   | POST   | Log an interaction to the audit trail       |

Both require an `Authorization: Bearer <credential>` header, where the credential is either your deployment's shared secret (`api_key` / `G8R_API_KEY`) or a verified OIDC JWT supplied via `credential_provider`. A bad or missing credential returns `401`; a JWT whose tenant claim does not match the request's `tenant_id` returns `403` (the verified claim wins). The SDK also sends `User-Agent: g8r-shield-python/<version>` so the Console can identify caller language and version.

## Requirements

- Python 3.10+
- `requests` 2.31+

## Google ADK (Gemini Enterprise / Agent Engine)

```bash
pip install "g8r-shield[adk]"
```

```python
from google.adk.runners import Runner
from g8r_shield import AgentShield
from g8r_shield.adk import ShieldPlugin

shield = AgentShield(
    tenant_id="...", console_url="https://console.example", api_key="...",
    agent_id="support-bot", department="Support",
)

runner = Runner(
    agent=root_agent,
    app_name="support",
    session_service=session_service,
    plugins=[ShieldPlugin(shield)],     # governs the WHOLE agent tree
)
```

One registration on the `Runner` covers every agent, sub-agent and tool — including agents added
later. Per-agent callbacks have to be repeated on each agent, and anything a developer forgets to
wire is silently ungoverned; a plugin cannot be forgotten.

### What it does

| Hook | Behaviour |
|---|---|
| `before_tool_callback` | **The gate.** Evaluates the tool + arguments; a block returns a denial dict so the side effect never happens and the model is told why. |
| `before_model_callback` | Optional prompt gate — **off by default** (it evaluates every model turn, roughly doubling policy traffic). Enable with `gate_prompts=True`. |

Sub-agent lineage is automatic: ADK's `invocation_id` becomes the governance `session_id`, and
its `branch` (the agent hierarchy path) becomes the root-first parent chain, so the Console can
stitch a multi-agent run back together.

### Options

| Option | Default | Notes |
|---|---|---|
| `gate_tools` | `True` | Evaluate tool calls. |
| `gate_prompts` | `False` | Also evaluate each model turn. |
| `fail_open` | `False` | **Fail-closed by default.** If the control plane is unreachable the tool is blocked — an outage must not silently become allow-all. Flipping this is an auditable choice. |
| `redact` | `True` | Strip high-entropy secrets from tool arguments before they leave the process. PII is deliberately preserved so the server-side detectors can still enforce PII policy; the control plane keeps content out of the audit body. |

### Async note

ADK hooks are async; the Shield client is synchronous. The plugin runs every policy call on a
worker thread (`asyncio.to_thread`), so a policy round trip never blocks the event loop — calling
the client directly from a hook would stall every other agent in the process.
