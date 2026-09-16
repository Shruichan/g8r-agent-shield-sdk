# @g8r-security/agent-shield-sdk

TypeScript client SDK for integrating AI agents with G8R policy enforcement. Includes a **local VPC redaction layer** that strips sensitive data before it ever leaves your network.

Part of the [G8R Agent Shield monorepo](../../README.md).

## Overview

This is a **compiled package**, built with [tsup](https://tsup.egg.js.org/). Publishing ships the `dist/` output — ESM (`dist/index.mjs`), CommonJS (`dist/index.js`), and type declarations (`dist/index.d.ts`) — and `package.json` sets `"files": ["dist"]`, so `src/` is **not** included in the published tarball. Consumers import from the package name:

```typescript
import { AgentShield, tenantId } from '@g8r-security/agent-shield-sdk';
```

No `transpilePackages` / `resolve.alias` wiring is needed — the package resolves through its standard `main` / `module` / `types` / `exports` entry points.

## Quick Start

```typescript
import { AgentShield, tenantId } from '@g8r-security/agent-shield-sdk';

const shield = new AgentShield({
  tenantId: tenantId('acme-corp'),        // the only hard-required field
  pepUrl: 'https://pep.yourcompany.com',  // or G8R_PEP_URL — required, no localhost
  consoleUrl: 'https://shield.yourcompany.com', // or G8R_CONSOLE_URL (audit /log)
  apiKey: 'sk-shield-...',                // or G8R_API_KEY env var
  agentId: 'enterprise-assistant',        // optional — defaults to 'sdk-client'
  department: 'Finance',                  // optional — defaults to 'General'
  userId: 'usr_FIN_042',                  // optional — defaults to 'unknown'
  aiModel: 'GPT-4o',                      // optional — defaults to 'unknown'
});

// Factory pattern — LLM is only called if the policy check passes
const result = await shield.wrap(
  () => openai.chat.completions.create({ model: 'gpt-4o', messages }),
  userPrompt
);
```

> **`ShieldConfig` fields.** `tenantId` is the **only hard-required** identity field. `pepUrl` is **required-in-effect** (`G8R_PEP_URL`); wrap() hops `POST {pepUrl}/decide` with **no** `consoleUrl` fallback and loopback refused. `consoleUrl` / `apiKey` are required-in-effect for audit `/log` and the `check()` gap (`G8R_CONSOLE_URL` / `G8R_API_KEY`). The constructor **throws** rather than defaulting to localhost. The credential can alternatively come from a [`credentialProvider`](#authenticating-with-short-lived-credentials-credentialprovider) — mutually exclusive with `apiKey`. Everything else is **optional with a default**: `department` (`"General"`), `userId` (`"unknown"`), `aiModel` (`"unknown"`), `agentId` (`"sdk-client"`), `employeeName` (falls back to `userId` in the audit log), `timeout` (`10` seconds), and `blockOnEscalated` (`false`). `sessionId` is optional with **no** default. `receiptVerification` is optional and **unset by default** (unsigned). See [Signed decision receipts](#signed-decision-receipts-receiptverification).

```typescript
// Minimal — consoleUrl + apiKey from env, everything else defaulted:
//   export G8R_CONSOLE_URL=https://shield.yourcompany.com
//   export G8R_API_KEY=sk-shield-...
const shield = new AgentShield({ tenantId: tenantId('acme-corp') });
```

### Signed decision receipts (`receiptVerification`)

Unsigned is the default. `wrap()` still POSTs `{pepUrl}/decide`. `check()` still POSTs Console `/api/sdk/v1/check`.

Pass `receiptVerification` to require a signed receipt on **both** hops. There is no unsigned fallback and no hop substitution. Both `pepUrl` and `consoleUrl` must be HTTPS without credentials, query, or fragment. Loopback is still refused.

In this mode `wrap()` runs the factory only for a signed `allowed` decision. A signed `escalated` decision is not executable, even when `blockOnEscalated` is `false`. `check()` still returns a verified deny instead of throwing. A missing or invalid receipt raises `ReceiptVerificationError`.

```typescript
import { AgentShield, tenantId } from '@g8r-security/agent-shield-sdk';
import type { ReceiptVerificationConfig } from '@g8r-security/agent-shield-sdk';

const receiptVerification: ReceiptVerificationConfig = {
  issuer: 'https://pep.yourcompany.com',
  audience: 'g8r-sdk',
  publicKeys: {
    'key-1': process.env.G8R_RECEIPT_PUBLIC_KEY_PEM!,
  },
};

const shield = new AgentShield({
  tenantId: tenantId('acme-corp'),
  pepUrl: 'https://pep.yourcompany.com',
  consoleUrl: 'https://shield.yourcompany.com',
  apiKey: process.env.G8R_API_KEY,
  receiptVerification,
});
```

Trusted keys are Ed25519 public keys in SPKI PEM form, indexed by key id. The protocol is in [signed-decision-receipts-v1.md](../docs/signed-decision-receipts-v1.md).

### Authenticating with short-lived credentials (`credentialProvider`)

The Console accepts either the deployment **shared secret** or a **verified OIDC JWT** (workload identity — e.g. AWS) in the same `Authorization: Bearer` header. For JWTs — which expire — pass a `credentialProvider` instead of a static `apiKey`. The provider is awaited **fresh on every `/decide`, `/check`, and `/log` request**, so a rotated token is always picked up:

```typescript
const shield = new AgentShield({
  tenantId: tenantId('acme-corp'),
  consoleUrl: 'https://shield.yourcompany.com',
  // Mint/refresh the OIDC workload-identity JWT per request — sync or async.
  credentialProvider: () => getWorkloadIdentityToken(),
});
```

- `apiKey` and `credentialProvider` are **mutually exclusive** — the constructor throws if both are passed, and the `G8R_API_KEY` env fallback is not consulted when a provider is configured.
- A provider **rejection on the policy check fails closed**: the SDK throws `ShieldConnectionError` (the provider's error is preserved on `.cause`), and `wrap()` never invokes the LLM factory. On the audit-log leg a provider failure is swallowed like any other logging failure — a logging outage never breaks the decision path (same contract as the Python SDK).
- The resolved credential is used only for the `Authorization` header and is **never logged**.
- With a verified JWT, the server trusts the JWT's **tenant claim** over the request body's `tenantId` — a mismatch returns HTTP `403`. A bad or missing credential returns `401`.

### Agent registration (trust on first use)

The **first** call from an unknown `agentId` auto-creates a **pending registration** in the Console's **Approvals queue**. What happens while it is pending depends on the server's pending-agent mode:

- **`flag`** (server default) — calls from a pending agent evaluate normally under policy; admins get an alert. The SDK sees ordinary decisions.
- **`block`** — calls return `decision: 'blocked'` with `requiresApproval: true` until an admin approves the agent.

The SDK derives `isPendingRegistration` **client-side** from exactly that conjunction (`decision === 'blocked' && requiresApproval === true`) — it is **not** a wire field, and reason strings are never parsed:

```typescript
try {
  const result = await shield.wrap(() => llmCall(), prompt);
} catch (err) {
  if (err instanceof ShieldBlockedError && err.isPendingRegistration) {
    // Not a policy violation — the agent is awaiting approval in the
    // Console's Approvals queue. Ask an admin to approve it, then retry.
  }
}

// Or, without wrap():
const result = await shield.check(prompt);
if (result.isPendingRegistration) {
  // Same signal on the raw decision object.
}
```

An admin-**denied** agent returns `blocked` with `requiresApproval: false` in both modes, so `isPendingRegistration` stays unset for it — that block is a verdict, not a waiting room.

## API

### `shield.wrap(factory, prompt)`

The primary integration point. Runs the full pipeline:

1. **Redact** — `redactSensitiveData(prompt)` strips secrets locally
2. **Decide** — POST redacted prompt to `{pepUrl}/decide` (one PEP policy hop)
3. **Log** — POST audit entry to Console `/api/sdk/v1/log`
4. **Invoke** — call `factory()` only if decision is `allowed`, or `escalated` while `blockOnEscalated` is `false`

If blocked, throws `ShieldBlockedError` — the factory is **never called**. If `escalated` and the shield was constructed with `blockOnEscalated: true`, it also throws `ShieldBlockedError`; otherwise an escalated action proceeds with a warning (pending out-of-band human review). When `receiptVerification` is set, a signed `escalated` decision is never executable. Internally `wrap()` runs PEP `/decide` and then a single `/log`, both under one `requestId` and one resolved [lineage](#sub-agent-lineage), so the policy hop and the audit line correlate under a single id. `wrap()` never POSTs Console `/api/sdk/v1/check`. That remaining hop is `check()` only. When allowed (or escalated-and-proceeding), the factory runs inside an ambient scope so nested `wrap()` calls inherit the session and parent-agent chain automatically.

```typescript
try {
  const result = await shield.wrap(() => llmCall(), prompt);
  console.log(result.llmResult);      // LLM response
  console.log(result.redactedTokens); // Tokens stripped from the prompt
} catch (err) {
  if (err instanceof ShieldBlockedError) {
    console.log(err.violatedRule);        // e.g. 'PII Detection'
    console.log(err.complianceMappings);  // GDPR Art. 32, etc.
  }
}
```

### `shield.check(prompt, opts?)`

Policy check only — no LLM call. **Never throws** on a `blocked`/`escalated` decision; it returns the decision for the caller to act on. By default it is **self-auditing** — it also POSTs to `/log` with the same `requestId`. Pass `{ log: false }` if you will follow up with `wrap()` for the same prompt (to avoid a duplicate audit entry), and `{ requestId }` to supply your own correlation id.

```typescript
const result = await shield.check(prompt);
// result.decision         → 'allowed' | 'blocked' | 'escalated'
// result.redactedTokens   → tokens stripped from the prompt before sending

// Options:
const result2 = await shield.check(prompt, {
  requestId: newRequestId(), // supply your own correlation id (optional)
  log: false,                // suppress the built-in audit log (default: true)
});
```

On a non-2xx response, `check()` throws a typed **`ShieldConsoleError`** (its message exposes only the status code — the raw body is on `.detail`). On a transient connection failure it retries once, then throws **`ShieldConnectionError`**.

### `shield.run(fn, opts?)`

Establishes an ambient governance **session** for the duration of `fn`, so every `wrap()`/`check()` call made inside it — across `await`s and nested agents — shares one `sessionId` with no manual threading. Use it to group a multi-turn conversation or a fan-out of tool calls that belong to **one logical run**. Returns whatever `fn` returns (await it if `fn` is async). See [Sub-agent lineage](#sub-agent-lineage).

```typescript
await shield.run(async () => {
  await shield.wrap(() => turn1(), prompt1);
  await shield.wrap(() => turn2(), prompt2); // same sessionId as turn1
}, { sessionId: 'conversation-abc' }); // sessionId optional — minted if omitted
```

The session resolves as: explicit `opts.sessionId` → the ambient session already in scope → the instance's configured `sessionId` → a freshly minted one. Any ancestor agent chain already in scope is preserved (`run()` groups calls under a session; `wrap()` is what extends the chain). The prior context is restored when `fn` returns or throws.

### `redactSensitiveData(input)`

Standalone redaction — can be used independently of the shield client.

```typescript
import { redactSensitiveData } from '@g8r-security/agent-shield-sdk';

const { redacted, tokensReplaced } = redactSensitiveData(input);
```

## Sub-agent lineage

When an agent governed by the SDK spawns **sub-agents** that are themselves governed, each hop should be evaluated with awareness of the run it belongs to and the agents that led to it. The SDK propagates that **lineage automatically** through nested `wrap()` calls — no manual instrumentation at each call site — by adding two optional, additive fields to the policy hop (`{pepUrl}/decide` for `wrap()`, Console `/api/sdk/v1/check` for `check()`) and `/log` wire payloads:

| Field | Type | Meaning |
|---|---|---|
| `sessionId` | `string` | Stable id for one logical agent run, propagated across nested **and** multi-turn calls. |
| `parentAgents` | `string[]` | Ancestor agent-id chain, **root-first, immediate-parent last**. Absent for a top-level call. |

### How propagation works

`wrap()` maintains an ambient governance context (backed by Node's `AsyncLocalStorage`). For each call it:

1. Resolves the **session** — the ambient session in scope, else this instance's configured `sessionId`, else a freshly minted one (`crypto.randomUUID`). A top-level call therefore mints a fresh session; a nested call inherits its parent's.
2. Resolves the **parent chain** — the ancestor chain in scope (empty at the top).
3. Sends both on the policy hop (`{pepUrl}/decide` for `wrap()`, Console `/check` for `check()`) and on `/log`.
4. Runs the factory **inside an extended scope** whose chain now ends with this agent, so any `wrap()` the factory makes — directly or in an awaited continuation — inherits the same session and the extended chain. The prior context auto-restores when the call returns, including on a block/throw.

```typescript
const orchestrator = new AgentShield({ ...cfg, agentId: 'orchestrator' });
const researcher   = new AgentShield({ ...cfg, agentId: 'researcher' });

await orchestrator.wrap(async () => {
  // This nested call is governed with lineage automatically:
  //   sessionId    → the SAME session as the orchestrator call
  //   parentAgents → ['orchestrator']   (root-first)
  await researcher.wrap(() => llm(), 'research the filing');
  return synthesize();
}, 'produce the report');
```

Two levels deep, the innermost call sends `parentAgents: ['orchestrator', 'researcher']`. Because the context is backed by `AsyncLocalStorage`, concurrent agent runs stay isolated — interleaved chains never observe each other's session or lineage.

### Grouping a run explicitly

Use [`shield.run(fn, { sessionId? })`](#shieldrunfn-opts) to bind a session across calls that aren't nested inside one `wrap()` — e.g. the turns of a conversation, or a fan-out of sibling tool calls:

```typescript
await shield.run(async () => {
  await shield.wrap(() => turnOne(), promptOne);
  await shield.wrap(() => turnTwo(), promptTwo); // shares turnOne's sessionId
});
```

`wrap()` itself is the **child-agent helper**: nesting a `wrap()` (from any shield instance, including a distinct sub-agent identity) inside another `wrap()`'s factory is all it takes to extend the chain — the sub-agent's `agentId` is appended automatically.

### Trust model — advisory, self-asserted

Lineage is **advisory / self-asserted**: the `sessionId` and `parentAgents` a client sends are metadata it vouches for, not cryptographically proven identity. The governance plane uses them for correlation, chain-aware policy, and audit — it **never** lets them relax a decision, and neither does the SDK (lineage is sent, but the local enforcement path is unchanged). Attestation-bound signing of the chain (so a hop's ancestry can be *verified*, not merely asserted) is a planned future capability; until then, treat lineage as trustworthy only to the extent you trust the agents populating it.

### Backward compatibility & environment support

The fields are **omitted entirely** when not meaningful: a plain, un-nested `check()` with no configured/ambient session sends neither, so existing integrations are byte-for-byte unchanged. On runtimes where `AsyncLocalStorage` cannot be loaded (browsers, some bundles) the SDK degrades to a single module-level context: synchronous nesting still propagates and the scope still restores, but concurrent async chains are **not** isolated. Prefer a Node runtime for lineage-critical multi-tenant workloads.

## Redaction Layer

Sensitive data is detected and replaced **locally** before the prompt leaves the process — on both the policy-check and audit-log paths, so the gateway never receives recognized raw secrets.

> ⚠️ **Best-effort, not exhaustive.** Redaction is pattern- and entropy-based. It catches the formats listed below, but it **cannot** catch every secret or PII shape — unstructured PII (names, addresses), free-form secrets below the entropy threshold, or novel token formats may pass through. Treat this as one layer of defense-in-depth, not a compliance guarantee, and keep downstream controls and human review in place.

### Detection Patterns

| Pattern | Label |
|---|---|
| BIP-32 extended keys (`xpub`, `xprv`, `ypub`, …) | `[REDACTED:BIP32_KEY]` |
| WIF private keys (Base58, starts with `5`, `K`, or `L`) | `[REDACTED:WIF_KEY]` |
| 256-bit hex keys (64 hex chars, optional `0x` prefix) | `[REDACTED:HEX_KEY]` |
| PEM private / public key blocks | `[REDACTED:PEM_KEY]` |
| `custodial-id:…` / `cust-{digits}` / `wallet-id:…` / `vault-id:…` | `[REDACTED:CUSTODIAL_ID]` etc. |
| Card numbers (13–19 digits, Luhn-validated) | `[REDACTED:CARD]` |
| US SSNs (`123-45-6789`) | `[REDACTED:SSN]` |
| Email addresses | `[REDACTED:EMAIL]` |
| Phone numbers (separated, e.g. `415-555-0199`) | `[REDACTED:PHONE]` |
| High Shannon entropy strings (≥4.5 bits/char, ≥32 chars) | `[REDACTED:HIGH_ENTROPY]` |

These map to controls such as **GDPR Art. 32** (security of processing) and **PCI-DSS** PAN handling by reducing sensitive-data exposure — they *support* those controls rather than satisfy them on their own.

### Shannon Entropy Detection

Any token that is 32+ characters with Shannon entropy ≥ 4.5 bits/char is caught as a generic high-entropy secret. This is a best-effort catch for many API keys and tokens that don't match a known format — but secrets shorter than 32 chars or below the entropy threshold will not be caught.

```
H = -Σ p(c) × log₂(p(c))   for each unique character c
```

Low-entropy strings (e.g. `"aaaaaaaaaaaaa"`, entropy ≈ 0) are not flagged.

## `PolicyCheckResult`

```typescript
interface PolicyCheckResult {
  decision: 'allowed' | 'blocked' | 'escalated';
  reason: string;
  violatedRule: string | null;
  requiresApproval: boolean;
  isPendingRegistration?: boolean; // Derived client-side (NOT a wire field):
                                   // decision === 'blocked' && requiresApproval === true,
                                   // i.e. the agent awaits approval in the Approvals queue
  complianceMappings: ComplianceMapping[];
  sessionRevoked?: boolean;
  redactedTokens?: string[];  // Tokens stripped by VPC masking layer
  decisionReceipt?: string;   // Verified compact JWS when receiptVerification is set
}
```

## Error taxonomy

```typescript
// Thrown by wrap() on a 'blocked' decision, or an 'escalated' decision when
// the shield was constructed with blockOnEscalated: true. The one error a
// normal caller catches.
class ShieldBlockedError extends Error {
  decision: string;                        // 'blocked' | 'escalated'
  reason: string;
  violatedRule: string | null;
  complianceMappings: ComplianceMapping[];
  sessionRevoked: boolean;                 // true when a kill-switch policy fired
  isPendingRegistration: boolean;          // true when the block is the trust-on-first-use
                                           // registration gate, not a policy verdict
}

// Thrown on a non-2xx HTTP response from /check. The message exposes ONLY the
// status code — the raw response body is on `.detail` for opt-in inspection,
// never in the message (so host frameworks can't echo internal stack
// traces / auth payloads / PII to end users).
class ShieldConsoleError extends Error {
  statusCode: number;
  detail: string;                          // raw body — opt-in only
}

// Thrown when the Console is unreachable after the single retry. Names the
// console URL; carries no response body. Also thrown when a configured
// credentialProvider rejects (fail closed — no request was sent); in that
// case the provider's error is preserved on `.cause`.
class ShieldConnectionError extends Error {
  consoleUrl: string;
}
```

## `ShieldLogEntry`

Returned by the internal audit-log call when logging succeeds.

```typescript
interface ShieldLogEntry {
  id: string;        // audit-trail entry id
  decision: string;  // recorded decision
  timestamp: string; // ISO 8601 timestamp
}
```

## Request IDs

The SDK correlates each `check()`/`log()` pair with a per-request id so the two
server-side log lines can be joined. `wrap()` generates one automatically, but
the id type and constructor are exported for callers who want to supply or
propagate their own.

```typescript
import { newRequestId, type RequestId } from '@g8r-security/agent-shield-sdk';

const requestId: RequestId = newRequestId();
const result = await shield.check(prompt, { requestId });
```

- `newRequestId(): RequestId` — mints a fresh id (prefers `crypto.randomUUID()`).
- `RequestId` — branded string type for a per-request correlation id.

## Source Layout

```
js/
├── src/
│   ├── index.ts       # AgentShield class, ShieldBlockedError, PolicyCheckResult, ShieldLogEntry
│   ├── redaction.ts   # redactSensitiveData() — local-first masking layer
│   ├── context.ts     # ambient governance context (session + parent-agent chain) via AsyncLocalStorage
│   ├── ids.ts         # tenantId(), newRequestId(), newSessionId() + TenantId / RequestId types
│   └── logger.ts      # structured logger used internally
├── __tests__/
│   ├── sdk.test.ts           # SDK client behavior + redaction integration
│   ├── lineage.test.ts       # sub-agent lineage propagation + async isolation
│   ├── credentials.test.ts   # credentialProvider auth (per-request resolution, fail-closed)
│   ├── registration.test.ts  # trust-on-first-use pending-registration detection
│   └── redaction.test.ts     # all patterns + entropy detection
├── jest.config.js
├── package.json
└── tsconfig.json
```

## Development

```bash
cd js

npm run build          # tsup — build dist/ (ESM + CJS + types)
npm test               # Jest
npm run test:coverage  # With coverage
npm run typecheck      # tsc --noEmit
```

## Coverage

Thresholds in `jest.config.js`: 85% statements, 75% branches, 85% functions, 85% lines.

## Compliance

| Regulation | Controls covered |
|---|---|
| GDPR | Art. 32 — appropriate technical measures for data protection |
| PCI-DSS v4.0 | 3.4 — cryptographic key protection |
