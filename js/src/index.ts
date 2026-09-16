/**
 * G8R Agent Shield SDK
 *
 * Lightweight TypeScript client that wraps LLM calls with policy enforcement.
 * Automatically intercepts prompts, applies best-effort local-first redaction,
 * checks them against the G8R policy engine, and logs all activity to the
 * Agent Shield Console.
 *
 * Usage:
 *   import { AgentShield, tenantId } from '@g8r-security/agent-shield-sdk';
 *
 *   const shield = new AgentShield({
 *     // consoleUrl / apiKey can be omitted and resolved from the
 *     // G8R_CONSOLE_URL / G8R_API_KEY environment variables instead.
 *     consoleUrl: 'https://shield.yourcompany.com',
 *     apiKey: 'sk-shield-...',
 *     // — or, for short-lived OIDC workload-identity JWTs, a provider that is
 *     // awaited fresh on every request (mutually exclusive with apiKey):
 *     // credentialProvider: () => mintWorkloadJwt(),
 *     tenantId: tenantId('acme-corp'),
 *     department: 'Finance',   // optional — defaults to 'General'
 *     userId: 'usr_FIN_042',   // optional — defaults to 'unknown'
 *     aiModel: 'GPT-4o',       // optional — defaults to 'unknown'
 *   });
 *
 *   // Wrap any LLM call — the factory function is only invoked if the policy allows it
 *   const result = await shield.wrap(
 *     () => openai.chat.completions.create({
 *       model: 'gpt-4o',
 *       messages: [{ role: 'user', content: 'Summarize Q1 earnings' }],
 *     }),
 *     'Summarize Q1 earnings'
 *   );
 */

import { match } from 'ts-pattern';
import { newRequestId, newSessionId, type RequestId, type TenantId } from './ids';
import { getGovernanceContext, runWithGovernanceContext } from './context';
import { log } from './logger';
import { redactSensitiveData } from './redaction';
import {
  ReceiptVerifier, ReceiptVerificationError, buildReceiptRequest, assertReceiptTransport,
  type ReceiptVerificationConfig, type ReceiptRequest,
} from './receipts';
export {
  ReceiptVerifier, ReceiptVerificationError, buildReceiptRequest, receiptRequestHash,
  canonicalJson, RECEIPT_ALGORITHM, RECEIPT_TYPE,
} from './receipts';
export type {
  ReceiptVerificationConfig, ReceiptRequest, ReceiptRequestInput,
  ReceiptDecision, ReceiptClaims, VerifiedReceipt,
} from './receipts';

// ── Public API re-exports ────────────────────────────────────────────────────
// Consumers need `tenantId()` to construct the branded TenantId required by
// ShieldConfig, and `redactSensitiveData` is documented as a public helper.
// `newSessionId()` mints the ambient-session id used for sub-agent lineage.
export { tenantId, newRequestId, newSessionId } from './ids';
export type { TenantId, RequestId } from './ids';
export { redactSensitiveData } from './redaction';
export type { RedactionResult } from './redaction';

/**
 * SDK version. Kept in lockstep with `package.json` and with the Python SDK's
 * `__version__` so "are these two in parity?" is answerable by a version-equality
 * check in CI. Bump both together.
 */
export const VERSION = '0.6.0';

/**
 * User-Agent identifying this SDK (language + version) to the Console on every
 * request. Lets the server distinguish python-vs-ts callers without polluting
 * customer-controlled fields like `agentId`. Mirrors the Python SDK's
 * `g8r-shield-python/{version}`.
 */
const SDK_USER_AGENT = `g8r-shield-typescript/${VERSION}`;

/**
 * Single-retry backoff (ms) for transient network errors on /check. Kept short
 * so it adds no user-visible latency on the happy path or on hard failures.
 */
const RETRY_BACKOFF_MS = 500;

/** Environment variable fallbacks for deployment config (12-factor). */
const ENV_CONSOLE_URL = 'G8R_CONSOLE_URL';
const ENV_API_KEY = 'G8R_API_KEY';
const ENV_PEP_URL = 'G8R_PEP_URL';
const PEP_DECIDE_PATH = '/decide';

const OUTCOME_TO_DECISION: Record<string, PolicyCheckResult['decision']> = {
  ALLOW: 'allowed',
  DENY: 'blocked',
  REQUIRE_APPROVAL: 'escalated',
  ERROR: 'blocked',
};

function rejectLoopback(url: string, field: string): string {
  const cleaned = url.trim().replace(/\/+$/, '');
  if (!cleaned) {
    throw new Error(`${field} is required`);
  }
  const host = cleaned.toLowerCase();
  if (
    host.includes('://localhost') ||
    host.includes('://127.0.0.1') ||
    host.includes('://[::1]') ||
    host.startsWith('localhost') ||
    host.startsWith('127.0.0.1')
  ) {
    throw new Error(
      `${field} must not target localhost. An SDK that ships prompts must fail closed rather than silently talk to 127.0.0.1.`
    );
  }
  return cleaned;
}

// ── Field defaults ────────────────────────────────────────────────────────────
// Defaulted-not-required fields. Attribution labels that degrade an audit trail
// when missing but never open a security hole — kept optional for adoption
// ergonomics, matching the Python SDK's construction-time defaults.
const DEFAULT_DEPARTMENT = 'General';
const DEFAULT_USER_ID = 'unknown';
const DEFAULT_AI_MODEL = 'unknown';
const DEFAULT_AGENT_ID = 'sdk-client';
const DEFAULT_TIMEOUT_SECONDS = 10.0;

export interface ShieldConfig {
  /** When set, both check() and wrap() require a valid signed receipt.
   * There is no unsigned fallback. Approval-required decisions never execute.
   * Leaving this unset keeps the existing unsigned behavior.
   */
  receiptVerification?: ReceiptVerificationConfig;
  /**
   * Base URL of the PEP gateway. Required: this field OR `G8R_PEP_URL`.
   * No consoleUrl fallback. Loopback is refused. wrap() hops POST {pepUrl}/decide.
   */
  pepUrl?: string;
  /**
   * Base URL of the deployed G8R Console (audit /log and the check() gap).
   * Optional at the type level, but effectively required: resolved from this
   * field OR the `G8R_CONSOLE_URL` env var. If neither is present the
   * constructor throws. Never defaults to localhost. A trailing slash is stripped.
   */
  consoleUrl?: string;
  /**
   * Static bearer credential for /api/sdk/v1/check and /log — the deployment
   * shared secret the customer configured server-side. Optional at the type
   * level, but effectively required unless `credentialProvider` is set:
   * resolved from this field OR the `G8R_API_KEY` env var. If neither yields
   * a non-empty value (and no provider is configured) the constructor throws.
   * Never included in toString()/logs. Mutually exclusive with
   * `credentialProvider`.
   */
  apiKey?: string;
  /**
   * Callback returning (or resolving to) the bearer credential for ONE
   * outbound request. Awaited fresh on EVERY /check and /log call, so
   * short-lived credentials — e.g. OIDC workload-identity JWTs (AWS workload
   * identity and friends) — never go stale inside a long-lived shield
   * instance. The Console accepts either the deployment shared secret or a
   * verified OIDC JWT in the same `Authorization: Bearer` header, so a static
   * apiKey and a provider speak the identical wire contract. With a verified
   * JWT the server trusts the JWT's tenant claim over the body's tenantId — a
   * mismatch is HTTP 403 (a bad/missing credential is 401).
   *
   * Mutually exclusive with `apiKey` — the constructor throws if both are
   * passed, and the `G8R_API_KEY` env fallback is not consulted when a
   * provider is configured. A provider rejection fails CLOSED: it surfaces as
   * ShieldConnectionError and wrap() never invokes the LLM factory. The
   * returned credential is used only for the Authorization header and is
   * never logged.
   */
  credentialProvider?: () => string | Promise<string>;
  /** Tenant this SDK instance operates on behalf of. The one hard-required field. */
  tenantId: TenantId;
  /** Optional: functional department for governance attribution (defaults to "General"). */
  department?: string;
  /** Optional: identifier of the end-user initiating the action (defaults to "unknown"). */
  userId?: string;
  /** Optional: model identifier being called (defaults to "unknown"). */
  aiModel?: string;
  /** Optional: agent identifier (defaults to "sdk-client"). */
  agentId?: string;
  /**
   * Optional: per-instance default session id — the stable id for one logical
   * agent run, propagated across nested and multi-turn calls (see sub-agent
   * lineage). When set, every wrap()/check() from this instance reports this
   * session UNLESS an ambient session (from a surrounding {@link
   * AgentShield.run} or a parent wrap()) overrides it. When unset, wrap() mints
   * a fresh session per top-level call and a standalone check() with no ambient
   * session sends none — so existing, non-nested usage is unchanged. Sent as
   * the additive wire field `sessionId`; advisory / self-asserted trust.
   */
  sessionId?: string;
  /** Optional: employee display name for the audit trail (falls back to userId at /log time). */
  employeeName?: string;
  /** Optional: HTTP request timeout in seconds applied to both /check and /log (defaults to 10). */
  timeout?: number;
  /**
   * Optional: when true, wrap() throws ShieldBlockedError on an 'escalated'
   * decision instead of proceeding with a warning (defaults to false — escalated
   * actions proceed pending out-of-band human review).
   */
  blockOnEscalated?: boolean;
}

export interface PolicyCheckResult {
  /** Verified compact JWS. The current /log endpoint does not store it. */
  decisionReceipt?: string;
  decision: 'allowed' | 'blocked' | 'escalated';
  reason: string;
  violatedRule: string | null;
  requiresApproval: boolean;
  /**
   * True when this call was blocked because the agent's trust-on-first-use
   * registration is still pending admin approval in the Console's Approvals
   * queue — not because a policy rule fired.
   *
   * Derived CLIENT-SIDE from `decision === 'blocked' && requiresApproval ===
   * true`; this is NOT a wire field the Console sends. On a v2 Console that
   * conjunction occurs only for pending registrations, and only when the
   * server runs in `block` pending-agent mode:
   *
   *  - `flag` mode (server default): calls from a pending agent evaluate
   *    normally under policy while admins are alerted out-of-band — the SDK
   *    sees ordinary decisions and this flag never appears.
   *  - `block` mode: calls return `blocked` + `requiresApproval: true` until
   *    an admin approves the agent, and this flag is set.
   *
   * An admin-DENIED agent is `blocked` with `requiresApproval: false` in both
   * modes, so this flag stays unset for it. Undefined (never `false`) when
   * the conjunction doesn't hold, matching the present-only-when-meaningful
   * style of `sessionRevoked`/`redactedTokens`. Reason strings are for humans
   * and are never parsed to derive this.
   */
  isPendingRegistration?: boolean;
  /**
   * Set to true when a kill-switch policy fires. Consumers should tear down
   * the agent session in response.
   */
  sessionRevoked?: boolean;
  complianceMappings: Array<{
    regulation: string;
    controlId: string;
    controlName: string;
    description: string;
  }>;
  /**
   * Tokens that were redacted from the prompt before it reached the gateway.
   * Undefined when no tokens were redacted (clean prompt).
   * Populated by the local-first redaction layer.
   */
  redactedTokens?: string[];
}

export interface ShieldLogEntry {
  id: string;
  decision: string;
  timestamp: string;
}

/** Options for {@link AgentShield.check}. */
export interface CheckOptions {
  /**
   * Explicit request id to correlate /check and /log. When omitted, a fresh id
   * is minted per call. wrap() passes its own id so the whole invocation shares
   * one correlation id end-to-end.
   */
  requestId?: RequestId;
  /**
   * Whether to also record this evaluation in the audit trail. Default true, so
   * standalone check() calls are self-auditing. Pass false if you will follow up
   * with wrap() for the same prompt — wrap() logs internally and a second log
   * here would duplicate the audit entry.
   */
  log?: boolean;
}

/**
 * Ambient governance lineage resolved for a single outbound request: the
 * session this call belongs to and the ancestor agent chain that led here
 * (root-first). Both are advisory, self-asserted metadata for the governance
 * plane — they are SENT on /check and /log but never influence the local
 * decision path.
 */
interface RequestLineage {
  sessionId?: string;
  parentAgents: string[];
}

export class AgentShield {
  private readonly pepUrl: string;
  private readonly consoleUrl: string;
  private readonly credential: () => string | Promise<string>;
  private readonly tenantId: TenantId;
  private readonly department: string;
  private readonly userId: string;
  private readonly aiModel: string;
  private readonly agentId: string;
  /** Per-instance default session id (see ShieldConfig.sessionId). Undefined = none configured. */
  private readonly sessionId?: string;
  private readonly employeeName?: string;
  private readonly timeoutMs: number;
  private readonly blockOnEscalated: boolean;
  private readonly receiptVerifier?: ReceiptVerifier;

  constructor(config: ShieldConfig) {
    if (!config.tenantId) {
      throw new Error('tenantId is required');
    }

    // Resolve deployment config from arg-or-env. Fail closed if unresolvable —
    // never fall back to localhost, which would silently exfiltrate customer
    // prompts + API keys to whatever is bound on 127.0.0.1 in the runtime.
    const resolvedUrl = config.consoleUrl || readEnv(ENV_CONSOLE_URL);
    if (!resolvedUrl) {
      throw new Error(
        `consoleUrl is required. Pass consoleUrl or set the ${ENV_CONSOLE_URL} env var. ` +
          'An SDK that ships customer prompts and API keys must never default to localhost.'
      );
    }
    const resolvedPep = config.pepUrl || readEnv(ENV_PEP_URL);
    if (!resolvedPep) {
      throw new Error(
        `pepUrl is required. Pass pepUrl or set the ${ENV_PEP_URL} env var. ` +
          'wrap() hops the PEP; there is no consoleUrl fallback and no localhost default.'
      );
    }

    // A static key and a per-request provider are two mutually exclusive
    // answers to "where does the bearer credential come from". Refuse the
    // ambiguity outright — silently preferring one usually hides a config
    // merge bug upstream.
    if (config.apiKey && config.credentialProvider) {
      throw new Error(
        'apiKey and credentialProvider are mutually exclusive. Pass exactly one credential source.'
      );
    }

    // Resolve the credential SOURCE — never the credential itself: a provider
    // is awaited per request (see resolveCredential()), not at construction.
    // A static key is normalized into the same closure shape as a provider so
    // /check and /log share one resolution path. When a provider is
    // configured the G8R_API_KEY env fallback is deliberately not consulted —
    // an explicit provider is an explicit choice of credential source.
    let credential: () => string | Promise<string>;
    if (config.credentialProvider) {
      credential = config.credentialProvider;
    } else {
      const resolvedKey = config.apiKey || readEnv(ENV_API_KEY);
      if (!resolvedKey) {
        throw new Error(
          `apiKey is required. Pass apiKey, set the ${ENV_API_KEY} env var, or pass a credentialProvider.`
        );
      }
      credential = () => resolvedKey;
    }

    // Store all fields (with defaults applied) as write-once instance state.
    // The instance holds no mutable state and is safe to share across loops.
    this.consoleUrl = resolvedUrl.replace(/\/+$/, ''); // strip trailing slash(es)
    this.pepUrl = rejectLoopback(resolvedPep, 'pepUrl');
    this.credential = credential;
    this.tenantId = config.tenantId;
    this.department = config.department ?? DEFAULT_DEPARTMENT;
    this.userId = config.userId ?? DEFAULT_USER_ID;
    this.aiModel = config.aiModel ?? DEFAULT_AI_MODEL;
    // Normalize agentId to a construction-time value so BOTH /check and /log
    // always send the same agentId (no inline '?? sdk-client' per call site).
    this.agentId = config.agentId ?? DEFAULT_AGENT_ID;
    // Optional per-instance default session. Left undefined when not configured
    // so a lone check() stays on the pre-lineage wire (no sessionId field).
    this.sessionId = config.sessionId;
    this.employeeName = config.employeeName;
    this.timeoutMs = (config.timeout ?? DEFAULT_TIMEOUT_SECONDS) * 1000;
    this.receiptVerifier = config.receiptVerification === undefined
      ? undefined : new ReceiptVerifier(config.receiptVerification);
    if (this.receiptVerifier) {
      assertReceiptTransport(this.pepUrl);
      assertReceiptTransport(this.consoleUrl);
    }
    // Requiring approval is not permission to run the callback.
    this.blockOnEscalated = this.receiptVerifier !== undefined || (config.blockOnEscalated ?? false);
  }

  /**
   * Custom toString() that never exposes the api_key. tenantId is not secret;
   * include it for operational clarity.
   */
  toString(): string {
    return (
      `AgentShield(pepUrl=${JSON.stringify(this.pepUrl)}, ` +
      `consoleUrl=${JSON.stringify(this.consoleUrl)}, ` +
      `tenantId=${JSON.stringify(this.tenantId)}, ` +
      `agentId=${JSON.stringify(this.agentId)}, department=${JSON.stringify(this.department)})`
    );
  }

  /**
   * Check a prompt against the policy engine before sending to the LLM.
   *
   * Applies best-effort local-first redaction before sending to the gateway, so
   * recognized signing keys, custodial IDs, common PII, and high-entropy secrets
   * are stripped before the prompt leaves the process. Redaction is one layer of
   * defense, not a guarantee that every secret is caught (see redaction.ts).
   *
   * Returns the policy decision without executing the LLM call. NEVER raises on a
   * blocked/escalated decision — it returns the decision for the caller to act on.
   *
   * By default this ALSO logs the evaluation to /log with the same requestId, so
   * standalone check() calls are self-auditing. Callers who will immediately call
   * wrap() for the same prompt should pass `{ log: false }` to avoid a duplicate
   * audit entry.
   */
  async check(prompt: string, opts: CheckOptions = {}): Promise<PolicyCheckResult> {
    // `requestId` is minted per-call by default, but wrap() passes its own value
    // so /check and /log share a single correlation id end-to-end.
    const requestId = opts.requestId ?? newRequestId();
    const shouldLog = opts.log ?? true;

    // Read the ambient governance lineage (session + ancestor chain) and report
    // it on /check — and, when self-auditing, on /log with the same requestId. A
    // standalone check() only REPORTS the lineage it already runs under; it
    // never opens a nested scope and never mints a session (see ambientLineage).
    const lineage = this.ambientLineage();

    const result = await this.evaluate(prompt, requestId, lineage);

    if (shouldLog) {
      await this.log(prompt, result, requestId, lineage);
    }

    return result;
  }

  /**
   * Wrap an LLM call with policy enforcement.
   *
   * The `llmCallFactory` is a function that creates the LLM promise. It is only
   * invoked if the policy engine allows the action, preventing the LLM call from
   * executing before the policy check completes.
   *
   * Governance lineage (session + parent-agent chain) is propagated
   * automatically: a top-level wrap() mints a fresh session and an empty
   * ancestor chain; the factory then runs inside an ambient scope, so any
   * wrapped call it makes inherits the same session and an ancestor chain that
   * now ends with this agent (root-first). Nested hops therefore self-assemble
   * their lineage with no manual instrumentation. Lineage is advisory metadata
   * for the governance plane and NEVER changes the local decision.
   *
   * @param llmCallFactory - A function that returns the LLM call promise
   * @param prompt - The prompt text to evaluate against the policy engine
   * @returns The result of the LLM call if allowed
   * @throws ShieldBlockedError if the policy engine blocks the action (or escalates
   *   it while blockOnEscalated is true)
   *
   * @example
   *   const result = await shield.wrap(
   *     () => openai.chat.completions.create({
   *       model: 'gpt-4o',
   *       messages: [{ role: 'user', content: prompt }],
   *     }),
   *     prompt
   *   );
   */
  async wrap<T>(llmCallFactory: () => Promise<T>, prompt: string): Promise<T> {
    // Mint ONE request_id for the whole invocation and thread it through both
    // /check and /log so the two server-side log lines can be joined end-to-end.
    const requestId = newRequestId();

    // Resolve THIS hop's governance lineage from the ambient context. A
    // top-level call has no ambient context, so it MINTS a fresh session (or
    // adopts the per-instance configured session) and starts with an empty
    // ancestor chain; a nested call inherits its parent's session and ancestor
    // chain verbatim. These values are what we SEND — the ancestor chain does
    // not yet include this agent (that extension is applied around the factory
    // in Step 4). Lineage never changes the decision.
    const ctx = getGovernanceContext();
    const sessionId = ctx?.sessionId ?? this.sessionId ?? newSessionId();
    const parentAgents = ctx?.agentChain ?? [];
    const lineage: RequestLineage = { sessionId, parentAgents };

    // Step 1: Check the prompt against the policy engine (includes redaction),
    // reporting the resolved lineage. We evaluate directly (rather than via the
    // public check()) so /check and /log share this exact lineage — including a
    // freshly minted session that is not yet in the ambient store.
    const policyResult = await this.evaluatePep(prompt, requestId, lineage);

    // Step 2: Log the attempt regardless of decision, BEFORE enforcement, so even
    // blocked attempts land in the audit trail. log() redacts before transmitting.
    await this.log(prompt, policyResult, requestId, lineage);

    // Step 3: Enforce the decision. Exhaustive match — adding a fourth decision
    // value will fail TypeScript compilation here until handled (fail-closed).
    match(policyResult.decision)
      .with('blocked', () => {
        if (policyResult.sessionRevoked) {
          log.warn('session_revoked', {
            tenant_id: this.tenantId,
            agent_id: this.agentId,
            reason: policyResult.reason,
          });
        }
        throw new ShieldBlockedError(
          policyResult.decision,
          policyResult.reason,
          policyResult.violatedRule,
          policyResult.complianceMappings,
          policyResult.sessionRevoked ?? false,
          policyResult.isPendingRegistration ?? false
        );
      })
      .with('escalated', () => {
        if (this.blockOnEscalated) {
          // Strict mode — treat escalated like blocked. Caller opted in at
          // construction time.
          throw new ShieldBlockedError(
            policyResult.decision,
            policyResult.reason,
            policyResult.violatedRule,
            policyResult.complianceMappings,
            policyResult.sessionRevoked ?? false,
            policyResult.isPendingRegistration ?? false
          );
        }
        log.warn('action_escalated', {
          tenant_id: this.tenantId,
          agent_id: this.agentId,
          reason: policyResult.reason,
        });
      })
      .with('allowed', () => {
        /* fall through to invoke the LLM */
      })
      .exhaustive();

    // Step 4: Only now invoke the LLM call — after the policy check passed —
    // and do it INSIDE the extended ambient scope so any wrapped call the
    // factory makes (directly, or via an awaited continuation) inherits this
    // session and an ancestor chain that now ends with this agent (root-first).
    // AsyncLocalStorage auto-restores the prior context when run() returns,
    // including if the factory throws. Escalated-but-proceeding calls fall
    // through here too, so their nested calls are governed with chain awareness
    // just like allowed ones.
    return runWithGovernanceContext(
      { sessionId, agentChain: [...parentAgents, this.agentId] },
      () => llmCallFactory()
    );
  }

  /**
   * Establish an ambient governance session for the duration of `fn`, so every
   * wrap()/check() call made inside it — across awaits and nested agents —
   * shares one sessionId with no manual threading. Multi-turn conversations and
   * fan-out tool calls that belong to ONE logical run should live inside a
   * single run() so the governance plane can stitch them together.
   *
   * The session is resolved as: an explicit `opts.sessionId` → the ambient
   * session already in scope → this instance's configured sessionId → a freshly
   * minted one. Any ancestor agent chain already in scope is PRESERVED: run()
   * groups calls under a session, it does not itself add an agent hop — wrap()
   * is what extends the chain. The prior context is restored when `fn` returns
   * or throws.
   *
   * Returns whatever `fn` returns (await it if `fn` is async). Lineage is
   * advisory / self-asserted and never alters a decision.
   *
   * @example
   *   await shield.run(async () => {
   *     await shield.wrap(() => turn1(), prompt1);
   *     await shield.wrap(() => turn2(), prompt2); // same sessionId as turn1
   *   });
   */
  run<T>(fn: () => T, opts: { sessionId?: string } = {}): T {
    const ctx = getGovernanceContext();
    const sessionId = opts.sessionId ?? ctx?.sessionId ?? this.sessionId ?? newSessionId();
    const agentChain = ctx?.agentChain ?? [];
    return runWithGovernanceContext({ sessionId, agentChain }, fn);
  }

  // ── Internal ────────────────────────────────────────────────────────────────

  /**
   * Resolve the lineage for a standalone check()/log(): the AMBIENT session +
   * ancestor chain, falling back to this instance's configured sessionId. Unlike
   * wrap(), a standalone check NEVER mints a session — a lone call with no
   * ambient context and no configured session carries neither field, so the wire
   * stays byte-for-byte the pre-lineage contract (full backward compatibility).
   */
  private ambientLineage(): RequestLineage {
    const ctx = getGovernanceContext();
    return {
      sessionId: ctx?.sessionId ?? this.sessionId,
      parentAgents: ctx?.agentChain ?? [],
    };
  }

  /**
   * The two additive lineage wire fields, included ONLY when meaningful —
   * matching the present-only-when-meaningful style of sessionRevoked /
   * redactedTokens / isPendingRegistration. A top-level call with an empty chain
   * omits `parentAgents`; a call with no session omits `sessionId`. Absent
   * fields keep pre-lineage consumers on the exact old wire contract.
   */
  private lineageWireFields(lineage: RequestLineage): Record<string, unknown> {
    return {
      ...(lineage.sessionId ? { sessionId: lineage.sessionId } : {}),
      ...(lineage.parentAgents.length > 0 ? { parentAgents: lineage.parentAgents } : {}),
    };
  }

  /** Create a new challenge for this check. Retries keep the same one. */
  private prepareReceiptRequest(
    endpoint: ReceiptRequest['endpoint'],
    headers: Record<string, string>,
    body: Record<string, unknown>,
    requestId: RequestId
  ): ReceiptRequest | undefined {
    if (!this.receiptVerifier) return undefined;
    const request = buildReceiptRequest({
      endpoint, tenantId: this.tenantId, agentId: this.agentId,
      requestId, headers, body,
    });
    headers['X-G8R-Receipt-Nonce'] = request.nonce;
    headers['X-G8R-Receipt-Version'] = '1';
    return request;
  }

  /** Use the signed decision, not any unsigned fields beside it. */
  private verifyReceipt(
    data: unknown, request: ReceiptRequest, tokensReplaced: string[]
  ): PolicyCheckResult {
    if (!this.receiptVerifier) throw new ReceiptVerificationError('Receipt verifier is required');
    const verified = this.receiptVerifier.verifyResponse(data, request);
    const decision = verified.decision;
    return {
      ...decision,
      complianceMappings: decision.complianceMappings.map(mapping => ({ ...mapping })),
      decisionReceipt: verified.token,
      ...(decision.decision === 'blocked' && decision.requiresApproval
        ? { isPendingRegistration: true } : {}),
      ...(tokensReplaced.length > 0 ? { redactedTokens: tokensReplaced } : {}),
    };
  }

  /**
   * POST the redacted prompt + governance fields to /api/sdk/v1/check and parse
   * the decision. Retries exactly once on a transient connection/timeout error
   * after a short backoff, then raises ShieldConnectionError. Non-2xx responses
   * raise ShieldConsoleError, whose message never carries the raw body.
   */
  private async evaluate(
    prompt: string,
    requestId: RequestId,
    lineage: RequestLineage
  ): Promise<PolicyCheckResult> {
    // Step 1: Local-first redaction — strip recognized secrets and PII before
    // the prompt reaches the remote gateway.
    const { redacted, tokensReplaced } = redactSensitiveData(prompt);

    const scopedLog = log.child({
      tenant_id: this.tenantId,
      request_id: requestId,
    });

    // Resolve the credential ONCE per request, before the retry loop — the
    // retry below is for transient network failures, not credential failures,
    // and a JWT valid at request start is still valid one backoff later.
    const credential = await this.resolveCredential();

    const url = `${this.consoleUrl}/api/sdk/v1/check`;
    const body = JSON.stringify({
      input: redacted, // send the redacted version — never the raw prompt
      tenantId: this.tenantId,
      requestId,
      department: this.department,
      userId: this.userId,
      aiModel: this.aiModel,
      agentId: this.agentId, // construction-time value — same on /check and /log
      // Additive lineage fields (sessionId / parentAgents), present only when
      // meaningful — omitted entirely for a plain top-level, un-nested call.
      ...this.lineageWireFields(lineage),
    });

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${credential}`,
      'User-Agent': SDK_USER_AGENT,
    };
    const receiptRequest = this.prepareReceiptRequest(
      '/api/sdk/v1/check', headers, JSON.parse(body), requestId
    );

    // Single retry on transient network failures (connection refused / timeout).
    // Hard failures (non-2xx HTTP responses) are surfaced immediately — retrying
    // those just doubles user-visible latency.
    let res: Response | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        res = await fetch(url, {
          method: 'POST',
          headers,
          body,
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        break;
      } catch (err) {
        // fetch rejects only on network-level failures (DNS, connection refused,
        // abort/timeout) — never on a non-2xx status. Treat all of these as
        // transient and retry once.
        if (attempt === 0) {
          await delay(RETRY_BACKOFF_MS);
          continue;
        }
        scopedLog.error('Console unreachable', { url: this.consoleUrl });
        throw new ShieldConnectionError(this.consoleUrl, err);
      }
    }

    // Unreachable in practice (loop either breaks with `res` set or throws), but
    // keeps the type checker honest.
    if (!res) {
      throw new ShieldConnectionError(this.consoleUrl);
    }

    if (!res.ok) {
      scopedLog.error('Shield policy check failed', { status: res.status });
      // Preserve the raw body on `.detail` for opt-in inspection, but keep it
      // out of the exception message (see ShieldConsoleError rationale).
      const detail = await safeReadText(res);
      throw new ShieldConsoleError(res.status, detail);
    }

    const data = await res.json();
    if (receiptRequest) return this.verifyReceipt(data, receiptRequest, tokensReplaced);
    return {
      decision: data.decision,
      reason: data.reason,
      violatedRule: data.violatedRule ?? null,
      requiresApproval: data.requiresApproval ?? false,
      // Derived CLIENT-SIDE — NOT a wire field. On a v2 Console the
      // conjunction decision=='blocked' && requiresApproval==true occurs ONLY
      // while an agent's trust-on-first-use registration is pending admin
      // approval (server pending-agent mode 'block'). Reason strings are for
      // humans and are never parsed for this.
      ...(data.decision === 'blocked' && data.requiresApproval === true
        ? { isPendingRegistration: true }
        : {}),
      ...(data.sessionRevoked !== undefined ? { sessionRevoked: data.sessionRevoked } : {}),
      complianceMappings: data.complianceMappings ?? [],
      ...(tokensReplaced.length > 0 ? { redactedTokens: tokensReplaced } : {}),
    };
  }

  /**
   * wrap() one-hop: POST PEP /decide. Never Console /check.
   */
  private async evaluatePep(
    prompt: string,
    requestId: RequestId,
    lineage: RequestLineage
  ): Promise<PolicyCheckResult> {
    const { redacted, tokensReplaced } = redactSensitiveData(prompt);
    const scopedLog = log.child({ tenant_id: this.tenantId, request_id: requestId });
    const credential = await this.resolveCredential();
    const url = `${this.pepUrl}${PEP_DECIDE_PATH}`;
    const lineageFields = this.lineageWireFields(lineage);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${credential}`,
      'User-Agent': SDK_USER_AGENT,
      'X-GF-Tenant-ID': this.tenantId,
      'X-GF-Agent-ID': this.agentId,
      'x-gf-department': this.department,
    };
    const parents = lineage.parentAgents;
    if (parents.length > 0) {
      headers['x-gf-agent-chain'] = [...parents].reverse().join(',');
      headers['x-gf-parent-agent-id'] = parents[parents.length - 1];
    }
    if (lineage.sessionId) {
      headers['x-gf-session-id'] = lineage.sessionId;
    }
    const body = JSON.stringify({
      downstream_url: 'sdk://wrap',
      method: 'POST',
      action_hint: 'llm_prompt',
      target_hint: 'llm_prompt',
      body: { prompt: redacted },
      correlation_id: requestId,
      action_type: 'tool_call',
      ...lineageFields,
    });

    const receiptRequest = this.prepareReceiptRequest(
      '/decide', headers, JSON.parse(body), requestId
    );
    let res: Response | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        res = await fetch(url, {
          method: 'POST',
          headers,
          body,
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        break;
      } catch (err) {
        if (attempt === 0) {
          await delay(RETRY_BACKOFF_MS);
          continue;
        }
        scopedLog.error('PEP unreachable', { url: this.pepUrl });
        throw new ShieldConnectionError(this.pepUrl, err);
      }
    }
    if (!res) {
      throw new ShieldConnectionError(this.pepUrl);
    }
    if (!res.ok) {
      scopedLog.error('PEP decide failed', { status: res.status });
      const detail = await safeReadText(res);
      throw new ShieldConsoleError(res.status, detail);
    }
    const data = await res.json();
    if (receiptRequest) return this.verifyReceipt(data, receiptRequest, tokensReplaced);
    const raw = data.decision;
    if (raw && typeof raw === 'object') {
      const outcome = String(raw.outcome || '').toUpperCase();
      const decision = OUTCOME_TO_DECISION[outcome] ?? 'blocked';
      const reasonCode = String(raw.reason_code || '');
      const rules: string[] = Array.isArray(raw.matched_rule_ids) ? raw.matched_rule_ids : [];
      return {
        decision,
        reason: String(raw.explanation || reasonCode || ''),
        violatedRule: rules[0] ?? null,
        requiresApproval: decision === 'escalated',
        ...(reasonCode.toUpperCase().includes('KILL') ? { sessionRevoked: true } : {}),
        complianceMappings: [],
        ...(tokensReplaced.length > 0 ? { redactedTokens: tokensReplaced } : {}),
      };
    }
    return {
      decision: data.decision,
      reason: data.reason,
      violatedRule: data.violatedRule ?? null,
      requiresApproval: data.requiresApproval ?? false,
      ...(data.decision === 'blocked' && data.requiresApproval === true
        ? { isPendingRegistration: true }
        : {}),
      ...(data.sessionRevoked !== undefined ? { sessionRevoked: data.sessionRevoked } : {}),
      complianceMappings: data.complianceMappings ?? [],
      ...(tokensReplaced.length > 0 ? { redactedTokens: tokensReplaced } : {}),
    };
  }

  /**
   * Log an interaction to /api/sdk/v1/log.
   *
   * Redacts the prompt before transmitting: the audit trail must not store or
   * carry raw secrets/PII, and this is an egress point just like /check.
   *
   * Failures are logged and swallowed (returns null) — a logging outage must
   * NEVER break the user's LLM call or mask the decision path. The single
   * deliberate exception is credential RESOLUTION: a rejecting
   * credentialProvider propagates (fail closed), because it means the SDK can
   * no longer authenticate at all — see resolveCredential().
   */
  private async log(
    input: string,
    result: PolicyCheckResult,
    requestId?: RequestId,
    lineage: RequestLineage = { parentAgents: [] }
  ): Promise<ShieldLogEntry | null> {
    const id = requestId ?? newRequestId();
    const scopedLog = log.child({
      tenant_id: this.tenantId,
      request_id: id,
    });

    // Redact at the egress boundary — never send the raw prompt to /log.
    const { redacted } = redactSensitiveData(input);

    try {
      // Resolve the credential INSIDE the swallow-all block: a provider
      // rejection on the audit path is a logging failure like any other —
      // an actual 401 from /log would be swallowed below, so a local
      // provider hiccup must not be treated more strictly than a real auth
      // rejection. Fail-closed protection lives on the /check leg, which
      // resolves the credential before any decision is rendered. (Parity:
      // the Python SDK behaves identically.)
      const credential = await this.resolveCredential();

      const res = await fetch(`${this.consoleUrl}/api/sdk/v1/log`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${credential}`,
          'User-Agent': SDK_USER_AGENT,
        },
        body: JSON.stringify({
          input: redacted,
          tenantId: this.tenantId,
          requestId: id,
          userId: this.userId,
          department: this.department,
          aiModel: this.aiModel,
          agentId: this.agentId, // construction-time value
          employeeName: this.employeeName ?? this.userId,
          decision: result.decision,
          reason: result.reason,
          violatedRule: result.violatedRule,
          requiresApproval: result.requiresApproval,
          complianceMappings: result.complianceMappings,
          // Same additive lineage fields as /check, so the audit trail records
          // the session + parent-agent chain this call ran under (present only
          // when meaningful — a plain top-level call carries neither).
          ...this.lineageWireFields(lineage),
        }),
        signal: AbortSignal.timeout(this.timeoutMs),
      });

      if (!res.ok) {
        // Swallow non-2xx — logging must never break the decision path.
        scopedLog.error('Failed to log interaction', { status: res.status });
        return null;
      }

      return (await res.json()) as ShieldLogEntry;
    } catch (err) {
      // Catch broadly — network errors, timeouts, JSON parse failures. Logging
      // must never interrupt the caller's LLM call.
      scopedLog.error('log_failed', { error: String(err) });
      return null;
    }
  }

  /**
   * Resolve the bearer credential for ONE outbound request. Static-key
   * configs resolve instantly; a configured credentialProvider is awaited
   * fresh on every call so short-lived credentials (e.g. OIDC workload JWTs)
   * never go stale inside a long-lived shield instance.
   *
   * A provider rejection fails CLOSED as ShieldConnectionError: no request
   * was sent, which is the same "could not complete the exchange with the
   * console" failure mode as an unreachable console — as opposed to
   * ShieldConsoleError, which asserts the console actually answered. The
   * rejection is never retried here: the provider is customer code, and its
   * retry policy belongs to the provider itself. The resolved credential is
   * handed to the caller for the Authorization header only and is NEVER
   * logged.
   */
  private async resolveCredential(): Promise<string> {
    try {
      return await this.credential();
    } catch (err) {
      // Log the failure (never the credential — there is none to leak, and
      // the provider's error is preserved on `.cause` rather than stringified
      // into a log line that downstream pipelines might surface).
      log.error('credential_provider_failed', { tenant_id: this.tenantId });
      throw new ShieldConnectionError(
        this.consoleUrl,
        err,
        '[G8R Shield] credentialProvider rejected — no request was sent to the console. ' +
          'Provider-based auth fails closed; check the credential source (e.g. the workload-identity token endpoint).'
      );
    }
  }
}

/**
 * Error thrown by wrap() when the policy engine blocks an LLM call (or escalates
 * it while blockOnEscalated is true). This is the one error a normal caller catches.
 */
export class ShieldBlockedError extends Error {
  public readonly decision: string;
  public readonly reason: string;
  public readonly violatedRule: string | null;
  public readonly complianceMappings: PolicyCheckResult['complianceMappings'];
  public readonly sessionRevoked: boolean;
  /**
   * True when the block is the trust-on-first-use pending-registration gate
   * (see {@link PolicyCheckResult.isPendingRegistration}) rather than a policy
   * verdict — the agent is awaiting admin approval in the Console's Approvals
   * queue. Integrators can branch on this to prompt "approve the agent, then
   * retry" instead of treating the block as a policy violation. Always false
   * for admin-DENIED agents (those are `blocked` with `requiresApproval:
   * false`) and for every decision on a server in `flag` pending-agent mode.
   */
  public readonly isPendingRegistration: boolean;

  constructor(
    decision: string,
    reason: string,
    violatedRule: string | null,
    complianceMappings: PolicyCheckResult['complianceMappings'],
    sessionRevoked: boolean = false,
    isPendingRegistration: boolean = false
  ) {
    super(`[G8R Shield BLOCKED] ${reason}`);
    this.name = 'ShieldBlockedError';
    this.decision = decision;
    this.reason = reason;
    this.violatedRule = violatedRule;
    this.complianceMappings = complianceMappings;
    this.sessionRevoked = sessionRevoked;
    this.isPendingRegistration = isPendingRegistration;
    // Restore prototype chain for `instanceof` after transpilation to ES targets
    // that don't preserve it across `extends Error`.
    Object.setPrototypeOf(this, ShieldBlockedError.prototype);
  }
}

/**
 * Error thrown on a non-2xx HTTP response from /check.
 *
 * The message exposes ONLY the safe, status-code-level string
 * `[G8R Shield] Console returned HTTP {status}`. The raw response body is
 * preserved on `.detail` for OPT-IN inspection but never appears in the message,
 * guarding against host frameworks echoing internal stack traces / auth payloads
 * / PII to end users.
 */
export class ShieldConsoleError extends Error {
  public readonly statusCode: number;
  public readonly detail: string;

  constructor(statusCode: number, detail: string = '') {
    super(`[G8R Shield] Console returned HTTP ${statusCode}`);
    this.name = 'ShieldConsoleError';
    this.statusCode = statusCode;
    this.detail = detail;
    Object.setPrototypeOf(this, ShieldConsoleError.prototype);
  }
}

/**
 * Error thrown when the Console is unreachable after the single retry
 * (connection refused / timeout). Names the console URL and that a retry was
 * attempted, but carries no response body. Lets callers distinguish
 * "server said no" (ShieldConsoleError) from "couldn't reach server".
 *
 * Also thrown when a configured credentialProvider rejects: no request can
 * leave the process without a credential, which is the same
 * "could not complete the exchange" failure mode — the `message` override
 * names the provider so operators aren't sent chasing a healthy console, and
 * `.cause` carries the provider's rejection.
 */
export class ShieldConnectionError extends Error {
  public readonly consoleUrl: string;
  public readonly cause?: unknown;

  constructor(consoleUrl: string, cause?: unknown, message?: string) {
    super(
      message ??
        `[G8R Shield] Could not connect to console at ${consoleUrl} after retry. Is the console running?`
    );
    this.name = 'ShieldConnectionError';
    this.consoleUrl = consoleUrl;
    this.cause = cause;
    Object.setPrototypeOf(this, ShieldConnectionError.prototype);
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/** Read an environment variable, tolerating environments without `process`. */
function readEnv(name: string): string | undefined {
  if (typeof process !== 'undefined' && process.env) {
    const v = process.env[name];
    return v && v.length > 0 ? v : undefined;
  }
  return undefined;
}

/** Promise-based delay used for the single-retry backoff. */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Read a response body as text, never throwing (best-effort detail capture). */
async function safeReadText(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return '';
  }
}
