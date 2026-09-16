/**
 * Verify signed policy decisions using the v1 receipt format.
 * Node handles Ed25519; this module handles request binding and receipt checks.
 * The wire format is documented in docs/signed-decision-receipts-v1.md.
 */
import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify, type KeyObject } from 'node:crypto';
import { TextDecoder } from 'node:util';

export const RECEIPT_ALGORITHM = 'Ed25519';
export const RECEIPT_TYPE = 'g8r-decision-receipt+jwt';
const DOMAIN = Buffer.from('g8r:decision-request:v1\0', 'utf8');
const MAX_TOKEN_BYTES = 65_536;
const MAX_JSON_BYTES = 1_048_576;
const MAX_DEPTH = 32;
const MAX_NODES = 100_000;
const KID = /^[A-Za-z0-9._-]{1,128}$(?![\s\S])/;
const B64 = /^[A-Za-z0-9_-]+$/;
const HASH = /^[0-9a-f]{64}$(?![\s\S])/;
const JTI = /^[A-Za-z0-9._-]{16,128}$(?![\s\S])/;
const ENDPOINTS = ['/decide', '/api/sdk/v1/check'] as const;
const REQUEST_FIELDS = ['version', 'method', 'endpoint', 'nonce', 'tenantId', 'agentId', 'requestId', 'governanceHeaders', 'body'];
const CLAIM_FIELDS = ['version', 'iss', 'aud', 'iat', 'exp', 'jti', 'nonce', 'tenantId', 'agentId', 'requestId', 'requestHash', 'decision'];
const DECISION_FIELDS = ['decision', 'reason', 'violatedRule', 'requiresApproval', 'sessionRevoked', 'complianceMappings'];

export class ReceiptVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReceiptVerificationError';
  }
}

function fail(message: string): never {
  throw new ReceiptVerificationError(message);
}

function object(value: unknown, fields?: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail('Expected object');
  // Jest undici JSON is a cross-realm plain object, not this Object.prototype.
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && Object.getPrototypeOf(prototype) !== null) fail('Expected object');
  if (Object.getOwnPropertySymbols(value).length) fail('Symbol keys are not JSON');
  for (const desc of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (!('value' in desc) || !desc.enumerable) fail('JSON accessors and hidden properties are unsupported');
  }
  const obj = value as Record<string, unknown>;
  if (fields && (Object.keys(obj).length !== fields.length || fields.some(k => !Object.prototype.hasOwnProperty.call(obj, k)))) {
    fail('Invalid object fields');
  }
  return obj;
}

function text(value: unknown, maximum = 256, empty = false): string {
  if (typeof value !== 'string') fail('Expected string');
  // Reject incomplete UTF-16 pairs instead of hashing replacement characters.
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) fail('Invalid Unicode');
    } else if (c >= 0xdc00 && c <= 0xdfff) fail('Invalid Unicode');
  }
  const length = Buffer.byteLength(value, 'utf8');
  if (length > maximum || (!empty && length === 0)) fail('Invalid string length');
  return value;
}

function integer(value: unknown, minimum: number, maximum: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) fail('Invalid integer');
  return value;
}

/** RFC 8785-compatible JSON subset with safe integers only (no floats). */
export function canonicalJson(value: unknown): Buffer {
  const active = new Set<object>();
  const chunks: string[] = [];
  let nodes = 0;
  let size = 0;
  const emit = (s: string): void => {
    size += Buffer.byteLength(s, 'utf8');
    if (size > MAX_JSON_BYTES) fail('JSON too large');
    chunks.push(s);
  };
  const visit = (item: unknown, depth: number): void => {
    if (++nodes > MAX_NODES || depth > MAX_DEPTH) fail('JSON structure limit exceeded');
    if (item === null) emit('null');
    else if (typeof item === 'boolean') emit(item ? 'true' : 'false');
    else if (typeof item === 'number') {
      integer(item, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER);
      emit(JSON.stringify(item));
    } else if (typeof item === 'string') {
      text(item, MAX_JSON_BYTES, true);
      emit(JSON.stringify(item));
    } else if (typeof item === 'object') {
      if (active.has(item)) fail('Cyclic JSON');
      active.add(item);
      try {
        if (Array.isArray(item)) {
          if (item.length > MAX_NODES || Object.keys(item).length !== item.length || Object.getOwnPropertySymbols(item).length) fail('Unsupported array properties');
          emit('[');
          for (let i = 0; i < item.length; i++) {
            const descriptor = Object.getOwnPropertyDescriptor(item, String(i));
            if (!descriptor || !('value' in descriptor)) fail('Sparse or accessor array');
            if (i) emit(',');
            visit(descriptor.value, depth + 1);
          }
          emit(']');
        } else {
          const obj = object(item);
          const keys = Object.keys(obj).sort();
          if (keys.length > MAX_NODES) fail('JSON structure limit exceeded'); // UTF-16 code unit order, as JCS requires.
          emit('{');
          keys.forEach((key, index) => {
            if (index) emit(',');
            visit(key, depth + 1);
            emit(':');
            visit(obj[key], depth + 1);
          });
          emit('}');
        }
      } finally { active.delete(item); }
    } else fail('Unsupported JSON value; only safe integers are accepted');
  };
  visit(value, 0);
  return Buffer.from(chunks.join(''), 'utf8');
}

function parseCanonical(data: Buffer): unknown {
  try {
    const decoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data);
    const value: unknown = JSON.parse(decoded);
    // JSON.parse keeps the last duplicate key. Comparing the original bytes
    // with the canonical form catches duplicates and alternate encodings.
    if (!canonicalJson(value).equals(data)) fail('Noncanonical signed JSON');
    return value;
  } catch (error) {
    if (error instanceof ReceiptVerificationError) throw error;
    return fail('Malformed JSON');
  }
}

function decode(segment: unknown, maximum: number): Buffer {
  if (typeof segment !== 'string' || segment.length > maximum || !B64.test(segment)) fail('Malformed base64url');
  const value = Buffer.from(segment, 'base64url');
  if (value.toString('base64url') !== segment) fail('Noncanonical base64url');
  return value;
}

function nonce(value: unknown): string {
  if (typeof value !== 'string' || value.length !== 43 || decode(value, 43).length !== 32) fail('Invalid request nonce');
  return value;
}

export interface ReceiptRequest {
  version: 1;
  method: 'POST';
  endpoint: typeof ENDPOINTS[number];
  nonce: string;
  tenantId: string;
  agentId: string;
  requestId: string;
  governanceHeaders: Record<string, string>;
  body: Record<string, unknown>;
}

export function validateReceiptRequest(request: unknown): ReceiptRequest {
  const obj = object(request, REQUEST_FIELDS);
  if (obj.version !== 1) fail('Unsupported request version');
  if (obj.method !== 'POST' || !ENDPOINTS.includes(obj.endpoint as ReceiptRequest['endpoint'])) fail('Unsupported request endpoint');
  nonce(obj.nonce);
  for (const name of ['tenantId', 'agentId', 'requestId']) text(obj[name]);
  const headers = object(obj.governanceHeaders);
  for (const [name, value] of Object.entries(headers)) {
    if (!/^x-gf-[a-z0-9-]+$(?![\s\S])/.test(name)) fail('Unexpected governance header');
    const val = text(value, 8192);
    if (/[^\x20-\x7e]/.test(val) || val !== val.trim()) fail('Invalid governance header value');
  }
  const body = object(obj.body);
  if (obj.endpoint === '/decide') {
    if (headers['x-gf-tenant-id'] !== obj.tenantId || headers['x-gf-agent-id'] !== obj.agentId || body.correlation_id !== obj.requestId) fail('Inconsistent PEP request identity');
  } else if (['tenantId', 'agentId', 'requestId'].some(k => body[k] !== obj[k])) fail('Inconsistent Console request identity');
  canonicalJson(obj);
  return obj as unknown as ReceiptRequest;
}

export interface ReceiptRequestInput {
  endpoint: ReceiptRequest['endpoint'];
  tenantId: string;
  agentId: string;
  requestId: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
  /** Leave unset for a fresh 256-bit challenge. SDK retries reuse the request. */
  nonce?: string;
}

/** Copy the evaluation request without including auth credentials. */
export function buildReceiptRequest(input: ReceiptRequestInput): ReceiptRequest {
  const governance: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const [name, value] of Object.entries(input.headers)) {
    const lower = name.toLowerCase();
    if (lower.startsWith('x-gf-')) {
      if (Object.prototype.hasOwnProperty.call(governance, lower)) fail('Duplicate governance header');
      governance[lower] = value;
    }
  }
  const request = {
    version: 1, method: 'POST', endpoint: input.endpoint,
    nonce: input.nonce === undefined ? randomBytes(32).toString('base64url') : input.nonce,
    tenantId: input.tenantId, agentId: input.agentId, requestId: input.requestId,
    governanceHeaders: governance, body: input.body,
  };
  validateReceiptRequest(request);
  return JSON.parse(canonicalJson(request).toString('utf8')) as ReceiptRequest;
}

export function receiptRequestHash(request: ReceiptRequest): string {
  validateReceiptRequest(request);
  return createHash('sha256').update(DOMAIN).update(canonicalJson(request)).digest('hex');
}

export interface ReceiptDecision {
  decision: 'allowed' | 'blocked' | 'escalated';
  reason: string;
  violatedRule: string | null;
  requiresApproval: boolean;
  sessionRevoked: boolean;
  complianceMappings: Array<{ regulation: string; controlId: string; controlName: string; description: string }>;
}

export function validateReceiptDecision(value: unknown): ReceiptDecision {
  const obj = object(value, DECISION_FIELDS);
  if (!['allowed', 'blocked', 'escalated'].includes(obj.decision as string)) fail('Unknown policy decision');
  text(obj.reason, 4096, true);
  if (obj.violatedRule !== null) text(obj.violatedRule);
  if (typeof obj.requiresApproval !== 'boolean' || typeof obj.sessionRevoked !== 'boolean') fail('Invalid decision flags');
  if (obj.decision === 'allowed' && (obj.requiresApproval || obj.sessionRevoked)) fail('Contradictory allow decision');
  if (obj.decision === 'escalated' && !obj.requiresApproval) fail('Escalated decision requires approval');
  if (obj.sessionRevoked && (obj.decision !== 'blocked' || obj.requiresApproval)) fail('Contradictory revoked decision');
  if (!Array.isArray(obj.complianceMappings) || obj.complianceMappings.length > 64) fail('Invalid compliance mappings');
  for (const entry of obj.complianceMappings) {
    const mapping = object(entry, ['regulation', 'controlId', 'controlName', 'description']);
    for (const val of Object.values(mapping)) text(val, 1024, true);
  }
  return obj as unknown as ReceiptDecision;
}

export function assertReceiptTransport(url: string): void {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password || parsed.search || parsed.hash || /[\r\n\t]/.test(url)) fail('Receipt verification requires HTTPS URLs without credentials, query, or fragment');
  } catch (error) {
    if (error instanceof ReceiptVerificationError) throw error;
    fail('Invalid HTTPS URL');
  }
}

export interface ReceiptVerificationConfig {
  issuer: string;
  audience: string;
  /** Trusted Ed25519 public keys in SPKI PEM format, indexed by key ID. */
  publicKeys: Record<string, string>;
  clockSkewSeconds?: number;
  maxLifetimeSeconds?: number;
}

export interface ReceiptClaims {
  version: 1;
  iss: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  nonce: string;
  tenantId: string;
  agentId: string;
  requestId: string;
  requestHash: string;
  decision: ReceiptDecision;
}

export interface VerifiedReceipt {
  readonly token: string;
  readonly claims: ReceiptClaims;
  readonly decision: ReceiptDecision;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export class ReceiptVerifier {
  private readonly issuer: string;
  private readonly audience: string;
  private readonly skew: number;
  private readonly lifetime: number;
  private readonly keys = new Map<string, KeyObject>();

  constructor(config: ReceiptVerificationConfig) {
    object(config);
    this.issuer = text(config.issuer);
    this.audience = text(config.audience);
    this.skew = integer(config.clockSkewSeconds === undefined ? 5 : config.clockSkewSeconds, 0, 30);
    this.lifetime = integer(config.maxLifetimeSeconds === undefined ? 60 : config.maxLifetimeSeconds, 1, 300);
    const entries = Object.entries(object(config.publicKeys));
    if (entries.length < 1 || entries.length > 32) fail('Configure 1 to 32 trusted public keys');
    for (const [kid, value] of entries) {
      if (!KID.test(kid)) fail('Invalid trusted key identifier');
      const pem = text(value, 4096);
      if (!/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----$(?![\s\S])/.test(pem.trim())) fail('Only public SPKI PEM keys are accepted');
      let key: KeyObject;
      try { key = createPublicKey(pem); } catch { return fail('Invalid trusted public key'); }
      if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') fail('Trusted keys must be Ed25519');
      this.keys.set(kid, key);
    }
  }

  verifyResponse(response: unknown, request: ReceiptRequest, now?: number): VerifiedReceipt {
    const obj = object(response);
    if (!Object.prototype.hasOwnProperty.call(obj, 'receipt')) fail('Signed decision receipt is required');
    // Only the decision inside the signed receipt counts.
    return this.verify(obj.receipt, request, now);
  }

  verify(token: unknown, request: ReceiptRequest, now?: number): VerifiedReceipt {
    try { return this.verifyInternal(token, request, now); }
    catch (error) {
      if (error instanceof ReceiptVerificationError) throw error;
      return fail('Receipt verification failed');
    }
  }

  private verifyInternal(token: unknown, request: ReceiptRequest, now?: number): VerifiedReceipt {
    if (typeof token !== 'string' || token.length > MAX_TOKEN_BYTES) fail('Invalid receipt size or type');
    const parts = token.split('.');
    if (parts.length !== 3) fail('Expected compact JWS');
    const [h, p, s] = parts;
    const header = object(parseCanonical(decode(h, 2048)), ['alg', 'typ', 'kid']);
    if (header.alg !== RECEIPT_ALGORITHM || header.typ !== RECEIPT_TYPE) fail('Unsupported receipt algorithm or type');
    if (typeof header.kid !== 'string' || !KID.test(header.kid)) fail('Unknown signing key');
    const key = this.keys.get(header.kid);
    if (!key) fail('Unknown signing key');
    const signature = decode(s, 128);
    if (signature.length !== 64) fail('Invalid Ed25519 signature length');
    const payload = decode(p, MAX_TOKEN_BYTES);
    if (!verify(null, Buffer.from(`${h}.${p}`, 'ascii'), key, signature)) fail('Invalid receipt signature');
    const claims = object(parseCanonical(payload), CLAIM_FIELDS);
    if (claims.version !== 1) fail('Unsupported receipt version');
    if (claims.iss !== this.issuer || claims.aud !== this.audience) fail('Receipt issuer or audience mismatch');
    if (!JTI.test(text(claims.jti, 128))) fail('Receipt identifier too short');
    const issued = integer(claims.iat, 0, Number.MAX_SAFE_INTEGER);
    const expires = integer(claims.exp, 0, Number.MAX_SAFE_INTEGER);
    const current = integer(now === undefined ? Math.floor(Date.now() / 1000) : now, 0, Number.MAX_SAFE_INTEGER);
    if (expires <= issued || expires - issued > this.lifetime || issued - current > this.skew || current - expires >= this.skew) fail('Receipt is expired, not yet valid, or exceeds lifetime policy');
    validateReceiptRequest(request);
    for (const field of ['tenantId', 'agentId', 'requestId', 'nonce'] as const) {
      if (typeof claims[field] !== 'string' || claims[field] !== request[field]) fail('Receipt request binding mismatch');
    }
    const digest = claims.requestHash;
    if (typeof digest !== 'string' || !HASH.test(digest)) fail('Invalid request digest');
    if (!timingSafeEqual(Buffer.from(digest, 'hex'), Buffer.from(receiptRequestHash(request), 'hex'))) fail('Receipt request digest mismatch');
    const decision = validateReceiptDecision(claims.decision);
    return deepFreeze({ token, claims: claims as unknown as ReceiptClaims, decision });
  }
}
