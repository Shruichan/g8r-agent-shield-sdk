import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { AgentShield, ShieldBlockedError, tenantId } from '../src/index';
import {
  ReceiptVerificationError,
  ReceiptVerifier,
  buildReceiptRequest,
  canonicalJson,
  receiptRequestHash,
  RECEIPT_ALGORITHM,
  RECEIPT_TYPE,
  type ReceiptDecision,
  type ReceiptRequest,
} from '../src/receipts';

const pair = generateKeyPairSync('ed25519');
const publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const verification = {
  issuer: 'integration-authority',
  audience: 'integration-sdk',
  publicKeys: { test: publicKey },
};
const config = {
  pepUrl: 'https://pep.example.test',
  consoleUrl: 'https://console.example.test',
  tenantId: tenantId('test-tenant'),
  agentId: 'test-agent',
  apiKey: 'test-credential',
  receiptVerification: verification,
};

function decision(outcome: ReceiptDecision['decision'] = 'allowed'): ReceiptDecision {
  return {
    decision: outcome,
    reason: 'integration test',
    violatedRule: null,
    requiresApproval: outcome === 'escalated',
    sessionRevoked: false,
    complianceMappings: [],
  };
}

function signed(request: ReceiptRequest, result: ReceiptDecision): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: RECEIPT_ALGORITHM, typ: RECEIPT_TYPE, kid: 'test' };
  const payload = {
    version: 1,
    iss: verification.issuer,
    aud: verification.audience,
    iat: now,
    exp: now + 30,
    jti: randomUUID(),
    nonce: request.nonce,
    tenantId: request.tenantId,
    agentId: request.agentId,
    requestId: request.requestId,
    requestHash: receiptRequestHash(request),
    decision: result,
  };
  const input = `${canonicalJson(header).toString('base64url')}.${canonicalJson(payload).toString('base64url')}`;
  return `${input}.${sign(null, Buffer.from(input), pair.privateKey).toString('base64url')}`;
}

function installTransport(outcome: ReceiptDecision['decision'] = 'allowed', omitReceipt = false): void {
  jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input);
    if (url.endsWith('/api/sdk/v1/log')) {
      return new Response(JSON.stringify({ id: 'log', decision: 'allowed', timestamp: 'test' }), { status: 200 });
    }
    const endpoint = new URL(url).pathname as ReceiptRequest['endpoint'];
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((value, name) => { headers[name] = value; });
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    expect(headers['x-g8r-receipt-version']).toBe('1');
    const request = buildReceiptRequest({
      endpoint,
      tenantId: config.tenantId,
      agentId: config.agentId,
      requestId: String(endpoint === '/decide' ? body.correlation_id : body.requestId),
      headers,
      body,
      nonce: headers['x-g8r-receipt-nonce'],
    });
    return new Response(JSON.stringify(omitReceipt ? { decision: 'allowed' } : { receipt: signed(request, decision(outcome)) }), { status: 200 });
  });
}

afterEach(() => jest.restoreAllMocks());

test('signed allow executes callback', async () => {
  installTransport('allowed');
  const callback = jest.fn(async () => 'ok');
  await expect(new AgentShield(config).wrap(callback, 'demo:allow')).resolves.toBe('ok');
  expect(callback).toHaveBeenCalledTimes(1);
});

test.each(['blocked', 'escalated'] as const)('signed %s never executes callback', async (outcome) => {
  installTransport(outcome);
  const callback = jest.fn(async () => 'must-not-run');
  await expect(new AgentShield({ ...config, blockOnEscalated: false }).wrap(callback, 'demo')).rejects.toBeInstanceOf(ShieldBlockedError);
  expect(callback).not.toHaveBeenCalled();
});

test('missing receipt fails closed', async () => {
  installTransport('allowed', true);
  const callback = jest.fn(async () => 'must-not-run');
  const err: unknown = await new AgentShield(config).wrap(callback, 'demo').then(
    () => {
      throw new Error('expected ReceiptVerificationError');
    },
    (caught: unknown) => caught,
  );
  expect(err).toBeInstanceOf(ReceiptVerificationError);
  expect(err).toHaveProperty('message', 'Signed decision receipt is required');
  expect(callback).not.toHaveBeenCalled();
});

test('undici Response.json() is accepted as a receipt envelope', async () => {
  const parsed: unknown = await new Response(JSON.stringify({ decision: 'allowed' })).json();
  const request = buildReceiptRequest({
    endpoint: '/decide',
    tenantId: config.tenantId,
    agentId: config.agentId,
    requestId: 'req-1',
    headers: { 'x-gf-tenant-id': config.tenantId, 'x-gf-agent-id': config.agentId },
    body: {
      correlation_id: 'req-1',
      downstream_url: 'sdk://wrap',
      method: 'POST',
      action_hint: 'llm_prompt',
      target_hint: 'llm_prompt',
      body: { prompt: 'x' },
      action_type: 'tool_call',
    },
  });
  expect(() => new ReceiptVerifier(verification).verifyResponse(parsed, request)).toThrow(
    'Signed decision receipt is required',
  );
});

test('signed mode requires HTTPS', () => {
  expect(() => new AgentShield({ ...config, pepUrl: 'http://pep.example.test' })).toThrow(ReceiptVerificationError);
});
