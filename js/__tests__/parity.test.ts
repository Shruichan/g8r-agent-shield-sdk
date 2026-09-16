/**
 * Parity / contract test.
 *
 * The canonical surface is a single synchronized release across the Python and
 * TypeScript SDKs. "Are these two in parity?" must be answerable by a
 * version-equality check plus a wire-contract check in CI — that is the whole
 * point of a canonical surface.
 *
 * This test pins the TypeScript side of the contract:
 *   1. The exported VERSION matches package.json AND the canonical 0.6.0.
 *   2. The User-Agent identifies the TS SDK + version (mirror of
 *      Python's `g8r-shield-python/{version}`).
 *   3. The /check and /log wire payloads carry EXACTLY the canonical field set
 *      when NO lineage is active (proving the additive sub-agent-lineage fields
 *      are backward-compatible — absent on a plain, un-nested call).
 *   4. The defaulted-not-required fields resolve to the canonical defaults.
 *   5. employeeName is on /log only, never on /check.
 *   6. Under active lineage, the ONLY new fields are `sessionId` +
 *      `parentAgents` — the two additive fields the 0.4.0 wire contract gained.
 *
 * The Python contract test asserts the same field sets against the same
 * canonical version, so a drift on either side breaks CI.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { AgentShield, VERSION } from '../src/index';
import { tenantId } from '../src/ids';

const CANONICAL_VERSION = '0.6.0';

// The exact governance field set the /check payload must carry (order-independent).
const CANONICAL_CHECK_FIELDS = [
  'input',
  'tenantId',
  'requestId',
  'department',
  'userId',
  'aiModel',
  'agentId',
].sort();

// The exact field set the /log payload must carry.
const CANONICAL_LOG_FIELDS = [
  'input',
  'tenantId',
  'requestId',
  'userId',
  'department',
  'aiModel',
  'agentId',
  'employeeName',
  'decision',
  'reason',
  'violatedRule',
  'requiresApproval',
  'complianceMappings',
].sort();

const allowedResponse = {
  decision: 'allowed',
  reason: 'ok',
  violatedRule: null,
  requiresApproval: false,
  complianceMappings: [],
};

function mockFetch(bodies: unknown[]) {
  let i = 0;
  global.fetch = jest.fn().mockImplementation(() => {
    const body = bodies[i] ?? bodies[bodies.length - 1];
    i++;
    return Promise.resolve({
      ok: true,
      status: 200,
      json: () => Promise.resolve(body),
      text: () => Promise.resolve(JSON.stringify(body)),
    });
  });
}

describe('canonical parity', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('exports VERSION equal to the canonical 0.6.0', () => {
    expect(VERSION).toBe(CANONICAL_VERSION);
  });

  it('keeps VERSION in lockstep with package.json (single-source version equality)', () => {
    const pkg = JSON.parse(
      readFileSync(join(__dirname, '..', 'package.json'), 'utf8')
    ) as { version: string };
    expect(pkg.version).toBe(CANONICAL_VERSION);
    expect(pkg.version).toBe(VERSION);
  });

  it('sends a versioned, language-tagged User-Agent (mirror of python-vs-ts)', async () => {
    mockFetch([allowedResponse]);
    const shield = new AgentShield({
      pepUrl: 'https://pep.test.example',
      consoleUrl: 'http://c',
      apiKey: 'k',
      tenantId: tenantId('acme'),
    });
    await shield.check('hi', { log: false });
    const ua = (global.fetch as jest.Mock).mock.calls[0][1].headers['User-Agent'];
    expect(ua).toBe(`g8r-shield-typescript/${CANONICAL_VERSION}`);
  });

  it('/check payload carries EXACTLY the canonical field set', async () => {
    mockFetch([allowedResponse]);
    const shield = new AgentShield({
      pepUrl: 'https://pep.test.example',
      consoleUrl: 'http://c',
      apiKey: 'k',
      tenantId: tenantId('acme'),
      employeeName: 'Should Not Appear On Check',
    });
    await shield.check('hi', { log: false });
    const body = JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body);
    expect(Object.keys(body).sort()).toEqual(CANONICAL_CHECK_FIELDS);
    // employeeName is NEVER on /check.
    expect(body).not.toHaveProperty('employeeName');
  });

  it('/log payload carries EXACTLY the canonical field set (no lineage → back-compat)', async () => {
    mockFetch([allowedResponse, { id: 'log' }]);
    const shield = new AgentShield({
      pepUrl: 'https://pep.test.example',
      consoleUrl: 'http://c',
      apiKey: 'k',
      tenantId: tenantId('acme'),
    });
    // Drive the audit log via a self-auditing check() with NO ambient session,
    // so the /log body is the base contract — the additive lineage fields are
    // omitted. (wrap() always mints a session; that lineage-active shape is
    // asserted separately below.)
    await shield.check('hi');
    const body = JSON.parse((global.fetch as jest.Mock).mock.calls[1][1].body);
    expect(Object.keys(body).sort()).toEqual(CANONICAL_LOG_FIELDS);
  });

  it('adds ONLY sessionId + parentAgents to the wire under active lineage', async () => {
    // Nested wrap() so lineage is fully populated: an inner call inherits the
    // session and carries a non-empty ancestor chain. The 0.4.0 contract gained
    // exactly these two additive fields on BOTH /check and /log — nothing else.
    mockFetch([allowedResponse, { id: 'log' }, allowedResponse, { id: 'log' }]);
    const shield = new AgentShield({
      pepUrl: 'https://pep.test.example',
      consoleUrl: 'http://c',
      apiKey: 'k',
      tenantId: tenantId('acme'),
      agentId: 'root',
    });
    await shield.wrap(async () => {
      await shield.wrap(() => Promise.resolve('inner'), 'inner');
      return 'outer';
    }, 'outer');

    // Fetch order: [0] outer /decide, [1] outer /log, [2] inner /decide, [3] inner /log.
    const innerCheck = JSON.parse((global.fetch as jest.Mock).mock.calls[2][1].body);
    const innerLog = JSON.parse((global.fetch as jest.Mock).mock.calls[3][1].body);

    expect(innerCheck).toMatchObject({
      downstream_url: 'sdk://wrap',
      action_hint: 'llm_prompt',
      parentAgents: ['root'],
    });
    expect(typeof innerCheck.sessionId).toBe('string');
    expect(new Set(Object.keys(innerLog))).toEqual(
      new Set([...CANONICAL_LOG_FIELDS, 'sessionId', 'parentAgents'])
    );
    expect(typeof innerCheck.sessionId).toBe('string');
    expect(innerCheck.parentAgents).toEqual(['root']); // root-first ancestor chain
    // /check and /log agree on the lineage for the same hop.
    expect(innerLog.sessionId).toBe(innerCheck.sessionId);
    expect(innerLog.parentAgents).toEqual(innerCheck.parentAgents);
  });

  it('resolves the canonical defaulted-not-required field values', async () => {
    mockFetch([allowedResponse]);
    const shield = new AgentShield({
      pepUrl: 'https://pep.test.example',
      consoleUrl: 'http://c',
      apiKey: 'k',
      tenantId: tenantId('acme'), // only hard-required field
    });
    await shield.check('hi', { log: false });
    const body = JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body);
    expect(body.department).toBe('General');
    expect(body.userId).toBe('unknown');
    expect(body.aiModel).toBe('unknown');
    expect(body.agentId).toBe('sdk-client');
  });

  it('tenantId is the sole hard-required field (construction fails without it)', () => {
    // Missing tenantId → throw. (console/api can come from env, so they are
    // required-in-effect but not construction-args; tenant has no env fallback.)
    expect(
      () =>
        new AgentShield({
          pepUrl: 'https://pep.test.example',
          consoleUrl: 'http://c',
          apiKey: 'k',
          tenantId: '' as ReturnType<typeof tenantId>,
        })
    ).toThrow(/tenantId is required/);
  });

  it('uses the same agentId on /check and /log (construction-time normalization)', async () => {
    mockFetch([allowedResponse, { id: 'log' }]);
    const shield = new AgentShield({
      pepUrl: 'https://pep.test.example',
      consoleUrl: 'http://c',
      apiKey: 'k',
      tenantId: tenantId('acme'),
      agentId: 'my-agent',
    });
    await shield.wrap(() => Promise.resolve('ok'), 'hi');
    const hopHeaders = (global.fetch as jest.Mock).mock.calls[0][1].headers;
    const logBody = JSON.parse((global.fetch as jest.Mock).mock.calls[1][1].body);
    expect(hopHeaders['X-GF-Agent-ID']).toBe('my-agent');
    expect(hopHeaders['x-gf-department']).toBe('General');
    expect(logBody.agentId).toBe('my-agent');
    expect(logBody.department).toBe('General');
    // PEP Actor has no user header. x-gf-model-id is an upstream RESPONSE
    // header. User and model stay on Console /log only.
    expect(hopHeaders['x-gf-user-id']).toBeUndefined();
    expect(hopHeaders['x-gf-model-id']).toBeUndefined();
    expect(logBody.userId).toBe('unknown');
    expect(logBody.aiModel).toBe('unknown');
  });
});
