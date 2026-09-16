import {
  AgentShield,
  ShieldBlockedError,
  ShieldConsoleError,
  ShieldConnectionError,
} from '../src/index';
import { tenantId } from '../src/ids';

const mockConfig = {
  pepUrl: 'https://pep.test.example',
  consoleUrl: 'https://console.test.example',
  apiKey: 'sk-shield-test-key',
  tenantId: tenantId('acme-inc'),
  department: 'Engineering',
  userId: 'usr_ENG_001',
  aiModel: 'GPT-4o',
  agentId: 'test-agent',
};

const allowedResponse = {
  decision: 'allowed',
  reason: 'No violations',
  violatedRule: null,
  requiresApproval: false,
  complianceMappings: [],
};

/** Queue a sequence of fetch responses; the last one repeats if over-drawn. */
function mockFetchSequence(responses: Array<{ ok: boolean; status?: number; body: unknown }>) {
  let callCount = 0;
  global.fetch = jest.fn().mockImplementation(() => {
    const response = responses[callCount] ?? responses[responses.length - 1];
    callCount++;
    return Promise.resolve({
      ok: response.ok,
      status: response.status ?? (response.ok ? 200 : 500),
      json: () => Promise.resolve(response.body),
      text: () => Promise.resolve(JSON.stringify(response.body)),
    });
  });
}

/** Convenience: a single OK /check response (used with { log: false }). */
function mockCheckOnly(body: unknown) {
  mockFetchSequence([{ ok: true, body }]);
}

describe('AgentShield', () => {
  let shield: AgentShield;

  beforeEach(() => {
    shield = new AgentShield(mockConfig);
    jest.restoreAllMocks();
    delete process.env.G8R_CONSOLE_URL;
    delete process.env.G8R_API_KEY;
  });

  describe('constructor / config resolution', () => {
    it('throws when tenantId is empty', () => {
      expect(
        () =>
          new AgentShield({
            ...mockConfig,
            tenantId: '' as ReturnType<typeof tenantId>,
          })
      ).toThrow(/tenantId is required/);
    });

    it('throws when consoleUrl is unresolvable (no arg, no env)', () => {
      expect(
        () => new AgentShield({ ...mockConfig, consoleUrl: undefined })
      ).toThrow(/consoleUrl is required/);
    });

    it('throws when apiKey is unresolvable (no arg, no env)', () => {
      expect(() => new AgentShield({ ...mockConfig, apiKey: undefined })).toThrow(
        /apiKey is required/
      );
    });

    it('resolves consoleUrl and apiKey from env when omitted', async () => {
      process.env.G8R_CONSOLE_URL = 'https://env-console.example.com';
      process.env.G8R_API_KEY = 'sk-from-env';

      const envShield = new AgentShield({
        ...mockConfig,
        consoleUrl: undefined,
        apiKey: undefined,
      });

      mockCheckOnly(allowedResponse);
      await envShield.check('hi', { log: false });

      const [url, init] = (global.fetch as jest.Mock).mock.calls[0];
      expect(url).toBe('https://env-console.example.com/api/sdk/v1/check');
      expect(init.headers.Authorization).toBe('Bearer sk-from-env');
    });

    it('prefers explicit args over env vars', async () => {
      process.env.G8R_CONSOLE_URL = 'https://env-console.example.com';
      process.env.G8R_API_KEY = 'sk-from-env';

      const argShield = new AgentShield(mockConfig);
      mockCheckOnly(allowedResponse);
      await argShield.check('hi', { log: false });

      const [url, init] = (global.fetch as jest.Mock).mock.calls[0];
      expect(url).toBe('https://console.test.example/api/sdk/v1/check');
      expect(init.headers.Authorization).toBe('Bearer sk-shield-test-key');
    });

    it('never defaults consoleUrl to localhost — fails closed', () => {
      // No arg, no env → must throw rather than silently pick 127.0.0.1. The
      // message deliberately WARNS about localhost, so we assert on behavior
      // (it throws and never issues a request) rather than message contents.
      global.fetch = jest.fn();
      expect(() => new AgentShield({ ...mockConfig, consoleUrl: undefined })).toThrow(
        /consoleUrl is required/
      );
      expect(global.fetch).not.toHaveBeenCalled();
    });

    it('strips a trailing slash from consoleUrl', async () => {
      const slashShield = new AgentShield({
        ...mockConfig,
        consoleUrl: 'https://console.test.example/',
      });
      mockCheckOnly(allowedResponse);
      await slashShield.check('hi', { log: false });
      const [url] = (global.fetch as jest.Mock).mock.calls[0];
      expect(url).toBe('https://console.test.example/api/sdk/v1/check');
    });

    it('applies field defaults (department/userId/aiModel/agentId) when omitted', async () => {
      const minimalShield = new AgentShield({
        pepUrl: 'https://pep.test.example',
        consoleUrl: 'https://console.test.example',
        apiKey: 'sk',
        tenantId: tenantId('acme-inc'),
      });
      mockCheckOnly(allowedResponse);
      await minimalShield.check('hi', { log: false });
      const body = JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body);
      expect(body.department).toBe('General');
      expect(body.userId).toBe('unknown');
      expect(body.aiModel).toBe('unknown');
      expect(body.agentId).toBe('sdk-client');
    });

    it('never exposes the api key in toString()', () => {
      expect(shield.toString()).not.toContain('sk-shield-test-key');
      expect(shield.toString()).toContain('acme-inc');
    });
  });

  describe('check()', () => {
    it('sends redacted prompt to gateway (not raw)', async () => {
      mockCheckOnly(allowedResponse);

      await shield.check('Check account custodial-id:abc123xyz for compliance', {
        log: false,
      });

      const body = JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body);
      expect(body.input).toContain('[REDACTED:CUSTODIAL_ID]');
      expect(body.input).not.toContain('custodial-id:abc123xyz');
    });

    it('sends correct request to /api/sdk/v1/check with User-Agent header', async () => {
      mockCheckOnly(allowedResponse);

      const result = await shield.check('What is the weather?', { log: false });

      const [url, init] = (global.fetch as jest.Mock).mock.calls[0];
      expect(url).toBe('https://console.test.example/api/sdk/v1/check');
      expect(init.method).toBe('POST');
      expect(init.headers['Content-Type']).toBe('application/json');
      expect(init.headers.Authorization).toBe('Bearer sk-shield-test-key');
      expect(init.headers['User-Agent']).toMatch(/^g8r-shield-typescript\/\d+\.\d+\.\d+$/);
      expect(result.decision).toBe('allowed');
    });

    it('does not send x-gf-department on check() (Console /check uses JSON department)', async () => {
      mockCheckOnly(allowedResponse);
      await shield.check('What is the weather?', { log: false });
      const [url, init] = (global.fetch as jest.Mock).mock.calls[0];
      expect(url).toBe('https://console.test.example/api/sdk/v1/check');
      expect(init.headers['x-gf-department']).toBeUndefined();
      const body = JSON.parse(init.body);
      expect(body.department).toBe('Engineering');
    });

    it('logs by default (POSTs to /log with the SAME requestId)', async () => {
      mockFetchSequence([
        { ok: true, body: allowedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);

      await shield.check('audit me');

      expect(global.fetch).toHaveBeenCalledTimes(2);
      expect((global.fetch as jest.Mock).mock.calls[0][0]).toBe(
        'https://console.test.example/api/sdk/v1/check'
      );
      expect((global.fetch as jest.Mock).mock.calls[1][0]).toBe(
        'https://console.test.example/api/sdk/v1/log'
      );
      const checkBody = JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body);
      const logBody = JSON.parse((global.fetch as jest.Mock).mock.calls[1][1].body);
      expect(checkBody.requestId).toBe(logBody.requestId);
    });

    it('does NOT log when { log: false }', async () => {
      mockCheckOnly(allowedResponse);
      await shield.check('no audit', { log: false });
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it('uses the explicit requestId verbatim when provided', async () => {
      mockCheckOnly(allowedResponse);
      const fixedId = 'req-fixed-123' as import('../src/ids').RequestId;
      await shield.check('x', { requestId: fixedId, log: false });
      const body = JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body);
      expect(body.requestId).toBe('req-fixed-123');
    });

    it('does NOT send employeeName on /check (parity: only /log carries it)', async () => {
      mockCheckOnly(allowedResponse);
      const named = new AgentShield({ ...mockConfig, employeeName: 'Alex Park' });
      mockCheckOnly(allowedResponse);
      await named.check('x', { log: false });
      const body = JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body);
      expect(body.employeeName).toBeUndefined();
    });

    it('throws a typed ShieldConsoleError on non-2xx, hiding the body', async () => {
      mockFetchSequence([{ ok: false, status: 500, body: { secretStack: 'do not leak' } }]);

      let thrown: ShieldConsoleError | undefined;
      try {
        await shield.check('test', { log: false });
      } catch (e) {
        thrown = e as ShieldConsoleError;
      }

      expect(thrown).toBeInstanceOf(ShieldConsoleError);
      expect(thrown!.statusCode).toBe(500);
      expect(thrown!.message).toBe('[G8R Shield] Console returned HTTP 500');
      // Raw body is preserved for opt-in inspection but NEVER in the message.
      expect(thrown!.message).not.toContain('do not leak');
      expect(thrown!.detail).toContain('do not leak');
    });

    it('does NOT retry on a non-2xx response (hard failure surfaces immediately)', async () => {
      mockFetchSequence([{ ok: false, status: 403, body: {} }]);
      await expect(shield.check('test', { log: false })).rejects.toBeInstanceOf(ShieldConsoleError);
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it('retries exactly once on a transient network error, then succeeds', async () => {
      let call = 0;
      global.fetch = jest.fn().mockImplementation(() => {
        call++;
        if (call === 1) {
          return Promise.reject(new Error('ECONNREFUSED'));
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(allowedResponse),
          text: () => Promise.resolve('{}'),
        });
      });

      const result = await shield.check('test', { log: false });
      expect(result.decision).toBe('allowed');
      expect(global.fetch).toHaveBeenCalledTimes(2);
    });

    it('raises ShieldConnectionError after the single retry fails', async () => {
      global.fetch = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));

      let thrown: ShieldConnectionError | undefined;
      try {
        await shield.check('test', { log: false });
      } catch (e) {
        thrown = e as ShieldConnectionError;
      }
      expect(thrown).toBeInstanceOf(ShieldConnectionError);
      expect(thrown!.consoleUrl).toBe('https://console.test.example');
      expect(thrown!.message).toContain('https://console.test.example');
      expect(global.fetch).toHaveBeenCalledTimes(2); // original + one retry
    });

    it("uses 'sdk-client' as default agentId when not configured", async () => {
      const noAgentShield = new AgentShield({ ...mockConfig, agentId: undefined });
      mockCheckOnly(allowedResponse);
      await noAgentShield.check('test', { log: false });
      const body = JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body);
      expect(body.agentId).toBe('sdk-client');
    });

    it('returns redactedTokens when sensitive tokens are replaced', async () => {
      mockCheckOnly(allowedResponse);
      const result = await shield.check('Check custodial-id:xyz-999 balance', { log: false });
      expect(result.redactedTokens).toBeDefined();
      expect(result.redactedTokens!.length).toBeGreaterThan(0);
    });

    it('returns undefined redactedTokens when no tokens replaced', async () => {
      mockCheckOnly(allowedResponse);
      const result = await shield.check('What is the weather today?', { log: false });
      expect(result.redactedTokens).toBeUndefined();
    });

    it('NEVER raises on a blocked decision (returns it for the caller to act on)', async () => {
      mockCheckOnly({
        decision: 'blocked',
        reason: 'nope',
        violatedRule: 'r',
        requiresApproval: false,
        complianceMappings: [],
      });
      const result = await shield.check('bad', { log: false });
      expect(result.decision).toBe('blocked');
    });
  });

  describe('wrap()', () => {
    const blockedResponse = {
      decision: 'blocked',
      reason: 'PII detected',
      violatedRule: 'PII Protection Guard',
      requiresApproval: false,
      complianceMappings: [
        {
          regulation: 'GDPR',
          controlId: 'Art. 5',
          controlName: 'Data Minimization',
          description: 'Limit data processing',
        },
      ],
    };

    it('invokes factory and returns result when policy allows', async () => {
      mockFetchSequence([
        { ok: true, body: allowedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);

      const factory = jest.fn().mockResolvedValue({ content: 'sunny' });
      const result = await shield.wrap(factory, 'What is the weather?');

      expect(factory).toHaveBeenCalledTimes(1);
      expect(result).toEqual({ content: 'sunny' });
    });

    it('makes exactly two HTTP calls (/check then /log) — no duplicate log', async () => {
      mockFetchSequence([
        { ok: true, body: allowedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);
      await shield.wrap(() => Promise.resolve('ok'), 'Safe query');
      expect(global.fetch).toHaveBeenCalledTimes(2);
      expect((global.fetch as jest.Mock).mock.calls[0][0]).toBe(
        'https://pep.test.example/decide'
      );
      expect((global.fetch as jest.Mock).mock.calls[1][0]).toBe(
        'https://console.test.example/api/sdk/v1/log'
      );
    });

    it('sends x-gf-department on wrap() PEP /decide equal to the constructed department', async () => {
      mockFetchSequence([
        { ok: true, body: allowedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);
      await shield.wrap(() => Promise.resolve('ok'), 'Safe query');
      const [url, init] = (global.fetch as jest.Mock).mock.calls[0];
      expect(url).toBe('https://pep.test.example/decide');
      expect(init.headers['x-gf-department']).toBe('Engineering');
      expect(init.headers['X-GF-Tenant-ID']).toBe('acme-inc');
      expect(init.headers['X-GF-Agent-ID']).toBe('test-agent');
      expect(typeof init.headers['x-gf-session-id']).toBe('string');
      // PEP Actor has no user header. x-gf-model-id is an upstream RESPONSE
      // header. User and model stay on Console /log only.
      expect(init.headers['x-gf-user-id']).toBeUndefined();
      expect(init.headers['x-gf-model-id']).toBeUndefined();
      expect((global.fetch as jest.Mock).mock.calls[1][0]).toBe(
        'https://console.test.example/api/sdk/v1/log'
      );
    });

    it('defaults wrap() PEP x-gf-department to General when department is omitted', async () => {
      const minimalShield = new AgentShield({
        pepUrl: 'https://pep.test.example',
        consoleUrl: 'https://console.test.example',
        apiKey: 'sk',
        tenantId: tenantId('acme-inc'),
      });
      mockFetchSequence([
        { ok: true, body: allowedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);
      await minimalShield.wrap(() => Promise.resolve('ok'), 'Safe query');
      const headers = (global.fetch as jest.Mock).mock.calls[0][1].headers;
      expect(headers['x-gf-department']).toBe('General');
    });

    it('does NOT invoke factory when policy blocks', async () => {
      mockFetchSequence([
        { ok: true, body: blockedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);

      const factory = jest.fn().mockResolvedValue('should not reach');
      await expect(shield.wrap(factory, 'Show me SSN records')).rejects.toThrow(ShieldBlockedError);
      expect(factory).not.toHaveBeenCalled();
    });

    it('logs the blocked attempt BEFORE throwing (audit records blocked attempts)', async () => {
      mockFetchSequence([
        { ok: true, body: blockedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);
      await expect(shield.wrap(() => Promise.resolve('x'), 'bad')).rejects.toThrow(
        ShieldBlockedError
      );
      // /check + /log both fired even though the decision was blocked.
      expect(global.fetch).toHaveBeenCalledTimes(2);
      expect((global.fetch as jest.Mock).mock.calls[1][0]).toBe(
        'https://console.test.example/api/sdk/v1/log'
      );
    });

    it('throws ShieldBlockedError with correct properties on block', async () => {
      mockFetchSequence([
        { ok: true, body: blockedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);

      try {
        await shield.wrap(() => Promise.resolve('nope'), 'bad prompt');
        fail('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(ShieldBlockedError);
        const blocked = err as ShieldBlockedError;
        expect(blocked.decision).toBe('blocked');
        expect(blocked.violatedRule).toBe('PII Protection Guard');
        expect(blocked.complianceMappings).toHaveLength(1);
        expect(blocked.complianceMappings[0].regulation).toBe('GDPR');
        expect(blocked.sessionRevoked).toBe(false);
      }
    });

    it('propagates sessionRevoked: true when kill switch fires', async () => {
      const killSwitchResponse = {
        decision: 'blocked',
        reason: 'Partner compensation data is restricted',
        violatedRule: 'Sensitive Data Egress',
        requiresApproval: false,
        sessionRevoked: true,
        complianceMappings: [
          {
            regulation: 'NIST AI RMF',
            controlId: 'GOVERN 1.1',
            controlName: 'AI Governance',
            description: 'Legal and regulatory requirements are documented.',
          },
        ],
      };

      mockFetchSequence([
        { ok: true, body: killSwitchResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);

      const logSpy = jest.spyOn(console, 'log').mockImplementation();
      try {
        await shield.wrap(() => Promise.resolve('nope'), 'Pull partner compensation report');
        fail('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(ShieldBlockedError);
        const blocked = err as ShieldBlockedError;
        expect(blocked.sessionRevoked).toBe(true);
        expect(blocked.violatedRule).toBe('Sensitive Data Egress');
      }
      // A session_revoked warning is emitted before the throw.
      const emitted = logSpy.mock.calls.map(([line]) => String(line));
      expect(emitted.some((l) => l.includes('session_revoked'))).toBe(true);
      logSpy.mockRestore();
    });

    it('invokes factory on escalated decisions by default (warn + proceed)', async () => {
      const escalatedResponse = {
        decision: 'escalated',
        reason: 'Requires approval',
        violatedRule: 'Destructive Action',
        requiresApproval: true,
        complianceMappings: [],
      };

      mockFetchSequence([
        { ok: true, body: escalatedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);

      const logSpy = jest.spyOn(console, 'log').mockImplementation();
      const factory = jest.fn().mockResolvedValue({ status: 'done' });

      const result = await shield.wrap(factory, 'DROP TABLE users');

      expect(factory).toHaveBeenCalledTimes(1);
      expect(result).toEqual({ status: 'done' });
      const emitted = logSpy.mock.calls.map(([line]) => String(line));
      const escalatedLine = emitted.find((l) => l.includes('action_escalated'));
      expect(escalatedLine).toBeDefined();
      expect(JSON.parse(escalatedLine as string)).toMatchObject({ level: 'warn' });
      logSpy.mockRestore();
    });

    it('throws on escalated when blockOnEscalated is true', async () => {
      const escalatedResponse = {
        decision: 'escalated',
        reason: 'Requires approval',
        violatedRule: 'Destructive Action',
        requiresApproval: true,
        complianceMappings: [],
      };
      const strictShield = new AgentShield({ ...mockConfig, blockOnEscalated: true });
      mockFetchSequence([
        { ok: true, body: escalatedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);

      const factory = jest.fn().mockResolvedValue('nope');
      await expect(strictShield.wrap(factory, 'DROP TABLE users')).rejects.toBeInstanceOf(
        ShieldBlockedError
      );
      expect(factory).not.toHaveBeenCalled();
    });

    it('sends a REDACTED prompt to /log (audit path must not leak raw secrets)', async () => {
      mockFetchSequence([
        { ok: true, body: allowedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);

      await shield.wrap(() => Promise.resolve('ok'), 'Move funds from custodial-id:abc123xyz now');

      const logBody = JSON.parse((global.fetch as jest.Mock).mock.calls[1][1].body);
      expect(logBody.input).toContain('[REDACTED:CUSTODIAL_ID]');
      expect(logBody.input).not.toContain('custodial-id:abc123xyz');
    });

    it('sends employeeName in log request (defaults to userId)', async () => {
      mockFetchSequence([
        { ok: true, body: allowedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);
      await shield.wrap(() => Promise.resolve('ok'), 'test');
      const logBody = JSON.parse((global.fetch as jest.Mock).mock.calls[1][1].body);
      expect(logBody.employeeName).toBe('usr_ENG_001');
    });

    it('sends configured employeeName in log request', async () => {
      const namedShield = new AgentShield({ ...mockConfig, employeeName: 'Alex Park' });
      mockFetchSequence([
        { ok: true, body: allowedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);
      await namedShield.wrap(() => Promise.resolve('ok'), 'test');
      const logBody = JSON.parse((global.fetch as jest.Mock).mock.calls[1][1].body);
      expect(logBody.employeeName).toBe('Alex Park');
    });

    it('uses a single requestId for both /check and /log', async () => {
      mockFetchSequence([
        { ok: true, body: allowedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);
      await shield.wrap(() => Promise.resolve('ok'), 'prompt');
      expect(global.fetch).toHaveBeenCalledTimes(2);
      const checkBody = JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body);
      const logBody = JSON.parse((global.fetch as jest.Mock).mock.calls[1][1].body);
      expect(checkBody.correlation_id).toBeDefined();
      expect(logBody.requestId).toBeDefined();
      expect(checkBody.correlation_id).toBe(logBody.requestId);
    });

    it('a /log outage does NOT break the wrapped call (log failure is swallowed)', async () => {
      mockFetchSequence([
        { ok: true, body: allowedResponse },
        { ok: false, status: 503, body: 'log server down' },
      ]);
      const logSpy = jest.spyOn(console, 'log').mockImplementation();
      const factory = jest.fn().mockResolvedValue({ content: 'ok' });
      const result = await shield.wrap(factory, 'safe');
      expect(result).toEqual({ content: 'ok' });
      expect(factory).toHaveBeenCalledTimes(1);
      logSpy.mockRestore();
    });
  });
});

describe('ShieldBlockedError', () => {
  it('has correct name', () => {
    const err = new ShieldBlockedError('blocked', 'Blocked', 'rule-1', []);
    expect(err.name).toBe('ShieldBlockedError');
  });

  it('includes reason in message', () => {
    const err = new ShieldBlockedError('blocked', 'PII detected', 'PII Guard', []);
    expect(err.message).toContain('PII detected');
    expect(err.message).toContain('[G8R Shield BLOCKED]');
  });

  it('exposes decision, violatedRule and complianceMappings', () => {
    const mappings = [
      {
        regulation: 'GDPR',
        controlId: 'Art. 5',
        controlName: 'Data Min',
        description: 'Desc',
      },
    ];
    const err = new ShieldBlockedError('blocked', 'reason', 'rule-1', mappings);
    expect(err.decision).toBe('blocked');
    expect(err.violatedRule).toBe('rule-1');
    expect(err.complianceMappings).toEqual(mappings);
  });

  it('is an instance of Error', () => {
    const err = new ShieldBlockedError('blocked', 'reason', null, []);
    expect(err).toBeInstanceOf(Error);
  });

  it('defaults sessionRevoked to false when not provided', () => {
    const err = new ShieldBlockedError('blocked', 'reason', 'rule', []);
    expect(err.sessionRevoked).toBe(false);
  });

  it('stores sessionRevoked: true when explicitly set', () => {
    const err = new ShieldBlockedError('blocked', 'kill switch', 'Partner Data', [], true);
    expect(err.sessionRevoked).toBe(true);
  });
});

describe('ShieldConsoleError', () => {
  it('exposes only the safe status message, keeping the body on .detail', () => {
    const err = new ShieldConsoleError(502, 'internal stack trace here');
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('ShieldConsoleError');
    expect(err.statusCode).toBe(502);
    expect(err.message).toBe('[G8R Shield] Console returned HTTP 502');
    expect(err.message).not.toContain('internal stack trace');
    expect(err.detail).toBe('internal stack trace here');
  });
});

describe('ShieldConnectionError', () => {
  it('names the console url and carries no body', () => {
    const err = new ShieldConnectionError('https://console.example.com');
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('ShieldConnectionError');
    expect(err.consoleUrl).toBe('https://console.example.com');
    expect(err.message).toContain('https://console.example.com');
    expect(err.message).toContain('retry');
  });
});
