import { AgentShield, ShieldBlockedError } from '../src/index';
import { tenantId } from '../src/ids';

const mockConfig = {
  consoleUrl: 'http://localhost:3000',
  apiKey: 'sk-shield-test-key',
  tenantId: tenantId('bitgo-inc'),
  department: 'Engineering',
  userId: 'usr_ENG_001',
  aiModel: 'GPT-4o',
  agentId: 'test-agent',
};

describe('AgentShield', () => {
  let shield: AgentShield;

  beforeEach(() => {
    shield = new AgentShield(mockConfig);
    jest.restoreAllMocks();
  });

  describe('check()', () => {
    it('sends redacted prompt to gateway (not raw)', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            decision: 'allowed',
            reason: 'No violations',
            violatedRule: null,
            requiresApproval: false,
            complianceMappings: [],
          }),
      });

      await shield.check('Check account custodial-id:abc123xyz for compliance');

      const body = JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body);
      expect(body.input).toContain('[REDACTED:CUSTODIAL_ID]');
      expect(body.input).not.toContain('custodial-id:abc123xyz');
    });

    it('sends correct request to /api/sdk/v1/check', async () => {
      const mockResponse = {
        decision: 'allowed',
        reason: 'No violations',
        violatedRule: null,
        requiresApproval: false,
        complianceMappings: [],
      };

      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await shield.check('What is the weather?');

      expect(global.fetch).toHaveBeenCalledWith(
        'http://localhost:3000/api/sdk/v1/check',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer sk-shield-test-key',
          },
        })
      );

      expect(result.decision).toBe('allowed');
    });

    it('throws on non-OK response', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: false,
        status: 500,
      });

      await expect(shield.check('test')).rejects.toThrow('Shield policy check failed: 500');
    });

    it("uses 'sdk-client' as default agentId when not configured", async () => {
      const noAgentShield = new AgentShield({
        ...mockConfig,
        agentId: undefined,
      });

      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            decision: 'allowed',
            reason: 'OK',
            violatedRule: null,
            requiresApproval: false,
            complianceMappings: [],
          }),
      });

      await noAgentShield.check('test');

      const body = JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body);
      expect(body.agentId).toBe('sdk-client');
    });

    it('returns redactedTokens when sensitive tokens are replaced', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            decision: 'allowed',
            reason: 'OK',
            violatedRule: null,
            requiresApproval: false,
            complianceMappings: [],
          }),
      });

      const result = await shield.check('Check custodial-id:xyz-999 balance');
      expect(result.redactedTokens).toBeDefined();
      expect(result.redactedTokens!.length).toBeGreaterThan(0);
    });

    it('returns undefined redactedTokens when no tokens replaced', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            decision: 'allowed',
            reason: 'OK',
            violatedRule: null,
            requiresApproval: false,
            complianceMappings: [],
          }),
      });

      const result = await shield.check('What is the weather today?');
      expect(result.redactedTokens).toBeUndefined();
    });
  });

  describe('wrap()', () => {
    const allowedResponse = {
      decision: 'allowed',
      reason: 'No violations',
      violatedRule: null,
      requiresApproval: false,
      complianceMappings: [],
    };

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

    function mockFetchSequence(responses: Array<{ ok: boolean; body: unknown }>) {
      let callCount = 0;
      global.fetch = jest.fn().mockImplementation(() => {
        const response = responses[callCount] ?? responses[responses.length - 1];
        callCount++;
        return Promise.resolve({
          ok: response.ok,
          status: response.ok ? 200 : 500,
          json: () => Promise.resolve(response.body),
        });
      });
    }

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

    it('does NOT invoke factory when policy blocks', async () => {
      mockFetchSequence([
        { ok: true, body: blockedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);

      const factory = jest.fn().mockResolvedValue('should not reach');

      await expect(shield.wrap(factory, 'Show me SSN records')).rejects.toThrow(ShieldBlockedError);

      expect(factory).not.toHaveBeenCalled();
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
        expect(blocked.violatedRule).toBe('PII Protection Guard');
        expect(blocked.complianceMappings).toHaveLength(1);
        expect(blocked.complianceMappings[0].regulation).toBe('GDPR');
        // Non-kill-switch blocks should default sessionRevoked to false so
        // consumers can branch on it without nullish checks.
        expect(blocked.sessionRevoked).toBe(false);
      }
    });

    it('propagates sessionRevoked: true when kill switch fires', async () => {
      const killSwitchResponse = {
        decision: 'blocked',
        reason: 'Partner compensation data is restricted',
        violatedRule: 'Unauthorized Partner Data Access',
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

      try {
        await shield.wrap(() => Promise.resolve('nope'), 'Pull partner compensation report');
        fail('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(ShieldBlockedError);
        const blocked = err as ShieldBlockedError;
        expect(blocked.sessionRevoked).toBe(true);
        expect(blocked.violatedRule).toBe('Unauthorized Partner Data Access');
      }
    });

    it('invokes factory on escalated decisions', async () => {
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
      const escalatedLine = emitted.find((l) => l.includes('Action escalated'));
      expect(escalatedLine).toBeDefined();
      expect(JSON.parse(escalatedLine as string)).toMatchObject({
        level: 'warn',
        msg: expect.stringContaining('Action escalated'),
      });
      logSpy.mockRestore();
    });

    it('calls log endpoint after check', async () => {
      mockFetchSequence([
        { ok: true, body: allowedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);

      await shield.wrap(() => Promise.resolve('ok'), 'Safe query');

      expect(global.fetch).toHaveBeenCalledTimes(2);
      expect((global.fetch as jest.Mock).mock.calls[0][0]).toBe(
        'http://localhost:3000/api/sdk/v1/check'
      );
      expect((global.fetch as jest.Mock).mock.calls[1][0]).toBe(
        'http://localhost:3000/api/sdk/v1/log'
      );
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
      const namedShield = new AgentShield({
        ...mockConfig,
        employeeName: 'Alex Park',
      });

      mockFetchSequence([
        { ok: true, body: allowedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);

      await namedShield.wrap(() => Promise.resolve('ok'), 'test');

      const logBody = JSON.parse((global.fetch as jest.Mock).mock.calls[1][1].body);
      expect(logBody.employeeName).toBe('Alex Park');
    });

    it('C2: wrap() uses a single requestId for both /check and /log', async () => {
      mockFetchSequence([
        { ok: true, body: allowedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);

      await shield.wrap(() => Promise.resolve('ok'), 'prompt');

      // Two calls: /check and /log
      expect(global.fetch).toHaveBeenCalledTimes(2);
      const checkBody = JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body);
      const logBody = JSON.parse((global.fetch as jest.Mock).mock.calls[1][1].body);

      expect(checkBody.requestId).toBeDefined();
      expect(logBody.requestId).toBeDefined();
      expect(checkBody.requestId).toBe(logBody.requestId); // SAME id
    });
  });
});

describe('ShieldBlockedError', () => {
  it('has correct name', () => {
    const err = new ShieldBlockedError('Blocked', 'rule-1', []);
    expect(err.name).toBe('ShieldBlockedError');
  });

  it('includes reason in message', () => {
    const err = new ShieldBlockedError('PII detected', 'PII Guard', []);
    expect(err.message).toContain('PII detected');
    expect(err.message).toContain('[G8R Shield BLOCKED]');
  });

  it('exposes violatedRule and complianceMappings', () => {
    const mappings = [
      {
        regulation: 'GDPR',
        controlId: 'Art. 5',
        controlName: 'Data Min',
        description: 'Desc',
      },
    ];
    const err = new ShieldBlockedError('reason', 'rule-1', mappings);
    expect(err.violatedRule).toBe('rule-1');
    expect(err.complianceMappings).toEqual(mappings);
  });

  it('is an instance of Error', () => {
    const err = new ShieldBlockedError('reason', null, []);
    expect(err).toBeInstanceOf(Error);
  });

  it('defaults sessionRevoked to false when not provided', () => {
    const err = new ShieldBlockedError('reason', 'rule', []);
    expect(err.sessionRevoked).toBe(false);
  });

  it('stores sessionRevoked: true when explicitly set', () => {
    const err = new ShieldBlockedError('kill switch', 'Partner Data', [], true);
    expect(err.sessionRevoked).toBe(true);
  });
});
