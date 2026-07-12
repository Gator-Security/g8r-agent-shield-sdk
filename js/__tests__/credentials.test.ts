/**
 * Credential-provider behavior (v2 Console auth).
 *
 * The Console accepts either the deployment shared secret or a verified OIDC
 * JWT in the same `Authorization: Bearer` header. A static `apiKey` covers
 * the former; `credentialProvider` covers the latter — it is awaited fresh on
 * EVERY /check and /log request so short-lived workload-identity JWTs never
 * go stale inside a long-lived shield instance. The two are mutually
 * exclusive, a provider rejection fails CLOSED (the wrap() LLM factory must
 * never run), and the resolved credential is never logged.
 */

import { AgentShield, ShieldConnectionError } from '../src/index';
import { tenantId } from '../src/ids';

const providerConfig = {
  consoleUrl: 'http://localhost:3000',
  tenantId: tenantId('acme-inc'),
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

describe('credentialProvider', () => {
  beforeEach(() => {
    jest.restoreAllMocks();
    delete process.env.G8R_CONSOLE_URL;
    delete process.env.G8R_API_KEY;
  });

  describe('construction', () => {
    it('throws when BOTH apiKey and credentialProvider are passed', () => {
      expect(
        () =>
          new AgentShield({
            ...providerConfig,
            apiKey: 'sk-static',
            credentialProvider: () => 'jwt',
          })
      ).toThrow(/mutually exclusive/);
    });

    it('satisfies the credential requirement on its own (no apiKey, no env)', () => {
      expect(
        () => new AgentShield({ ...providerConfig, credentialProvider: () => 'jwt' })
      ).not.toThrow();
    });

    it('is NOT invoked at construction time (only per request)', () => {
      const provider = jest.fn().mockResolvedValue('jwt');
      new AgentShield({ ...providerConfig, credentialProvider: provider });
      expect(provider).not.toHaveBeenCalled();
    });
  });

  describe('per-request resolution', () => {
    it('is awaited fresh per request — /check and /log each carry the value current at THEIR call', async () => {
      mockFetchSequence([
        { ok: true, body: allowedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);
      const provider = jest
        .fn()
        .mockResolvedValueOnce('jwt-1')
        .mockResolvedValueOnce('jwt-2');
      const shield = new AgentShield({ ...providerConfig, credentialProvider: provider });

      await shield.check('hi'); // log defaults to true → /check then /log

      expect(provider).toHaveBeenCalledTimes(2);
      const calls = (global.fetch as jest.Mock).mock.calls;
      expect(calls[0][0]).toBe('http://localhost:3000/api/sdk/v1/check');
      expect(calls[0][1].headers.Authorization).toBe('Bearer jwt-1');
      expect(calls[1][0]).toBe('http://localhost:3000/api/sdk/v1/log');
      expect(calls[1][1].headers.Authorization).toBe('Bearer jwt-2');
    });

    it('wrap() also resolves per endpoint (a token rotated mid-flight is picked up on /log)', async () => {
      mockFetchSequence([
        { ok: true, body: allowedResponse },
        { ok: true, body: { id: 'log-entry' } },
      ]);
      const provider = jest
        .fn()
        .mockResolvedValueOnce('jwt-check')
        .mockResolvedValueOnce('jwt-log');
      const shield = new AgentShield({ ...providerConfig, credentialProvider: provider });

      await shield.wrap(() => Promise.resolve('ok'), 'hi');

      expect(provider).toHaveBeenCalledTimes(2);
      const calls = (global.fetch as jest.Mock).mock.calls;
      expect(calls[0][1].headers.Authorization).toBe('Bearer jwt-check');
      expect(calls[1][1].headers.Authorization).toBe('Bearer jwt-log');
    });

    it('supports a synchronous provider (plain string return)', async () => {
      mockFetchSequence([{ ok: true, body: allowedResponse }]);
      const shield = new AgentShield({
        ...providerConfig,
        credentialProvider: () => 'sync-jwt',
      });
      await shield.check('hi', { log: false });
      const [, init] = (global.fetch as jest.Mock).mock.calls[0];
      expect(init.headers.Authorization).toBe('Bearer sync-jwt');
    });

    it('ignores the G8R_API_KEY env fallback when a provider is configured', async () => {
      process.env.G8R_API_KEY = 'sk-from-env';
      mockFetchSequence([{ ok: true, body: allowedResponse }]);
      const shield = new AgentShield({
        ...providerConfig,
        credentialProvider: () => 'jwt-from-provider',
      });
      await shield.check('hi', { log: false });
      const [, init] = (global.fetch as jest.Mock).mock.calls[0];
      expect(init.headers.Authorization).toBe('Bearer jwt-from-provider');
    });

    it('resolves ONCE per request — the transient-network retry reuses the same credential', async () => {
      let fetchCall = 0;
      global.fetch = jest.fn().mockImplementation(() => {
        fetchCall++;
        if (fetchCall === 1) {
          return Promise.reject(new Error('ECONNREFUSED'));
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(allowedResponse),
          text: () => Promise.resolve('{}'),
        });
      });
      const provider = jest.fn().mockResolvedValue('jwt-stable');
      const shield = new AgentShield({ ...providerConfig, credentialProvider: provider });

      await shield.check('hi', { log: false });

      expect(global.fetch).toHaveBeenCalledTimes(2); // original + one retry
      expect(provider).toHaveBeenCalledTimes(1); // per request, not per attempt
    });
  });

  describe('rejection fails closed', () => {
    it('wrap() never invokes the LLM factory — no request leaves the process', async () => {
      global.fetch = jest.fn();
      const provider = jest.fn().mockRejectedValue(new Error('sts endpoint unavailable'));
      const shield = new AgentShield({ ...providerConfig, credentialProvider: provider });
      const factory = jest.fn().mockResolvedValue('should not reach');

      await expect(shield.wrap(factory, 'hi')).rejects.toBeInstanceOf(ShieldConnectionError);
      expect(factory).not.toHaveBeenCalled();
      expect(global.fetch).not.toHaveBeenCalled();
      expect(provider).toHaveBeenCalledTimes(1); // never retried — provider retry policy is the provider's
    });

    it('surfaces as ShieldConnectionError naming the provider, with the rejection on .cause', async () => {
      global.fetch = jest.fn();
      const rejection = new Error('sts endpoint unavailable');
      const shield = new AgentShield({
        ...providerConfig,
        credentialProvider: () => Promise.reject(rejection),
      });

      let thrown: ShieldConnectionError | undefined;
      try {
        await shield.check('hi', { log: false });
      } catch (e) {
        thrown = e as ShieldConnectionError;
      }
      expect(thrown).toBeInstanceOf(ShieldConnectionError);
      expect(thrown!.consoleUrl).toBe('http://localhost:3000');
      expect(thrown!.cause).toBe(rejection);
      expect(thrown!.message).toContain('credentialProvider');
      // The message stays generic — the provider's own error text (which
      // could carry anything) lives on .cause only.
      expect(thrown!.message).not.toContain('sts endpoint unavailable');
    });

    it('a rejection on the audit (/log) path is swallowed like any /log failure — the decision path proceeds', async () => {
      // Parity with the Python SDK and with how a real 401 from /log behaves:
      // the swallow-all /log contract ("a logging outage must never break the
      // user's LLM call") covers provider failures on this leg too. Fail-closed
      // protection lives on the /check leg, which already succeeded here.
      mockFetchSequence([{ ok: true, body: allowedResponse }]);
      const provider = jest
        .fn()
        .mockResolvedValueOnce('jwt-1')
        .mockRejectedValueOnce(new Error('token source went away'));
      const shield = new AgentShield({ ...providerConfig, credentialProvider: provider });
      const factory = jest.fn().mockResolvedValue('llm-result');

      await expect(shield.wrap(factory, 'hi')).resolves.toBe('llm-result');
      expect(factory).toHaveBeenCalledTimes(1);
      expect(global.fetch).toHaveBeenCalledTimes(1); // /check only — /log aborted pre-send, silently
    });
  });

  describe('credential hygiene', () => {
    it('never emits the resolved credential through the structured logger', async () => {
      const logSpy = jest.spyOn(console, 'log').mockImplementation();
      global.fetch = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));
      const shield = new AgentShield({
        ...providerConfig,
        credentialProvider: () => 'super-secret-oidc-jwt',
      });

      await expect(shield.check('hi', { log: false })).rejects.toBeInstanceOf(
        ShieldConnectionError
      );

      const emitted = logSpy.mock.calls.map(([line]) => String(line));
      expect(emitted.length).toBeGreaterThan(0); // the failure itself IS logged
      expect(emitted.every((l) => !l.includes('super-secret-oidc-jwt'))).toBe(true);
      logSpy.mockRestore();
    });
  });
});
