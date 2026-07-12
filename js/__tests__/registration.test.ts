/**
 * Trust-on-first-use (TOFU) pending-registration awareness.
 *
 * On a v2 Console the FIRST call from an unknown agentId auto-creates a
 * pending registration in the Console's Approvals queue. In `block`
 * pending-agent mode those calls return decision 'blocked' with
 * requiresApproval true until an admin approves the agent — and on v2 that
 * conjunction occurs ONLY for pending registrations. The SDK derives
 * `isPendingRegistration` from it CLIENT-SIDE (it is not a wire field), and
 * never parses reason strings: reasons are for humans.
 */

import { AgentShield, ShieldBlockedError } from '../src/index';
import { tenantId } from '../src/ids';

const mockConfig = {
  consoleUrl: 'http://localhost:3000',
  apiKey: 'sk-shield-test-key',
  tenantId: tenantId('acme-inc'),
  agentId: 'brand-new-agent',
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

/** A /check response with the given decision/requiresApproval pair. */
function decisionResponse(decision: string, requiresApproval: boolean, reason = 'r') {
  return {
    decision,
    reason,
    violatedRule: null,
    requiresApproval,
    complianceMappings: [],
  };
}

describe('isPendingRegistration', () => {
  let shield: AgentShield;

  beforeEach(() => {
    shield = new AgentShield(mockConfig);
    jest.restoreAllMocks();
  });

  describe('truth table (decision × requiresApproval → derived flag)', () => {
    // Present-only-when-true, like sessionRevoked/redactedTokens: the flag is
    // set for EXACTLY the pending conjunction and undefined everywhere else.
    const cases: Array<[string, boolean, true | undefined]> = [
      ['blocked', true, true], // the pending signal (block mode)
      ['blocked', false, undefined], // policy block, or admin-denied agent
      ['escalated', true, undefined], // escalation approval ≠ registration approval
      ['escalated', false, undefined],
      ['allowed', true, undefined],
      ['allowed', false, undefined],
    ];

    it.each(cases)(
      'decision=%s, requiresApproval=%s → %s',
      async (decision, requiresApproval, expected) => {
        mockFetchSequence([{ ok: true, body: decisionResponse(decision, requiresApproval) }]);
        const result = await shield.check('hi', { log: false });
        expect(result.isPendingRegistration).toBe(expected);
      }
    );
  });

  describe('reason strings are never parsed', () => {
    it('a "pending"-sounding reason WITHOUT the conjunction is not pending', async () => {
      mockFetchSequence([
        {
          ok: true,
          body: decisionResponse('blocked', false, 'agent registration pending in Approvals queue'),
        },
      ]);
      const result = await shield.check('hi', { log: false });
      expect(result.isPendingRegistration).toBeUndefined();
    });

    it('an unrelated reason WITH the conjunction is still pending', async () => {
      mockFetchSequence([
        { ok: true, body: decisionResponse('blocked', true, 'totally unrelated wording') },
      ]);
      const result = await shield.check('hi', { log: false });
      expect(result.isPendingRegistration).toBe(true);
    });
  });

  describe('wrap() exposure via ShieldBlockedError', () => {
    it('a pending block fails closed and sets isPendingRegistration on the error', async () => {
      mockFetchSequence([
        {
          ok: true,
          body: decisionResponse('blocked', true, 'agent pending approval in the Approvals queue'),
        },
        { ok: true, body: { id: 'log-entry' } },
      ]);

      const factory = jest.fn().mockResolvedValue('should not reach');
      let thrown: ShieldBlockedError | undefined;
      try {
        await shield.wrap(factory, 'hi');
      } catch (e) {
        thrown = e as ShieldBlockedError;
      }

      expect(factory).not.toHaveBeenCalled();
      expect(thrown).toBeInstanceOf(ShieldBlockedError);
      expect(thrown!.isPendingRegistration).toBe(true);
    });

    it('an admin-denied agent surfaces as an ordinary block (isPendingRegistration false)', async () => {
      mockFetchSequence([
        { ok: true, body: decisionResponse('blocked', false, 'agent registration denied') },
        { ok: true, body: { id: 'log-entry' } },
      ]);

      let thrown: ShieldBlockedError | undefined;
      try {
        await shield.wrap(() => Promise.resolve('x'), 'hi');
      } catch (e) {
        thrown = e as ShieldBlockedError;
      }

      expect(thrown).toBeInstanceOf(ShieldBlockedError);
      expect(thrown!.isPendingRegistration).toBe(false);
    });
  });
});

describe('ShieldBlockedError.isPendingRegistration', () => {
  it('defaults to false when not provided (additive — existing constructions unchanged)', () => {
    const err = new ShieldBlockedError('blocked', 'reason', 'rule', []);
    expect(err.isPendingRegistration).toBe(false);
  });

  it('stores true when explicitly set', () => {
    const err = new ShieldBlockedError('blocked', 'pending', null, [], false, true);
    expect(err.isPendingRegistration).toBe(true);
  });
});
