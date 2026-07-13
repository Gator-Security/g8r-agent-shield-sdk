/**
 * Sub-agent lineage tests.
 *
 * The 0.4.0 wire contract gained two optional, additive fields on /check and
 * /log — `sessionId` (a stable id for one logical agent run) and
 * `parentAgents` (the ancestor agent-id chain, ROOT-first / immediate-parent
 * last). This suite pins how the SDK auto-propagates that lineage through
 * NESTED wrap() calls with no manual instrumentation, and proves the additive
 * fields stay backward-compatible (absent on a plain, un-nested call).
 *
 * All governance HTTP is mocked. The fetch mock always ALLOWS (unless a test
 * asks for a block), so wrap() proceeds and runs its factory — which is where
 * the nested lineage propagation happens.
 */

import { AgentShield, ShieldBlockedError } from '../src/index';
import { tenantId } from '../src/ids';
import { getGovernanceContext, asyncContextIsolated } from '../src/context';

const baseConfig = {
  consoleUrl: 'http://localhost:3000',
  apiKey: 'sk-test',
  tenantId: tenantId('acme-inc'),
};

const allowed = {
  decision: 'allowed',
  reason: 'ok',
  violatedRule: null,
  requiresApproval: false,
  complianceMappings: [],
};

const blocked = {
  decision: 'blocked',
  reason: 'nope',
  violatedRule: 'some-rule',
  requiresApproval: false,
  complianceMappings: [],
};

/** URL-aware fetch mock: /check → the given decision, everything else → a log entry. */
function mockFetch(decision: unknown = allowed): void {
  global.fetch = jest.fn().mockImplementation((url: string) => {
    const isCheck = String(url).endsWith('/check');
    const body = isCheck ? decision : { id: 'log-entry', decision: 'allowed', timestamp: 't' };
    return Promise.resolve({
      ok: true,
      status: 200,
      json: () => Promise.resolve(body),
      text: () => Promise.resolve(JSON.stringify(body)),
    });
  });
}

/** Parsed request bodies for every call to an endpoint suffix, in call order. */
function bodiesFor(suffix: string): any[] {
  return (global.fetch as jest.Mock).mock.calls
    .filter(([url]) => String(url).endsWith(suffix))
    .map(([, init]) => JSON.parse(init.body));
}

const checkBodies = (): any[] => bodiesFor('/check');
const logBodies = (): any[] => bodiesFor('/log');

/** Force a macrotask boundary so concurrent chains actually interleave. */
const tick = (): Promise<void> => new Promise((res) => setTimeout(res, 0));

describe('sub-agent lineage', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('top-level wrap()', () => {
    it('sends a fresh sessionId and an empty parent chain', async () => {
      mockFetch();
      const shield = new AgentShield({ ...baseConfig, agentId: 'root' });

      await shield.wrap(() => Promise.resolve('ok'), 'hello');

      const [check] = checkBodies();
      expect(typeof check.sessionId).toBe('string');
      expect(check.sessionId.length).toBeGreaterThan(0);
      // Empty ancestor chain at the top → parentAgents omitted (present-only-when-meaningful).
      expect(check.parentAgents ?? []).toEqual([]);
    });

    it('mints a DISTINCT session per independent top-level wrap()', async () => {
      mockFetch();
      const shield = new AgentShield({ ...baseConfig, agentId: 'root' });

      await shield.wrap(() => Promise.resolve('a'), 'a');
      await shield.wrap(() => Promise.resolve('b'), 'b');

      const [c1, c2] = checkBodies();
      expect(c1.sessionId).not.toBe(c2.sessionId);
    });

    it('sends the lineage on /log as well as /check', async () => {
      mockFetch();
      const shield = new AgentShield({ ...baseConfig, agentId: 'root' });

      await shield.wrap(() => Promise.resolve('ok'), 'hello');

      const [check] = checkBodies();
      const [logEntry] = logBodies();
      expect(logEntry.sessionId).toBe(check.sessionId);
    });
  });

  describe('nested wrap()', () => {
    it('a nested call inherits the SAME session and parentAgents === [parentAgentId]', async () => {
      mockFetch();
      const parent = new AgentShield({ ...baseConfig, agentId: 'parent-agent' });
      const child = new AgentShield({ ...baseConfig, agentId: 'child-agent' });

      await parent.wrap(async () => {
        await child.wrap(() => Promise.resolve('inner'), 'inner');
        return 'outer';
      }, 'outer');

      const [outerCheck, innerCheck] = checkBodies();
      expect(innerCheck.sessionId).toBe(outerCheck.sessionId);
      expect(innerCheck.parentAgents).toEqual(['parent-agent']);
      // The outer (top-level) call still has no ancestors.
      expect(outerCheck.parentAgents ?? []).toEqual([]);
    });

    it('a nested call also carries the lineage on its /log', async () => {
      mockFetch();
      const parent = new AgentShield({ ...baseConfig, agentId: 'parent-agent' });
      const child = new AgentShield({ ...baseConfig, agentId: 'child-agent' });

      await parent.wrap(async () => {
        await child.wrap(() => Promise.resolve('inner'), 'inner');
        return 'outer';
      }, 'outer');

      const logs = logBodies();
      const innerLog = logs[logs.length - 1];
      expect(typeof innerLog.sessionId).toBe('string');
      expect(innerLog.parentAgents).toEqual(['parent-agent']);
    });

    it('propagates a ROOT-first chain two levels deep => [root, mid]', async () => {
      mockFetch();
      const root = new AgentShield({ ...baseConfig, agentId: 'root' });
      const mid = new AgentShield({ ...baseConfig, agentId: 'mid' });
      const leaf = new AgentShield({ ...baseConfig, agentId: 'leaf' });

      await root.wrap(async () => {
        await mid.wrap(async () => {
          await leaf.wrap(() => Promise.resolve('x'), 'leaf');
          return 'mid';
        }, 'mid');
        return 'root';
      }, 'root');

      const checks = checkBodies();
      const leafCheck = checks[checks.length - 1];
      expect(leafCheck.parentAgents).toEqual(['root', 'mid']); // root-first, immediate-parent last
      // All three hops share one session.
      expect(new Set(checks.map((c) => c.sessionId)).size).toBe(1);
    });
  });

  describe('run()', () => {
    it('groups every wrap()/check() inside it under ONE session', async () => {
      mockFetch();
      const shield = new AgentShield({ ...baseConfig, agentId: 'root' });

      await shield.run(async () => {
        await shield.wrap(() => Promise.resolve('1'), 'turn-1');
        await shield.wrap(() => Promise.resolve('2'), 'turn-2');
        await shield.check('turn-3', { log: false });
      });

      const checks = checkBodies();
      expect(checks).toHaveLength(3);
      expect(new Set(checks.map((c) => c.sessionId)).size).toBe(1);
      // The sibling wraps are each top-level WITHIN the run → empty ancestor chains.
      expect(checks[0].parentAgents ?? []).toEqual([]);
      expect(checks[1].parentAgents ?? []).toEqual([]);
    });

    it('honors an explicit sessionId', async () => {
      mockFetch();
      const shield = new AgentShield({ ...baseConfig, agentId: 'root' });

      await shield.run(
        async () => {
          await shield.wrap(() => Promise.resolve('x'), 'p');
        },
        { sessionId: 'sess-explicit-123' }
      );

      const [check] = checkBodies();
      expect(check.sessionId).toBe('sess-explicit-123');
    });
  });

  describe('ambient store restoration', () => {
    it('sets the extended scope inside the factory and restores it after wrap() resolves', async () => {
      mockFetch();
      const shield = new AgentShield({ ...baseConfig, agentId: 'root' });

      expect(getGovernanceContext()).toBeUndefined();

      let insideChain: string[] | undefined;
      let insideSession: string | undefined;
      await shield.wrap(() => {
        const ctx = getGovernanceContext();
        insideChain = ctx?.agentChain;
        insideSession = ctx?.sessionId;
        return Promise.resolve('ok');
      }, 'p');

      // Inside the factory the extended scope was active (chain ends with this agent)...
      expect(insideChain).toEqual(['root']);
      expect(typeof insideSession).toBe('string');
      // ...and it is gone once wrap() returns.
      expect(getGovernanceContext()).toBeUndefined();
    });

    it('restores the ambient context even when wrap() throws (deny path)', async () => {
      mockFetch(blocked);
      const shield = new AgentShield({ ...baseConfig, agentId: 'root' });

      expect(getGovernanceContext()).toBeUndefined();
      await expect(shield.wrap(() => Promise.resolve('x'), 'p')).rejects.toBeInstanceOf(
        ShieldBlockedError
      );
      expect(getGovernanceContext()).toBeUndefined();
    });

    it('restores the ambient context when the factory itself throws', async () => {
      mockFetch();
      const shield = new AgentShield({ ...baseConfig, agentId: 'root' });

      await expect(
        shield.wrap(() => Promise.reject(new Error('boom')), 'p')
      ).rejects.toThrow('boom');
      expect(getGovernanceContext()).toBeUndefined();
    });
  });

  describe('backward compatibility', () => {
    it('a lone check() with no session/nesting OMITS both lineage fields', async () => {
      mockFetch();
      const shield = new AgentShield({ ...baseConfig, agentId: 'root' });

      await shield.check('hello', { log: false });

      const [check] = checkBodies();
      expect(check).not.toHaveProperty('sessionId');
      expect(check).not.toHaveProperty('parentAgents');
    });

    it('a per-instance configured sessionId IS reported by a standalone check()', async () => {
      mockFetch();
      const shield = new AgentShield({ ...baseConfig, sessionId: 'sess-config-1' });

      await shield.check('hello', { log: false });

      const [check] = checkBodies();
      expect(check.sessionId).toBe('sess-config-1');
      // Still no ancestor chain — a standalone check does not open a nested scope.
      expect(check).not.toHaveProperty('parentAgents');
    });

    it('an ambient session overrides the per-instance configured session', async () => {
      mockFetch();
      const shield = new AgentShield({
        ...baseConfig,
        sessionId: 'sess-config-1',
        agentId: 'root',
      });

      await shield.run(
        async () => {
          await shield.check('x', { log: false });
        },
        { sessionId: 'sess-ambient-2' }
      );

      const [check] = checkBodies();
      expect(check.sessionId).toBe('sess-ambient-2');
    });
  });

  describe('async isolation', () => {
    it('does not cross-contaminate lineage across concurrent async chains', async () => {
      // The isolation guarantee requires true AsyncLocalStorage; assert we run
      // on that path (Node with node:async_hooks) rather than the fallback.
      expect(asyncContextIsolated).toBe(true);

      mockFetch();
      const root = new AgentShield({ ...baseConfig, agentId: 'root' });
      const child = new AgentShield({ ...baseConfig, agentId: 'child' });

      // Two independent agent runs, each root→child, interleaved on the loop.
      async function run(tag: string): Promise<string> {
        return root.wrap(async () => {
          await tick(); // yield so the sibling chain interleaves here
          await child.wrap(async () => {
            await tick();
            return tag;
          }, `child-${tag}`);
          return tag;
        }, `root-${tag}`);
      }

      await Promise.all([run('A'), run('B')]);

      const checks = checkBodies();
      const byInput = (needle: string): any =>
        checks.find((c) => String(c.input).includes(needle));
      const rootA = byInput('root-A');
      const rootB = byInput('root-B');
      const childA = byInput('child-A');
      const childB = byInput('child-B');

      // Each child inherited ITS OWN root's session, despite interleaving.
      expect(childA.sessionId).toBe(rootA.sessionId);
      expect(childB.sessionId).toBe(rootB.sessionId);
      // The two runs never shared a session — no cross-contamination.
      expect(rootA.sessionId).not.toBe(rootB.sessionId);
      expect(childA.sessionId).not.toBe(childB.sessionId);
      // Ancestry stayed correct on both chains.
      expect(childA.parentAgents).toEqual(['root']);
      expect(childB.parentAgents).toEqual(['root']);
    });
  });
});
