/**
 * Parity / contract test.
 *
 * The canonical surface is a single synchronized release across the Python and
 * TypeScript SDKs. "Are these two in parity?" must be answerable by a
 * version-equality check plus a wire-contract check in CI — that is the whole
 * point of a canonical surface.
 *
 * This test pins the TypeScript side of the contract:
 *   1. The exported VERSION matches package.json AND the canonical 0.2.0.
 *   2. The User-Agent identifies the TS SDK + version (mirror of
 *      Python's `g8r-shield-python/{version}`).
 *   3. The /check and /log wire payloads carry EXACTLY the canonical field set.
 *   4. The defaulted-not-required fields resolve to the canonical defaults.
 *   5. employeeName is on /log only, never on /check.
 *
 * The Python contract test asserts the same field sets against the same
 * canonical version, so a drift on either side breaks CI.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { AgentShield, VERSION } from '../src/index';
import { tenantId } from '../src/ids';

const CANONICAL_VERSION = '0.2.0';

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

  it('exports VERSION equal to the canonical 0.2.0', () => {
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

  it('/log payload carries EXACTLY the canonical field set', async () => {
    mockFetch([allowedResponse, { id: 'log' }]);
    const shield = new AgentShield({
      consoleUrl: 'http://c',
      apiKey: 'k',
      tenantId: tenantId('acme'),
    });
    await shield.wrap(() => Promise.resolve('ok'), 'hi');
    const body = JSON.parse((global.fetch as jest.Mock).mock.calls[1][1].body);
    expect(Object.keys(body).sort()).toEqual(CANONICAL_LOG_FIELDS);
  });

  it('resolves the canonical defaulted-not-required field values', async () => {
    mockFetch([allowedResponse]);
    const shield = new AgentShield({
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
          consoleUrl: 'http://c',
          apiKey: 'k',
          tenantId: '' as ReturnType<typeof tenantId>,
        })
    ).toThrow(/tenantId is required/);
  });

  it('uses the same agentId on /check and /log (construction-time normalization)', async () => {
    mockFetch([allowedResponse, { id: 'log' }]);
    const shield = new AgentShield({
      consoleUrl: 'http://c',
      apiKey: 'k',
      tenantId: tenantId('acme'),
      agentId: 'my-agent',
    });
    await shield.wrap(() => Promise.resolve('ok'), 'hi');
    const checkBody = JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body);
    const logBody = JSON.parse((global.fetch as jest.Mock).mock.calls[1][1].body);
    expect(checkBody.agentId).toBe('my-agent');
    expect(logBody.agentId).toBe('my-agent');
    expect(checkBody.agentId).toBe(logBody.agentId);
  });
});
