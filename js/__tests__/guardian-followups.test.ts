/**
 * Guardian follow-ups for the per-tenant credential change.
 *
 * HTTPS is required on both console and PEP URLs. Loopback is refused on
 * both unless G8R_ALLOW_INSECURE_LOCALHOST is set, and that override never
 * permits plaintext to a non-loopback host. Blank tenant ids are rejected.
 * Provider failures are not chained. Two tenants checked concurrently keep
 * their own credentials. The node:fs read is lazy so a browser or edge
 * bundle does not fail resolving it.
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from 'node:util';

import * as esbuild from 'esbuild';

import { AgentShield, ShieldConnectionError } from '../src/index';
import { tenantId, type TenantId } from '../src/ids';

const PEP = 'https://pep.test.example';
const CONSOLE = 'https://console.test.example';

function shield(overrides: Partial<ConstructorParameters<typeof AgentShield>[0]> = {}) {
  return new AgentShield({
    pepUrl: PEP,
    consoleUrl: CONSOLE,
    apiKey: 'k',
    tenantId: tenantId('tenant-a'),
    ...overrides,
  });
}

describe('guardian follow-ups', () => {
  const previousAllow = process.env.G8R_ALLOW_INSECURE_LOCALHOST;

  afterEach(() => {
    if (previousAllow === undefined) delete process.env.G8R_ALLOW_INSECURE_LOCALHOST;
    else process.env.G8R_ALLOW_INSECURE_LOCALHOST = previousAllow;
  });

  it('rejects a blank or whitespace tenantId even if the brand is cast', () => {
    for (const value of [' ', '\t', '\n', ' \t ']) {
      expect(() => shield({ tenantId: value as TenantId })).toThrow(/tenantId is required/);
    }
  });

  it('requires https for consoleUrl and pepUrl', () => {
    expect(() => shield({ consoleUrl: 'http://console.example.test' })).toThrow(/https/);
    expect(() => shield({ pepUrl: 'http://pep.example.test' })).toThrow(/https/);
    expect(() => shield({ consoleUrl: '   ' })).toThrow(/consoleUrl/);
  });

  it('rejects loopback consoleUrl unless the localhost dev override is set', () => {
    for (const consoleUrl of [
      'http://localhost:3000',
      'https://localhost:3000',
      'https://127.0.0.1',
      'http://[::1]:3000',
    ]) {
      expect(() => shield({ consoleUrl })).toThrow(/localhost/);
    }

    process.env.G8R_ALLOW_INSECURE_LOCALHOST = '1';
    const local = shield({
      pepUrl: 'http://localhost:8083',
      consoleUrl: 'http://127.0.0.1:3000',
    });
    expect(local.toString()).toContain('http://localhost:8083');
    expect(local.toString()).toContain('http://127.0.0.1:3000');

    const ipv6 = shield({
      pepUrl: 'http://[::1]:8083',
      consoleUrl: 'https://localhost:8443',
    });
    expect(ipv6.toString()).toContain('http://[::1]:8083');

    expect(() => shield({ pepUrl: 'http://pep.example.test' })).toThrow(/https/);
    expect(() => shield({ consoleUrl: 'http://console.example.test' })).toThrow(/https/);

    process.env.G8R_ALLOW_INSECURE_LOCALHOST = '0';
    expect(() => shield({ consoleUrl: 'http://localhost:3000' })).toThrow(/localhost/);
  });

  it('does not chain a credentialProvider error that may contain the credential', async () => {
    const secret = 'provider-jwt-do-not-echo';
    const client = shield({
      apiKey: undefined,
      credentialProvider: () => Promise.reject(new Error(secret)),
    });

    let thrown: ShieldConnectionError | undefined;
    try {
      await client.check('hi', { log: false });
    } catch (err) {
      thrown = err as ShieldConnectionError;
    }
    expect(thrown).toBeInstanceOf(ShieldConnectionError);
    expect(thrown!.cause).toBeUndefined();
    expect(thrown!.message).not.toContain(secret);
    expect(thrown!.stack ?? '').not.toContain(secret);
    expect(inspect(thrown)).not.toContain(secret);
  });

  it('keeps two tenants credentials apart when checks run concurrently', async () => {
    const scratch = mkdtempSync(join(tmpdir(), 'g8r-conc-'));
    try {
      const credFile = join(scratch, 'tenant-a');
      writeFileSync(credFile, 'cred-tenant-a\n', 'utf8');
      process.env.TENANT_B_CREDENTIAL = 'cred-tenant-b';
      const clientA = shield({
        apiKey: undefined,
        tenantId: tenantId('tenant-a'),
        credentialFile: credFile,
      });
      const clientB = shield({
        apiKey: undefined,
        tenantId: tenantId('tenant-b'),
        credentialEnv: 'TENANT_B_CREDENTIAL',
      });

      const seen: Array<{ auth: string; tenant: string }> = [];
      global.fetch = jest.fn().mockImplementation(async (_url: string, init: RequestInit) => {
        const body = JSON.parse(String(init.body)) as { tenantId: string };
        const headers = init.headers as Record<string, string>;
        seen.push({ auth: headers.Authorization, tenant: body.tenantId });
        await new Promise((resolve) => setImmediate(resolve));
        return {
          ok: true,
          status: 200,
          json: () =>
            Promise.resolve({
              decision: 'allowed',
              reason: 'ok',
              violatedRule: null,
              requiresApproval: false,
              complianceMappings: [],
            }),
          text: () => Promise.resolve('{}'),
        };
      });

      await Promise.all([
        ...Array.from({ length: 12 }, () => clientA.check('a', { log: false })),
        ...Array.from({ length: 12 }, () => clientB.check('b', { log: false })),
      ]);

      expect(seen).toHaveLength(24);
      for (const call of seen) {
        if (call.tenant === 'tenant-a') {
          expect(call.auth).toBe('Bearer cred-tenant-a');
        } else if (call.tenant === 'tenant-b') {
          expect(call.auth).toBe('Bearer cred-tenant-b');
        } else {
          throw new Error(`unexpected tenant ${call.tenant}`);
        }
      }
    } finally {
      delete process.env.TENANT_B_CREDENTIAL;
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  it('browser and edge bundles do not statically import node:fs', async () => {
    // node:crypto and node:util stay external: they are a pre-existing
    // receipt import, not this follow-up. node:fs must not need that
    // treatment — a browser or edge bundler has to be able to skip it.
    for (const platform of ['browser', 'neutral'] as const) {
      const result = await esbuild.build({
        absWorkingDir: join(__dirname, '..'),
        entryPoints: ['src/index.ts'],
        bundle: true,
        platform,
        format: 'esm',
        write: false,
        logLevel: 'silent',
        external: ['ts-pattern', 'node:crypto', 'node:util'],
      });
      const output = result.outputFiles.map((file) => file.text).join('\n');
      // A static import is evaluated at load and breaks the bundle. A guarded
      // __require('node:fs') inside the file reader is the lazy fallback
      // (same shape as node:async_hooks) and is allowed.
      expect(output).not.toMatch(/from\s+['"]node:fs['"]/);
      expect(output).not.toMatch(/^\s*import\s.*node:fs/m);
    }
  });
});
