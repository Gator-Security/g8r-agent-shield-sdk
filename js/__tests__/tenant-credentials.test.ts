/**
 * Per-tenant credential contract.
 *
 * The SDK has no shared or default secret. Each client must be given that
 * tenant's or agent's credential at runtime — an explicit value, a file path
 * (for example a 1Password or broker mount), or the name of an env var — and
 * must refuse to start without one. The credential is never logged.
 */

import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';

import { AgentShield, ShieldConnectionError } from '../src/index';
import { tenantId } from '../src/ids';

const PEP = 'https://pep.test.example';
const CONSOLE = 'https://console.test.example';

// Names of the removed deployment-wide secret. Split so this file is not
// itself a copy of a credential, and so the scan needles stay obvious.
const SHARED_SECRET_NAMES = ['GF_SDK_' + 'SHARED_SECRET', 'G8R_' + 'API_KEY'] as const;
const HARDCODED_SECRET = /['"]sk-[^'"]+['"]/;

const allowedResponse = {
  decision: 'allowed',
  reason: 'No violations',
  violatedRule: null,
  requiresApproval: false,
  complianceMappings: [],
};

function productionFiles(root: string): string[] {
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.name.endsWith('.py') || entry.name.endsWith('.ts')) {
        files.push(full);
      }
    }
  };
  walk(join(root, 'python', 'g8r_shield'));
  walk(join(root, 'js', 'src'));
  files.push(
    join(root, 'README.md'),
    join(root, 'python', 'README.md'),
    join(root, 'python', 'example_bedrock.py'),
    join(root, 'js', 'README.md'),
  );
  return files;
}

describe('tenant credentials', () => {
  const envSnapshot = { ...process.env };
  let scratch = '';

  beforeEach(() => {
    scratch = mkdtempSync(join(tmpdir(), 'g8r-cred-'));
    jest.restoreAllMocks();
  });

  afterEach(() => {
    for (const key of Object.keys(process.env)) {
      if (envSnapshot[key] === undefined) delete process.env[key];
    }
    for (const [key, value] of Object.entries(envSnapshot)) {
      if (value !== undefined) process.env[key] = value;
    }
    if (scratch) rmSync(scratch, { recursive: true, force: true });
  });

  it('no credential throws a clear error', () => {
    delete process.env.G8R_TENANT_CREDENTIAL;
    delete process.env.G8R_TENANT_CREDENTIAL_FILE;
    process.env[SHARED_SECRET_NAMES[1]] = 'shared-deployment-secret';

    expect(() =>
      new AgentShield({
        pepUrl: PEP,
        consoleUrl: CONSOLE,
        tenantId: tenantId('tenant-a'),
      }),
    ).toThrow(/per-tenant credential/);

    try {
      new AgentShield({
        pepUrl: PEP,
        consoleUrl: CONSOLE,
        tenantId: tenantId('tenant-a'),
      });
    } catch (err) {
      const message = String(err);
      expect(message).not.toContain('shared-deployment-secret');
      expect(message).toContain('no shared or default');
    }
  });

  it('two clients with different tenant credentials send their own', async () => {
    process.env[SHARED_SECRET_NAMES[1]] = 'shared-deployment-secret';
    process.env.TENANT_B_CREDENTIAL = 'cred-for-tenant-b';
    const credFile = join(scratch, 'tenant-a');
    writeFileSync(credFile, 'cred-for-tenant-a\n', 'utf8');

    const clientA = new AgentShield({
      pepUrl: PEP,
      consoleUrl: CONSOLE,
      tenantId: tenantId('tenant-a'),
      credentialFile: credFile,
    });
    const clientB = new AgentShield({
      pepUrl: PEP,
      consoleUrl: CONSOLE,
      tenantId: tenantId('tenant-b'),
      agentId: 'agent-b',
      credentialEnv: 'TENANT_B_CREDENTIAL',
    });

    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => undefined);
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve(allowedResponse),
      text: () => Promise.resolve('{}'),
    });

    await clientA.check('hello from a', { log: false });
    await clientB.check('hello from b', { log: false });

    const calls = (global.fetch as jest.Mock).mock.calls;
    expect(calls[0][1].headers.Authorization).toBe('Bearer cred-for-tenant-a');
    expect(calls[1][1].headers.Authorization).toBe('Bearer cred-for-tenant-b');
    expect(calls[0][1].headers.Authorization).not.toContain('shared-deployment-secret');
    expect(calls[1][1].headers.Authorization).not.toContain('shared-deployment-secret');
    expect(calls[0][1].body).not.toContain('cred-for-tenant-a');
    expect(calls[1][1].body).not.toContain('cred-for-tenant-b');

    global.fetch = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    await expect(clientA.check('again', { log: false })).rejects.toBeInstanceOf(
      ShieldConnectionError,
    );

    const leaked = [
      clientA.toString(),
      clientB.toString(),
      ...logSpy.mock.calls.map((call) => String(call[0])),
    ].join('\n');
    expect(leaked).not.toContain('cred-for-tenant-a');
    expect(leaked).not.toContain('cred-for-tenant-b');
    expect(leaked).not.toContain('shared-deployment-secret');
  });

  it('re-reads a rotated credential file and never logs either value', async () => {
    delete process.env.G8R_TENANT_CREDENTIAL;
    delete process.env.G8R_TENANT_CREDENTIAL_FILE;
    const credFile = join(scratch, 'rotating');
    writeFileSync(credFile, 'cred-before-rotation\n', 'utf8');
    const client = new AgentShield({
      pepUrl: PEP,
      consoleUrl: CONSOLE,
      tenantId: tenantId('tenant-a'),
      credentialFile: credFile,
    });
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => undefined);
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve(allowedResponse),
      text: () => Promise.resolve('{}'),
    });

    await client.check('first', { log: false });
    writeFileSync(credFile, 'cred-after-rotation\n', 'utf8');
    await client.check('second', { log: false });

    const calls = (global.fetch as jest.Mock).mock.calls;
    expect(calls[0][1].headers.Authorization).toBe('Bearer cred-before-rotation');
    expect(calls[1][1].headers.Authorization).toBe('Bearer cred-after-rotation');
    const leaked = [client.toString(), ...logSpy.mock.calls.map((call) => String(call[0]))].join(
      '\n',
    );
    expect(leaked).not.toContain('cred-before-rotation');
    expect(leaked).not.toContain('cred-after-rotation');
  });

  it('an empty credential file refuses to start', () => {
    const credFile = join(scratch, 'empty');
    writeFileSync(credFile, '\n', 'utf8');
    expect(
      () =>
        new AgentShield({
          pepUrl: PEP,
          consoleUrl: CONSOLE,
          tenantId: tenantId('tenant-a'),
          credentialFile: credFile,
        }),
    ).toThrow(/per-tenant credential/);
  });

  it('no hard-coded or default secret remains', () => {
    const root = join(__dirname, '..', '..');
    const hits: string[] = [];
    for (const file of productionFiles(root)) {
      const text = readFileSync(file, 'utf8');
      const rel = relative(root, file).split(sep).join('/');
      for (const needle of SHARED_SECRET_NAMES) {
        if (text.includes(needle)) hits.push(`${rel}: contains ${needle}`);
      }
      if (HARDCODED_SECRET.test(text)) hits.push(`${rel}: hard-coded sk- secret literal`);
    }
    expect(hits).toEqual([]);
  });
});
