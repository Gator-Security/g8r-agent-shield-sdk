# @g8r-security/agent-shield-sdk

TypeScript client SDK for integrating AI agents with G8R policy enforcement. Includes a **local VPC redaction layer** that strips sensitive data before it ever leaves your network.

Part of the [G8R Agent Shield monorepo](../../README.md).

## Overview

This is a **compiled package**, built with [tsup](https://tsup.egg.js.org/). Publishing ships the `dist/` output — ESM (`dist/index.mjs`), CommonJS (`dist/index.js`), and type declarations (`dist/index.d.ts`) — and `package.json` sets `"files": ["dist"]`, so `src/` is **not** included in the published tarball. Consumers import from the package name:

```typescript
import { AgentShield, tenantId } from '@g8r-security/agent-shield-sdk';
```

No `transpilePackages` / `resolve.alias` wiring is needed — the package resolves through its standard `main` / `module` / `types` / `exports` entry points.

## Quick Start

```typescript
import { AgentShield, tenantId } from '@g8r-security/agent-shield-sdk';

const shield = new AgentShield({
  tenantId: tenantId('acme-corp'),        // the only hard-required field
  consoleUrl: 'https://shield.yourcompany.com', // or G8R_CONSOLE_URL env var
  apiKey: 'sk-shield-...',                // or G8R_API_KEY env var
  agentId: 'enterprise-assistant',        // optional — defaults to 'sdk-client'
  department: 'Finance',                  // optional — defaults to 'General'
  userId: 'usr_FIN_042',                  // optional — defaults to 'unknown'
  aiModel: 'GPT-4o',                      // optional — defaults to 'unknown'
});

// Factory pattern — LLM is only called if the policy check passes
const result = await shield.wrap(
  () => openai.chat.completions.create({ model: 'gpt-4o', messages }),
  userPrompt
);
```

> **`ShieldConfig` fields.** `tenantId` is the **only hard-required** field — it identifies the tenant in the multi-tenant governance plane. `consoleUrl` and `apiKey` are **required-in-effect**: pass them directly, or omit them and let the constructor resolve them from the `G8R_CONSOLE_URL` / `G8R_API_KEY` environment variables. If neither the argument nor the env var resolves, the constructor **throws** — it never falls back to `localhost` (an SDK that ships prompts + API keys must fail closed). Everything else is **optional with a default**: `department` (`"General"`), `userId` (`"unknown"`), `aiModel` (`"unknown"`), `agentId` (`"sdk-client"`), `employeeName` (falls back to `userId` in the audit log), `timeout` (`10` seconds), and `blockOnEscalated` (`false`).

```typescript
// Minimal — consoleUrl + apiKey from env, everything else defaulted:
//   export G8R_CONSOLE_URL=https://shield.yourcompany.com
//   export G8R_API_KEY=sk-shield-...
const shield = new AgentShield({ tenantId: tenantId('acme-corp') });
```

## API

### `shield.wrap(factory, prompt)`

The primary integration point. Runs the full pipeline:

1. **Redact** — `redactSensitiveData(prompt)` strips secrets locally
2. **Check** — POST redacted prompt to `/api/sdk/v1/check` (policy evaluation)
3. **Log** — POST audit entry to `/api/sdk/v1/log`
4. **Invoke** — call `factory()` only if decision is `allowed`, or `escalated` while `blockOnEscalated` is `false`

If blocked, throws `ShieldBlockedError` — the factory is **never called**. If `escalated` and the shield was constructed with `blockOnEscalated: true`, it also throws `ShieldBlockedError`; otherwise an escalated action proceeds with a warning (pending out-of-band human review). Internally `wrap()` reuses `check(prompt, { requestId, log: false })` and then logs once with the same `requestId`, so `/check` and `/log` correlate under a single id with no duplicate audit entry.

```typescript
try {
  const result = await shield.wrap(() => llmCall(), prompt);
  console.log(result.llmResult);      // LLM response
  console.log(result.redactedTokens); // Tokens stripped from the prompt
} catch (err) {
  if (err instanceof ShieldBlockedError) {
    console.log(err.violatedRule);        // e.g. 'PII Detection'
    console.log(err.complianceMappings);  // GDPR Art. 32, etc.
  }
}
```

### `shield.check(prompt, opts?)`

Policy check only — no LLM call. **Never throws** on a `blocked`/`escalated` decision; it returns the decision for the caller to act on. By default it is **self-auditing** — it also POSTs to `/log` with the same `requestId`. Pass `{ log: false }` if you will follow up with `wrap()` for the same prompt (to avoid a duplicate audit entry), and `{ requestId }` to supply your own correlation id.

```typescript
const result = await shield.check(prompt);
// result.decision         → 'allowed' | 'blocked' | 'escalated'
// result.redactedTokens   → tokens stripped from the prompt before sending

// Options:
const result2 = await shield.check(prompt, {
  requestId: newRequestId(), // supply your own correlation id (optional)
  log: false,                // suppress the built-in audit log (default: true)
});
```

On a non-2xx response, `check()` throws a typed **`ShieldConsoleError`** (its message exposes only the status code — the raw body is on `.detail`). On a transient connection failure it retries once, then throws **`ShieldConnectionError`**.

### `redactSensitiveData(input)`

Standalone redaction — can be used independently of the shield client.

```typescript
import { redactSensitiveData } from '@g8r-security/agent-shield-sdk';

const { redacted, tokensReplaced } = redactSensitiveData(input);
```

## Redaction Layer

Sensitive data is detected and replaced **locally** before the prompt leaves the process — on both the policy-check and audit-log paths, so the gateway never receives recognized raw secrets.

> ⚠️ **Best-effort, not exhaustive.** Redaction is pattern- and entropy-based. It catches the formats listed below, but it **cannot** catch every secret or PII shape — unstructured PII (names, addresses), free-form secrets below the entropy threshold, or novel token formats may pass through. Treat this as one layer of defense-in-depth, not a compliance guarantee, and keep downstream controls and human review in place.

### Detection Patterns

| Pattern | Label |
|---|---|
| BIP-32 extended keys (`xpub`, `xprv`, `ypub`, …) | `[REDACTED:BIP32_KEY]` |
| WIF private keys (Base58, starts with `5`, `K`, or `L`) | `[REDACTED:WIF_KEY]` |
| 256-bit hex keys (64 hex chars, optional `0x` prefix) | `[REDACTED:HEX_KEY]` |
| PEM private / public key blocks | `[REDACTED:PEM_KEY]` |
| `custodial-id:…` / `cust-{digits}` / `wallet-id:…` / `vault-id:…` | `[REDACTED:CUSTODIAL_ID]` etc. |
| Card numbers (13–19 digits, Luhn-validated) | `[REDACTED:CARD]` |
| US SSNs (`123-45-6789`) | `[REDACTED:SSN]` |
| Email addresses | `[REDACTED:EMAIL]` |
| Phone numbers (separated, e.g. `415-555-0199`) | `[REDACTED:PHONE]` |
| High Shannon entropy strings (≥4.5 bits/char, ≥32 chars) | `[REDACTED:HIGH_ENTROPY]` |

These map to controls such as **GDPR Art. 32** (security of processing) and **PCI-DSS** PAN handling by reducing sensitive-data exposure — they *support* those controls rather than satisfy them on their own.

### Shannon Entropy Detection

Any token that is 32+ characters with Shannon entropy ≥ 4.5 bits/char is caught as a generic high-entropy secret. This is a best-effort catch for many API keys and tokens that don't match a known format — but secrets shorter than 32 chars or below the entropy threshold will not be caught.

```
H = -Σ p(c) × log₂(p(c))   for each unique character c
```

Low-entropy strings (e.g. `"aaaaaaaaaaaaa"`, entropy ≈ 0) are not flagged.

## `PolicyCheckResult`

```typescript
interface PolicyCheckResult {
  decision: 'allowed' | 'blocked' | 'escalated';
  reason: string;
  violatedRule: string | null;
  requiresApproval: boolean;
  complianceMappings: ComplianceMapping[];
  sessionRevoked?: boolean;
  redactedTokens?: string[];  // Tokens stripped by VPC masking layer
}
```

## Error taxonomy

```typescript
// Thrown by wrap() on a 'blocked' decision, or an 'escalated' decision when
// the shield was constructed with blockOnEscalated: true. The one error a
// normal caller catches.
class ShieldBlockedError extends Error {
  decision: string;                        // 'blocked' | 'escalated'
  reason: string;
  violatedRule: string | null;
  complianceMappings: ComplianceMapping[];
  sessionRevoked: boolean;                 // true when a kill-switch policy fired
}

// Thrown on a non-2xx HTTP response from /check. The message exposes ONLY the
// status code — the raw response body is on `.detail` for opt-in inspection,
// never in the message (so host frameworks can't echo internal stack
// traces / auth payloads / PII to end users).
class ShieldConsoleError extends Error {
  statusCode: number;
  detail: string;                          // raw body — opt-in only
}

// Thrown when the Console is unreachable after the single retry. Names the
// console URL; carries no response body.
class ShieldConnectionError extends Error {
  consoleUrl: string;
}
```

## `ShieldLogEntry`

Returned by the internal audit-log call when logging succeeds.

```typescript
interface ShieldLogEntry {
  id: string;        // audit-trail entry id
  decision: string;  // recorded decision
  timestamp: string; // ISO 8601 timestamp
}
```

## Request IDs

The SDK correlates each `check()`/`log()` pair with a per-request id so the two
server-side log lines can be joined. `wrap()` generates one automatically, but
the id type and constructor are exported for callers who want to supply or
propagate their own.

```typescript
import { newRequestId, type RequestId } from '@g8r-security/agent-shield-sdk';

const requestId: RequestId = newRequestId();
const result = await shield.check(prompt, { requestId });
```

- `newRequestId(): RequestId` — mints a fresh id (prefers `crypto.randomUUID()`).
- `RequestId` — branded string type for a per-request correlation id.

## Source Layout

```
js/
├── src/
│   ├── index.ts       # AgentShield class, ShieldBlockedError, PolicyCheckResult, ShieldLogEntry
│   ├── redaction.ts   # redactSensitiveData() — local-first masking layer
│   ├── ids.ts         # tenantId(), newRequestId() + TenantId / RequestId types
│   └── logger.ts      # structured logger used internally
├── __tests__/
│   ├── sdk.test.ts        # SDK client behavior + redaction integration
│   └── redaction.test.ts  # all patterns + entropy detection
├── jest.config.js
├── package.json
└── tsconfig.json
```

## Development

```bash
cd js

npm run build          # tsup — build dist/ (ESM + CJS + types)
npm test               # Jest
npm run test:coverage  # With coverage
npm run typecheck      # tsc --noEmit
```

## Coverage

Thresholds in `jest.config.js`: 85% statements, 75% branches, 85% functions, 85% lines.

## Compliance

| Regulation | Controls covered |
|---|---|
| GDPR | Art. 32 — appropriate technical measures for data protection |
| PCI-DSS v4.0 | 3.4 — cryptographic key protection |
