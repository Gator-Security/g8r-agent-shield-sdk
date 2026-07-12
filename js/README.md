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

> **`ShieldConfig` fields.** `tenantId` is the **only hard-required** field — it identifies the tenant in the multi-tenant governance plane. `consoleUrl` and `apiKey` are **required-in-effect**: pass them directly, or omit them and let the constructor resolve them from the `G8R_CONSOLE_URL` / `G8R_API_KEY` environment variables. If neither the argument nor the env var resolves, the constructor **throws** — it never falls back to `localhost` (an SDK that ships prompts + API keys must fail closed). The credential can alternatively come from a [`credentialProvider`](#authenticating-with-short-lived-credentials-credentialprovider) — mutually exclusive with `apiKey`. Everything else is **optional with a default**: `department` (`"General"`), `userId` (`"unknown"`), `aiModel` (`"unknown"`), `agentId` (`"sdk-client"`), `employeeName` (falls back to `userId` in the audit log), `timeout` (`10` seconds), and `blockOnEscalated` (`false`).

```typescript
// Minimal — consoleUrl + apiKey from env, everything else defaulted:
//   export G8R_CONSOLE_URL=https://shield.yourcompany.com
//   export G8R_API_KEY=sk-shield-...
const shield = new AgentShield({ tenantId: tenantId('acme-corp') });
```

### Authenticating with short-lived credentials (`credentialProvider`)

The Console accepts either the deployment **shared secret** or a **verified OIDC JWT** (workload identity — e.g. AWS) in the same `Authorization: Bearer` header. For JWTs — which expire — pass a `credentialProvider` instead of a static `apiKey`. The provider is awaited **fresh on every `/check` and `/log` request**, so a rotated token is always picked up:

```typescript
const shield = new AgentShield({
  tenantId: tenantId('acme-corp'),
  consoleUrl: 'https://shield.yourcompany.com',
  // Mint/refresh the OIDC workload-identity JWT per request — sync or async.
  credentialProvider: () => getWorkloadIdentityToken(),
});
```

- `apiKey` and `credentialProvider` are **mutually exclusive** — the constructor throws if both are passed, and the `G8R_API_KEY` env fallback is not consulted when a provider is configured.
- A provider **rejection on the policy check fails closed**: the SDK throws `ShieldConnectionError` (the provider's error is preserved on `.cause`), and `wrap()` never invokes the LLM factory. On the audit-log leg a provider failure is swallowed like any other logging failure — a logging outage never breaks the decision path (same contract as the Python SDK).
- The resolved credential is used only for the `Authorization` header and is **never logged**.
- With a verified JWT, the server trusts the JWT's **tenant claim** over the request body's `tenantId` — a mismatch returns HTTP `403`. A bad or missing credential returns `401`.

### Agent registration (trust on first use)

The **first** call from an unknown `agentId` auto-creates a **pending registration** in the Console's **Approvals queue**. What happens while it is pending depends on the server's pending-agent mode:

- **`flag`** (server default) — calls from a pending agent evaluate normally under policy; admins get an alert. The SDK sees ordinary decisions.
- **`block`** — calls return `decision: 'blocked'` with `requiresApproval: true` until an admin approves the agent.

The SDK derives `isPendingRegistration` **client-side** from exactly that conjunction (`decision === 'blocked' && requiresApproval === true`) — it is **not** a wire field, and reason strings are never parsed:

```typescript
try {
  const result = await shield.wrap(() => llmCall(), prompt);
} catch (err) {
  if (err instanceof ShieldBlockedError && err.isPendingRegistration) {
    // Not a policy violation — the agent is awaiting approval in the
    // Console's Approvals queue. Ask an admin to approve it, then retry.
  }
}

// Or, without wrap():
const result = await shield.check(prompt);
if (result.isPendingRegistration) {
  // Same signal on the raw decision object.
}
```

An admin-**denied** agent returns `blocked` with `requiresApproval: false` in both modes, so `isPendingRegistration` stays unset for it — that block is a verdict, not a waiting room.

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
  isPendingRegistration?: boolean; // Derived client-side (NOT a wire field):
                                   // decision === 'blocked' && requiresApproval === true,
                                   // i.e. the agent awaits approval in the Approvals queue
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
  isPendingRegistration: boolean;          // true when the block is the trust-on-first-use
                                           // registration gate, not a policy verdict
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
// console URL; carries no response body. Also thrown when a configured
// credentialProvider rejects (fail closed — no request was sent); in that
// case the provider's error is preserved on `.cause`.
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
│   ├── sdk.test.ts           # SDK client behavior + redaction integration
│   ├── credentials.test.ts   # credentialProvider auth (per-request resolution, fail-closed)
│   ├── registration.test.ts  # trust-on-first-use pending-registration detection
│   └── redaction.test.ts     # all patterns + entropy detection
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
