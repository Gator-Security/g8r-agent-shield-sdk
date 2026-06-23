# @g8r-security/agent-shield-sdk

TypeScript client SDK for integrating AI agents with G8R policy enforcement. Includes a **local VPC redaction layer** that strips sensitive data before it ever leaves your network.

Part of the [G8R Agent Shield monorepo](../../README.md).

## Overview

This is a **TypeScript source package** — no compile step. Consumers reference `./src/index.ts` directly via `transpilePackages` (Next.js) or `resolve.alias` (Vite).

## Quick Start

```typescript
import { AgentShield, tenantId } from '@g8r-security/agent-shield-sdk';

const shield = new AgentShield({
  consoleUrl: 'https://shield.yourcompany.com',
  apiKey: 'sk-shield-...',
  tenantId: tenantId('acme-corp'),
  agentId: 'enterprise-assistant',
  department: 'Finance',
  userId: 'usr_FIN_042',
  aiModel: 'GPT-4o',
});

// Factory pattern — LLM is only called if the policy check passes
const result = await shield.wrap(
  () => openai.chat.completions.create({ model: 'gpt-4o', messages }),
  userPrompt
);
```

## API

### `shield.wrap(factory, prompt)`

The primary integration point. Runs the full pipeline:

1. **Redact** — `redactSensitiveData(prompt)` strips secrets locally
2. **Check** — POST redacted prompt to `/api/sdk/v1/check` (policy evaluation)
3. **Log** — POST audit entry to `/api/sdk/v1/log`
4. **Invoke** — call `factory()` only if decision is `allowed` or `escalated`

If blocked, throws `ShieldBlockedError` — the factory is **never called**.

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

### `shield.check(prompt)`

Policy check only — no LLM call.

```typescript
const result = await shield.check(prompt);
// result.decision         → 'allowed' | 'blocked' | 'escalated'
// result.redactedTokens   → tokens stripped from the prompt before sending
```

### `redactSensitiveData(input)`

Standalone redaction — can be used independently of the shield client.

```typescript
import { redactSensitiveData } from '@g8r-security/agent-shield-sdk';

const { redacted, tokensReplaced } = redactSensitiveData(input);
```

## VPC Redaction Layer

Sensitive data is detected and replaced **locally** before leaving the VPC. The gateway never sees raw secrets.

### Detection Patterns

| Pattern | Label | Maps to |
|---|---|---|
| BIP-32 extended keys (`xpub`, `xprv`, `ypub`, …) | `[REDACTED:BIP32_KEY]` | PCI-DSS 3.4 |
| WIF private keys (Base58, starts with `5`, `K`, or `L`) | `[REDACTED:WIF_KEY]` | PCI-DSS 3.4 |
| 256-bit hex keys (64 hex chars, optional `0x` prefix) | `[REDACTED:HEX_KEY]` | PCI-DSS 3.4, GDPR Art. 32 |
| PEM private / public key blocks | `[REDACTED:PEM_KEY]` | GDPR Art. 32 |
| `custodial-id:…` | `[REDACTED:CUSTODIAL_ID]` | GDPR Art. 32 |
| `cust-{digits}` | `[REDACTED:CUST_ID]` | GDPR Art. 32 |
| `wallet-id:…` | `[REDACTED:WALLET_ID]` | GDPR Art. 32 |
| `vault-id:…` | `[REDACTED:VAULT_ID]` | GDPR Art. 32 |
| High Shannon entropy strings (≥4.5 bits/char, ≥32 chars) | `[REDACTED:HIGH_ENTROPY]` | GDPR Art. 32, PCI-DSS 3.4 |

### Shannon Entropy Detection

Any token that is 32+ characters with Shannon entropy ≥ 4.5 bits/char is caught as a generic high-entropy secret. This acts as a catch-all for API keys, tokens, and other secrets that don't match a known format.

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

## `ShieldBlockedError`

Thrown by `shield.wrap()` when `decision === 'blocked'`.

```typescript
class ShieldBlockedError extends Error {
  decision: 'blocked';
  reason: string;
  violatedRule: string | null;
  complianceMappings: ComplianceMapping[];
}
```

## Source Layout

```
packages/sdk/
├── src/
│   ├── index.ts       # AgentShield class, ShieldBlockedError, PolicyCheckResult
│   └── redaction.ts   # redactSensitiveData() — VPC masking layer
├── __tests__/
│   ├── sdk.test.ts        # 43 tests — SDK client behavior + redaction integration
│   └── redaction.test.ts  # 43 tests — all patterns + entropy detection
├── jest.config.ts
├── package.json
└── tsconfig.json
```

## Development

```bash
cd packages/sdk

npm test               # Jest (43 tests)
npm run test:coverage  # With coverage (97%+ statements)
npm run typecheck      # tsc --noEmit
```

## Coverage

Thresholds in `jest.config.ts`: 85% statements, 75% branches, 85% functions, 85% lines.

## Compliance

| Regulation | Controls covered |
|---|---|
| GDPR | Art. 32 — appropriate technical measures for data protection |
| PCI-DSS v4.0 | 3.4 — cryptographic key protection |
