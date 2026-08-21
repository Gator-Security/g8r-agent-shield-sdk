# wrap / check / PEP one-hop

`wrap()` and `check()` take one hop: `pepUrl` → `POST /proxy`. Configure
`G8R_PEP_URL`, `G8R_CONSOLE_URL`, and `G8R_API_KEY`.

## Required property

**One governed action = local redaction + one PEP `/proxy` hop, and exactly one
PDP decision at that PEP.**

`wrap()` does not add a second decide hop. The factory runs only after that
decision allows it.

```
prompt
  │
  ├─ 1. redact locally
  │
  ├─ 2. ONE hop — pepUrl POST /proxy  →  exactly one PDP decision
  │
  └─ 3. invoke factory                →  only after allowed
```

`check()` is the same `/proxy` hop without a factory. Do not pair `check()` and
`wrap()` on the same prompt if you need a single decision — each call is its
own hop.

## wrap()

<CodeGroup>

```typescript TypeScript
import { AgentShield, tenantId } from '@g8r-security/agent-shield-sdk';

const shield = new AgentShield({
  tenantId: tenantId('your-tenant'),
  pepUrl: process.env.G8R_PEP_URL,
  consoleUrl: process.env.G8R_CONSOLE_URL,
  apiKey: process.env.G8R_API_KEY,
});

const result = await shield.wrap(() => model.complete(prompt), prompt);
```

```python Python
from g8r_shield import AgentShield

shield = AgentShield(
    tenant_id="your-tenant",
    pep_url=None,      # G8R_PEP_URL
    console_url=None,  # G8R_CONSOLE_URL
    api_key=None,      # G8R_API_KEY
)

result = shield.wrap(lambda: model.complete(prompt), prompt)
```

</CodeGroup>

## check()

Same `/proxy` hop. No factory.

<CodeGroup>

```typescript TypeScript
const decision = await shield.check(prompt);
// decision.decision → 'allowed' | 'blocked' | 'escalated'
```

```python Python
decision = shield.check(prompt)
# decision.decision → "allowed" | "blocked" | "escalated"
```

</CodeGroup>

## After the hop

| Decision    | `wrap()` |
| ----------- | -------- |
| `allowed`   | Invoke `factory` |
| `blocked`   | Throw `ShieldBlockedError`. `factory` is not called |
| `escalated` | Invoke `factory` unless `blockOnEscalated` / `block_on_escalated` is true |
