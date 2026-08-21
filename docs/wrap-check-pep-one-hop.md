# wrap / check / PEP one-hop

`wrap()` takes one hop: `pepUrl` → PEP `POST /proxy`. Configure `G8R_PEP_URL`,
`G8R_CONSOLE_URL`, and `G8R_API_KEY`.

The hop is inside `wrap()`. Do not call `wrap()` and then fetch `/proxy`
yourself.

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

`check()` is not a second hop you add after `wrap()`. Do not pair it with
`wrap()` on the same prompt.

## After `wrap()`

| Decision    | `wrap()` |
| ----------- | -------- |
| `allowed`   | Invoke `factory` |
| `blocked`   | Throw `ShieldBlockedError`. `factory` is not called |
| `escalated` | Invoke `factory` unless `blockOnEscalated` / `block_on_escalated` is true |
