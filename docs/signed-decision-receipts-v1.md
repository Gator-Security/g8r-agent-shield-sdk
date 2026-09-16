# G8R signed decision receipts, version 1

**Still in development.** This is the proposed protocol and its reference implementation, not an API already running on the G8R server. The SDK baseline is `270584990150b9ea783e7193e50c72378104d6cc` (0.5.2).

## 1. What a receipt confirms

An accepted receipt confirms that a holder of a configured signing key issued this decision for the expected **redacted evaluation request**, within the allowed time window. It does not prove that the policy was evaluated correctly, that reported agent ancestry is true, or that the callback performed an authorized action.

This covers the protocol, both SDK verifiers, a development signer/mock service, and shared tests. The policy engine, Cedar schema, audit storage, dashboard, inventory, approval workflow, and execution gateway are unchanged.

Before signing, the real service must authenticate the caller, establish the tenant and agent, reject identity mismatches, and evaluate policy. A request hash binds the submitted values; it does not make them trustworthy. The development mock does not do this authentication or evaluation.

In this specification, 'must' marks a protocol requirement, not a suggestion.

## 2. Signature format

The envelope is JWS Compact Serialization [1]. The only permitted algorithm is Ed25519, using the fully specified JOSE identifier `Ed25519` from RFC 9864 [2], with the Ed25519 parameters of RFC 8032 [3]. `EdDSA`, `Ed448`, HMAC, RSA, and `none` are not accepted by version 1. The response cannot negotiate another algorithm.

The protected header has exactly these members:

```json
{"alg":"Ed25519","kid":"authority-key-1","typ":"g8r-decision-receipt+jwt"}
```

`kid` is 1-128 ASCII letters, digits, dots, underscores, or hyphens. It selects a public key already provisioned in the verifier's local configuration. A token must not introduce its own trusted key, URL, certificate, or algorithm. Extra header members, including `jwk`, `jku`, `x5u`, `crit`, and `b64`, are rejected. Only one public SubjectPublicKeyInfo PEM block per configured key is accepted; keys must be Ed25519.

The signature is 64 bytes. The TypeScript implementation delegates signing verification to Node's `node:crypto`; Python delegates to `cryptography` [6,7]. The SDK defines the receipt checks and wire format; the libraries handle the curve arithmetic.

## 3. Canonical JSON profile

Version 1 uses a **restricted RFC 8785-compatible subset** [4]. It does not implement every JCS numeric case. Supported values are objects, arrays, Unicode scalar strings, booleans, null, and integers in `[-9007199254740991, 9007199254740991]`. Floating-point values are unsupported. In Python, even `1.0` must be supplied as integer `1`; non-integral numbers require a future protocol extension or an explicitly specified string representation.

Object names sort recursively by UTF-16 code units. Array order is preserved. Strings are not Unicode-normalized. Output is UTF-8 without extra whitespace. Lone surrogates, non-finite numbers, cycles, unsupported native values, duplicate JSON members, and excessive structure are rejected. Signed header and payload bytes must already be canonical; verification does not repair or reserialize the bytes before checking the signature.

Limits: JSON canonical output at most 1,048,576 bytes, nesting depth at most 32, and visited nodes at most 100,000. The entire compact receipt is at most 65,536 ASCII characters; encoded header at most 2,048 characters; encoded signature at most 128 characters before the decoded 64-byte check. Base64url has no padding or whitespace and must round-trip to the same spelling, including unused pad bits.

## 4. Evaluation request binding

For each new `check()` or `wrap()` evaluation, the SDK generates a fresh 32-byte cryptographically random challenge. A reused caller-provided request ID does not reuse the challenge. Only the network retry of that same evaluation reuses it.

The SDK sends:

```text
X-G8R-Receipt-Version: 1
X-G8R-Receipt-Nonce: <43-character unpadded base64url challenge>
```

The canonical request descriptor has exactly these fields:

| Field | Value |
|---|---|
| `version` | Integer `1` |
| `method` | String `POST` |
| `endpoint` | `/decide` or `/api/sdk/v1/check` |
| `nonce` | The challenge sent in `X-G8R-Receipt-Nonce` |
| `tenantId`, `agentId`, `requestId` | Exact expected identity/correlation strings, each 1-256 UTF-8 bytes |
| `governanceHeaders` | All transmitted `x-gf-*` headers, lower-case names and exact values |
| `body` | The complete redacted JSON object sent to the endpoint |

Governance header names match `x-gf-[a-z0-9-]+`. Values are visible ASCII plus interior spaces, at most 8,192 bytes, without leading/trailing whitespace. Duplicate header names after case folding are rejected. The actual service must also reject ambiguous duplicate HTTP headers before reconstructing the descriptor.

For `/decide`, `x-gf-tenant-id`, `x-gf-agent-id`, and `body.correlation_id` must match the descriptor. For `/api/sdk/v1/check`, `body.tenantId`, `body.agentId`, and `body.requestId` must match it. Session and ancestor information is bound wherever it appears in the transmitted body or governance headers; this protects the reported values against alteration, not their truthfulness.

Authorization credentials, cookies, User-Agent, and generic transport headers are not part of the digest. The issuing authority and intended verifier are bound separately through the signed `iss` and `aud` claims; deployments must use distinct trust configuration across environments.

The request digest is:

```text
requestHash = lowercase_hex(
    SHA256(UTF8("g8r:decision-request:v1") || 0x00 || canonical_json(descriptor))
)
```

The service reconstructs the descriptor from its received request; it must not simply sign an unchecked client-supplied digest. The digest represents the evaluation input, not `factory()` behavior, a downstream HTTP transaction, or an unredacted prompt.

## 5. Receipt payload

Exactly these members are allowed. Extensions require a new protocol version rather than silently ignored conditions.

| Field | Meaning and validation |
|---|---|
| `version` | Integer `1`; booleans are not integers |
| `iss`, `aud` | Exact, case-sensitive matches to configured issuer and audience |
| `iat`, `exp` | Nonnegative safe-integer Unix seconds |
| `jti` | Issuer-generated receipt identifier, 16-128 ASCII letters/digits/dots/underscores/hyphens |
| `nonce` | Exact expected request challenge |
| `tenantId`, `agentId`, `requestId` | Exact matches to the request descriptor |
| `requestHash` | Exactly 64 lower-case hexadecimal characters matching the local digest |
| `decision` | The complete normalized decision object described below |

The decision object contains exactly: `decision`, `reason`, `violatedRule`, `requiresApproval`, `sessionRevoked`, and `complianceMappings`.

`decision` is one of `allowed`, `blocked`, or `escalated`. `reason` is a string of at most 4,096 UTF-8 bytes and may be empty. `violatedRule` is null or a nonempty string of at most 256 UTF-8 bytes. Both flags are real booleans. `complianceMappings` is an array of at most 64 objects, each containing exactly `regulation`, `controlId`, `controlName`, and `description`, with strings of at most 1,024 UTF-8 bytes each.

An `allowed` decision cannot require approval or revoke a session. `escalated` requires approval. Revocation must be `blocked` with `requiresApproval=false`. The existing pending-registration convention, `blocked` plus `requiresApproval=true`, remains representable. Compliance labels are signed metadata, not a legal certification.

There is no policy revision or Cedar schema digest in v1. The repository does not provide an authoritative source for them, so this version does not invent one. They can be added in a later version once the real engine is connected.

## 6. Signing, response, and verification

Let `H` and `P` be the canonical protected header and payload bytes. The JWS signing input is ASCII `base64url(H) + "." + base64url(P)`. Sign those exact bytes with the authority's Ed25519 private key; append `"." + base64url(signature)` [1]. This is ordinary Ed25519, not Ed25519ph.

The endpoint returns:

```json
{"receipt":"<compact JWS>"}
```

Unsigned outer fields may be present for legacy consumers, but required-verification mode ignores them. In particular, an unsigned outer `decision: "allowed"` never overrides a signed denial.

Verification rejects an absent receipt, unsupported encoding, wrong type/algorithm, unknown key, invalid signature, invalid schema, contradictory decision, issuer/audience mismatch, request mismatch, or invalid time window. All rejection paths fail closed. The verifier checks signature bytes against the received signed segments and only then treats claims as authenticated. The claim checks still need to pass after the signature is verified [5].

The default maximum receipt lifetime is 60 seconds; the reference signer issues 30-second receipts. Configuration allows a lifetime ceiling of 1-300 seconds and clock skew of 0-30 seconds (default 5). Acceptance requires:

```text
exp > iat
exp - iat <= configured_max_lifetime
iat - now <= configured_clock_skew
now - exp < configured_clock_skew
```

At zero skew, `now == exp` is expired. Production SDK calls use the current wall clock. A `now` argument exists only on the low-level verifier for deterministic tests and explicit offline verification; callers using it are responsible for its trustworthiness.

## 7. SDK integration and compatibility

`receiptVerification` in TypeScript, or `receipt_verification` in Python, enables required verification on **both** `/decide` and `/api/sdk/v1/check`. There is no response-driven downgrade and no fallback to the other endpoint. Both issuing endpoints must support the protocol before this mode can operate successfully.

Without this configuration, existing unsigned Node/Python behavior remains for backwards compatibility and provides **no signed-receipt guarantee**. Production installations adopting this feature must explicitly enable it. Required mode additionally requires HTTPS for both configured URLs. The existing SDK's loopback restrictions are not loosened. TypeScript receipt support targets Node.js >=18; browser/edge bundling is outside this implementation's support scope.

In required mode, `wrap()` executes only `allowed`. Approval-required decisions are blocked even when the caller passes the old `blockOnEscalated=false` option. This adds no approval/resume service: after approval, the real authority must issue a fresh allowed decision for a new evaluation. `check()` continues to return verified policy denials rather than raising for ordinary denials; invalid receipts raise `ReceiptVerificationError`.

`check()` exposes the verified token as `decisionReceipt` / `decision_receipt`. Existing `wrap()` return values remain unchanged. Existing `/log` submission is not redesigned and does not automatically persist the compact receipt. Receipt retention and execution-result linkage remain separate future work.

## 8. Replay and key lifecycle

A fresh challenge and request hash prevent a receipt from a different evaluation from matching the current request, assuming the SDK snapshot and randomness are trusted. Expiry limits age. Neither `jti` nor the challenge records whether a receipt has been used. The same receipt can be verified against the same snapshot again, including on a retry. This does not guarantee exactly-once execution.

Each verifier keeps a copy of its configured public keys. To rotate keys, provision the new public key alongside the old one, switch the signer, then remove the retired key and create new verifier instances according to the deployment policy. Unknown keys fail closed; no response-supplied URL is fetched. Compromised-key revocation requires updating trust configuration; expiry alone is not immediate revocation. Already-created verifier instances retain their key snapshot until replaced.

Private signing keys must remain outside agent/client runtimes. The development CLI creates fresh keys without overwriting existing files and uses restrictive private-key file permissions. The predictable keys embedded in test fixtures are PUBLIC TEST MATERIAL and must never enter a deployment trust store.

## 9. Before production

Receipts authenticate a decision statement, not the correctness of Cedar evaluation or the truth of an asserted identity. They do not prove actual execution, prevent a compromised process from bypassing the SDK, guarantee current policy after issuance, provide complete audit coverage, or add confidentiality. HTTPS is still required, and a request hash is not anonymization: guessable inputs may be tested against a known receipt context.

Before using this in production, connect the authenticated signer and test both endpoints. The parser and trust assumptions need review, keys need protected storage and a rotation/revocation process, and clocks need synchronization. The full upstream SDK suites and an independent security review are still required. Passing the local tests is not an audit certification.

## References

[1] RFC 7515, JSON Web Signature: https://www.rfc-editor.org/rfc/rfc7515.html

[2] RFC 9864, Fully-Specified Algorithms for JOSE and COSE: https://www.rfc-editor.org/rfc/rfc9864.html

[3] RFC 8032, Edwards-Curve Digital Signature Algorithm: https://www.rfc-editor.org/rfc/rfc8032.html

[4] RFC 8785, JSON Canonicalization Scheme: https://www.rfc-editor.org/rfc/rfc8785.html

[5] RFC 8725, JSON Web Token Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725.html

[6] Node.js crypto API: https://nodejs.org/api/crypto.html

[7] Python cryptography, Ed25519: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
