# How the signed policy decisions work

I've started working on the cryptographic confirmation part of the policy engine. It's still in development. The first version includes the protocol, verification in Python and TypeScript, a reference signer/mock PEP, and shared tests. It still needs to be connected to the real policy service.

The basic idea is that the policy service returns a signed receipt for each decision. The SDK checks that the receipt was signed by an authority it trusts and belongs to the request it actually sent. A valid signature by itself is not enough: an approval for a different request should not count.

## The keys

I'm using Ed25519 for the signatures [1]. The policy service keeps the private key, while the SDK only gets the public key. That lets the SDK verify decisions without giving it the ability to sign new ones. With a shared-key MAC, anyone who has the verification secret can also produce valid MACs, which is not the separation we want here [2].

The public key has to come from trusted configuration. Accepting a key supplied with the response would not prove much, since someone could sign a fake decision with their own key and send both. The receipt's key ID just selects one of the keys already configured in the SDK.

Node's crypto API and Python's cryptography library handle Ed25519 [6,7]. I haven't written a new signature algorithm. The work here is defining what gets signed and which checks the SDK has to make.

## Tying it to the request

A signed "allow" is not useful unless we know what was allowed. So the SDK builds a request description containing the endpoint, tenant, agent, request ID, governance headers, redacted body, and a fresh random challenge. It hashes that description with SHA-256, and the policy service includes the same hash in the signed receipt.

```text
request hash = SHA256("g8r:decision-request:v1\0" + canonical request bytes)
```

The fixed prefix separates this use of the hash from other uses in the system. The service must reconstruct the description from the request it received, not just sign a hash the client supplied.

Changing the request means the old receipt should no longer match. A hash alone would not stop someone from making that change and calculating a new hash; signing it together with the decision is what authenticates the result.

This covers the redacted request sent for evaluation, not the original unredacted prompt or the callback passed to `wrap()`.

## Making both languages agree

Python and TypeScript need to hash the same bytes. JSON can carry the same data with different whitespace or key order, so using each language's usual JSON output would be unreliable.

The implementation uses a restricted RFC 8785-compatible format [3]. Keys have a defined order, arrays keep their order, and the output is UTF-8 without extra formatting. It accepts safe integers, not arbitrary floats, and rejects duplicate keys or invalid Unicode. Strings are not normalized. Both languages run against the same fixtures, including Unicode and key-order cases.

## What's signed

The receipt uses the compact JWS format [2]:

```text
encoded header . encoded payload . signature
```

The header gives the receipt type, key ID, and algorithm. The algorithm is fixed to `Ed25519`, using the fully specified name in RFC 9864 [4]. The response cannot choose a different algorithm or introduce another trusted key.

The payload contains the complete decision, request hash, tenant, agent, request ID, challenge, issuer, intended verifier, timestamps, and receipt ID. The SDK uses the decision inside that verified payload. An unsigned `allowed` field beside a signed denial does not override it.

## Old receipts and expiration

Each new evaluation gets a fresh 256-bit random challenge, even when the caller reuses a request ID. A receipt from an earlier evaluation will not match the new challenge. A network retry keeps the same challenge because it is still the same evaluation.

Receipts also expire. The reference signer gives them 30 seconds. The default verifier accepts at most a 60-second issued lifetime, with five seconds of clock tolerance. These are settings we've chosen for the protocol, not properties of Ed25519.

This does not make receipts globally single-use. Checking the same valid receipt against the same expected request twice can still succeed. Preventing repeated execution would need trusted consumption state and an explicit retry policy.

## What the SDK checks

The SDK verifies the signature, then checks the issuer, audience, tenant, agent, request ID, challenge, request hash, timestamps, protocol version, and decision format. That distinction matters: a genuine signed token can still be wrong for this request [5].

Once required verification is enabled, missing or invalid receipts stop execution. Only `allowed` reaches the callback. `REQUIRE_APPROVAL` does not become permission to proceed, even when the old advisory-escalation option is set. This does not build the approval workflow; the service needs to issue a fresh allowed decision after approval.

Verification is opt-in for compatibility. Installing the code without configuring it leaves the existing unsigned behavior in place.

## The limit of the guarantee

Right now, the guarantee is that a holder of the trusted signing key issued this decision for this policy request. It does not prove that the engine evaluated the policy correctly or that the agent did exactly what was checked. The callback and checked prompt are still separate in the current API. Enforcing the actual operation would need a controlled tool adapter or gateway.

Signing reported ancestry also does not prove that ancestry is true. The real service has to validate the identities and attributes it relies on before signing.

The private key needs protection. If it is stolen, forged decisions can look genuine until the trusted-key configuration is updated. Rotating keys means provisioning the new public key, switching the signer, and replacing verifier instances when the retired key is removed.

Finally, signing is not encryption. The receipt is readable, HTTPS is still required, and a hash is not anonymization. Guessable requests can be tested against a known hash and context. Audit storage is also unchanged; retaining receipts and linking them to execution results is separate work.

The mock shows the signing and verification flow, not production authentication or Cedar evaluation. This is a development implementation with tests, not an independently audited or deployed security guarantee.

## Signing details

```text
D = SHA256("g8r:decision-request:v1\0" || canonical(request))
M = base64url(canonical(header)) || "." || base64url(canonical(claims including D))
signature = Ed25519.Sign(private_key, ASCII(M))
receipt = M || "." || base64url(signature)
```

Ed25519 itself uses elliptic-curve operations and SHA-512 [1]. That is separate from the SHA-256 request hash above. The libraries handle the curve arithmetic and signature verification; the SDK handles the request and decision checks.

## References

[1] RFC 8032, Ed25519: https://www.rfc-editor.org/rfc/rfc8032.html

[2] RFC 7515, JSON Web Signature: https://www.rfc-editor.org/rfc/rfc7515.html

[3] RFC 8785, JSON Canonicalization Scheme: https://www.rfc-editor.org/rfc/rfc8785.html

[4] RFC 9864, Fully-Specified Algorithms for JOSE and COSE: https://www.rfc-editor.org/rfc/rfc9864.html

[5] RFC 8725, JSON Web Token Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725.html

[6] Node.js crypto API: https://nodejs.org/api/crypto.html

[7] Python cryptography, Ed25519: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
