'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const impl = require(process.env.G8R_RECEIPTS_JS);
const { ReceiptVerifier, ReceiptVerificationError, canonicalJson, buildReceiptRequest,
  receiptRequestHash, assertReceiptTransport } = impl;
const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, '../test-vectors/decision-receipts-v1.json'), 'utf8'));

for (const c of vectors.cases) {
  test(`shared: ${c.name}`, () => {
    const run = () => new ReceiptVerifier(c.config).verify(c.receipt, c.request, c.now);
    if (c.accept) {
      const result = run();
      assert.equal(result.decision.decision, c.decision);
      assert.equal(result.token, c.receipt);
    } else assert.throws(run, ReceiptVerificationError);
  });
}
for (const c of vectors.canonicalCases) {
  test(`canonical: ${c.name}`, () => assert.equal(canonicalJson(c.value).toString('base64url'), c.canonicalBase64));
}
test('golden request digest', () => {
  assert.equal(receiptRequestHash(vectors.baseRequest), vectors.requestHash);
  assert.equal(canonicalJson(vectors.baseRequest).toString('base64url'), vectors.requestCanonicalBase64);
});
test('Node signing matches the Python-generated receipt byte for byte', () => {
  const h = canonicalJson(vectors.baseHeader).toString('base64url');
  const p = canonicalJson(vectors.baseClaims).toString('base64url');
  const input = h + '.' + p;
  const signature = crypto.sign(null, Buffer.from(input, 'ascii'), vectors.testOnlyPrivateKeyPem).toString('base64url');
  assert.equal(input + '.' + signature, vectors.validReceipt);
});
test('fresh nonce per evaluation and detached request snapshot', () => {
  const r = vectors.baseRequest;
  const body = structuredClone(r.body);
  const headers = { ...r.governanceHeaders, Authorization: 'Bearer sensitive-test' };
  const args = { endpoint: r.endpoint, tenantId: r.tenantId, agentId: r.agentId, requestId: r.requestId, body, headers };
  const one = buildReceiptRequest(args), two = buildReceiptRequest(args);
  assert.notEqual(one.nonce, two.nonce);
  assert.notEqual(receiptRequestHash(one), receiptRequestHash(two));
  assert.equal(canonicalJson(one).includes('sensitive-test'), false);
  body.body.prompt = 'mutated'; headers['x-gf-agent-id'] = 'changed';
  assert.equal(one.body.body.prompt, 'demo:allow');
  assert.equal(one.governanceHeaders['x-gf-agent-id'], r.agentId);
});
test('reject case-duplicate governance header', () => {
  const r = vectors.baseRequest;
  assert.throws(() => buildReceiptRequest({ endpoint: r.endpoint, tenantId: r.tenantId,
    agentId: r.agentId, requestId: r.requestId, body: r.body,
    headers: { ...r.governanceHeaders, 'X-GF-Agent-ID': r.agentId } }), ReceiptVerificationError);
});
test('unsigned outer allow cannot override a signed deny', () => {
  const c = vectors.cases.find(c => c.name === 'valid_deny');
  const result = new ReceiptVerifier(c.config).verifyResponse({ receipt: c.receipt, decision: 'allowed' }, c.request, c.now);
  assert.equal(result.decision.decision, 'blocked');
  assert.throws(() => { result.decision.decision = 'allowed'; }, TypeError);
});
for (const value of [{ decision: 'allowed' }, {}, null, [], { receipt: null }]) {
  test(`unsigned response rejected: ${JSON.stringify(value)}`, () => {
    assert.throws(() => new ReceiptVerifier(vectors.config).verifyResponse(value, vectors.baseRequest, vectors.now), ReceiptVerificationError);
  });
}
test('repeated low-level verification is not token consumption', () => {
  const verifier = new ReceiptVerifier(vectors.config);
  assert.equal(verifier.verify(vectors.validReceipt, vectors.baseRequest, vectors.now).token,
    verifier.verify(vectors.validReceipt, vectors.baseRequest, vectors.now).token);
});
test('configuration is a key snapshot; another curve is rejected', () => {
  const config = structuredClone(vectors.config);
  const verifier = new ReceiptVerifier(config);
  config.publicKeys = {};
  assert.ok(verifier.verify(vectors.validReceipt, vectors.baseRequest, vectors.now));
  const wrong = crypto.generateKeyPairSync('ed448').publicKey.export({ type: 'spki', format: 'pem' });
  assert.throws(() => new ReceiptVerifier({ issuer: 'issuer', audience: 'audience', publicKeys: { key: wrong } }), ReceiptVerificationError);
});
test('reject unsupported and ambiguous JSON values', () => {
  const cyclic = []; cyclic.push(cyclic);
  const getter = {}; Object.defineProperty(getter, 'value', { enumerable: true, get() { throw new Error('must not run'); } });
  let deep = null; for (let i = 0; i < 35; i++) deep = [deep];
  const sparse = []; sparse[1] = 1;
  for (const bad of [1.5, NaN, Infinity, 9007199254740992, -9007199254740992, undefined, 1n,
    new Date(), Buffer.from('x'), '\ud800', cyclic, deep, sparse, getter,
    'x'.repeat(1048577), Array(100001).fill(null)]) {
    assert.throws(() => canonicalJson(bad), ReceiptVerificationError);
  }
});
test('HTTPS required for SDK signed mode', () => {
  for (const url of ['http://example.com', 'ftp://example.com', 'https://a:b@example.com',
    'https://example.com/#fragment', 'https://example.com/?q=x', 'not-a-url', 'https://exam\nple.com']) {
    assert.throws(() => assertReceiptTransport(url), ReceiptVerificationError);
  }
  assertReceiptTransport('https://pep.example.com:8443/prefix');
});
test('verified claims and nested mappings cannot be changed', () => {
  const c = vectors.cases.find(c => c.name === 'valid_compliance_metadata');
  const result = new ReceiptVerifier(c.config).verify(c.receipt, c.request, c.now);
  assert.throws(() => { result.claims.tenantId = 'changed-tenant'; }, TypeError);
  assert.throws(() => { result.claims.decision.complianceMappings[0].controlId = 'changed'; }, TypeError);
  assert.equal(result.decision.complianceMappings[0].controlId, 'test-1');
});
