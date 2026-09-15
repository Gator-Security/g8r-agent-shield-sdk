'use strict';
const http = require('node:http');
const fs = require('node:fs');
const { randomUUID } = require('node:crypto');
const assert = require('node:assert/strict');
const { ReceiptVerifier, buildReceiptRequest } = require(process.env.G8R_RECEIPTS_JS);
const port = Number(process.argv[2]);
const publicKey = fs.readFileSync(process.argv[3], 'utf8');
const verifier = new ReceiptVerifier({ issuer: 'g8r-development-mock', audience: 'g8r-sdk-development',
  publicKeys: { 'development-key-1': publicKey } });
function post(endpoint, body, headers) {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request({ host: '127.0.0.1', port, path: endpoint, method: 'POST',
      headers: { ...headers, 'Content-Length': data.length } }, res => {
      const chunks = []; res.on('data', x => chunks.push(x));
      res.on('end', () => { try { assert.equal(res.statusCode, 200); resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(e); } });
    });
    req.setTimeout(5000, () => req.destroy(new Error('development request timeout')));
    req.on('error', reject); req.end(data);
  });
}
(async () => {
  let evaluations = 0, allowed = 0;
  for (const endpoint of ['/decide', '/api/sdk/v1/check']) {
    for (const [prompt, expected] of [['demo:allow', 'allowed'], ['demo:deny', 'blocked'], ['demo:approval', 'escalated']]) {
      const requestId = randomUUID(), tenantId = 'development-tenant', agentId = 'development-agent';
      const headers = { Authorization: 'Bearer development-only-not-a-production-credential', 'Content-Type': 'application/json' };
      let body;
      if (endpoint === '/decide') {
        headers['X-GF-Tenant-ID'] = tenantId; headers['X-GF-Agent-ID'] = agentId;
        body = { downstream_url: 'sdk://wrap', method: 'POST', action_hint: 'llm_prompt', target_hint: 'llm_prompt',
          body: { prompt }, correlation_id: requestId, action_type: 'tool_call' };
      } else body = { input: prompt, tenantId, agentId, requestId, department: 'General', userId: 'unknown', aiModel: 'unknown' };
      const request = buildReceiptRequest({ endpoint, tenantId, agentId, requestId, headers, body });
      headers['X-G8R-Receipt-Nonce'] = request.nonce; headers['X-G8R-Receipt-Version'] = '1';
      const receipt = verifier.verifyResponse(await post(endpoint, body, headers), request);
      assert.equal(receipt.decision.decision, expected); evaluations++;
      if (receipt.decision.decision === 'allowed') allowed++;
    }
  }
  assert.equal(allowed, 2);
  console.log(`${evaluations} signed evaluations verified across both endpoints; only ALLOW is executable`);
})().catch(error => { console.error(error); process.exitCode = 1; });
