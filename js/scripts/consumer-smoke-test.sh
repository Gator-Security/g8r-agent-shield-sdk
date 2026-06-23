#!/usr/bin/env bash
#
# Consumer smoke test.
#
# Builds and packs the SDK, then installs the resulting tarball into a throwaway
# project exactly as a customer would — and verifies that the public API
# type-checks and that redaction actually fires. This catches the class of bug
# that unit tests miss because they import from `src/` directly: missing exports,
# broken `exports` maps, raw-TS publishing, and leaked internal references.
#
# Run locally with `npm run smoke-test`; CI runs it on every PR and before every
# release.
set -euo pipefail

SDK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARBALL_PATH=""
WORK=""
cleanup() { [ -n "$TARBALL_PATH" ] && rm -f "$TARBALL_PATH"; [ -n "$WORK" ] && rm -rf "$WORK"; }
trap cleanup EXIT

cd "$SDK_DIR"
echo "==> Building and packing"
npm run build
TARBALL="$(npm pack --silent)"
TARBALL_PATH="$SDK_DIR/$TARBALL"

WORK="$(mktemp -d)"
echo "==> Installing tarball into a fresh consumer project ($WORK)"
cd "$WORK"
npm init -y >/dev/null
npm install --silent typescript >/dev/null
npm install --silent "$TARBALL_PATH" >/dev/null

echo "==> Type-checking a sample consumer import (strict, node16 resolution)"
cat > tsconfig.json <<'JSON'
{
  "compilerOptions": {
    "strict": true,
    "module": "node16",
    "moduleResolution": "node16",
    "noEmit": true,
    "skipLibCheck": true
  }
}
JSON
cat > consumer.ts <<'TS'
import {
  AgentShield,
  tenantId,
  redactSensitiveData,
  ShieldBlockedError,
  type ShieldConfig,
  type PolicyCheckResult,
  type RedactionResult,
} from '@g8r-security/agent-shield-sdk';

const cfg: ShieldConfig = {
  consoleUrl: 'https://example.test',
  apiKey: 'sk-shield-test',
  tenantId: tenantId('acme-corp'),
  department: 'Finance',
  userId: 'usr_001',
  aiModel: 'gpt-4o',
};

const shield = new AgentShield(cfg);
const _check: Promise<PolicyCheckResult> = shield.check('hello');
const _redaction: RedactionResult = redactSensitiveData('hello');
const _err: Error = new ShieldBlockedError('blocked', null, []);
void _check;
void _redaction;
void _err;
TS
npx --yes tsc --project tsconfig.json
echo "    ok: public API resolves and type-checks for a consumer"

echo "==> Asserting redaction fires at runtime"
node --input-type=commonjs -e '
const { redactSensitiveData } = require("@g8r-security/agent-shield-sdk");
const must = (label, input, fragment) => {
  const { redacted } = redactSensitiveData(input);
  if (!redacted.includes(fragment)) {
    console.error("    FAIL " + label + " -> " + redacted);
    process.exit(1);
  }
  console.log("    ok: " + label);
};
must("credit card", "card 4111 1111 1111 1111", "[REDACTED:CARD]");
must("ssn", "ssn 123-45-6789", "[REDACTED:SSN]");
must("email", "reach me at jane@acme.com", "[REDACTED:EMAIL]");
must("crypto key", "key xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL", "[REDACTED:BIP32_KEY]");
'

echo "==> Asserting no internal references leaked into the published bundle"
PKG_DIR="$WORK/node_modules/@g8r-security/agent-shield-sdk"
if grep -riE 'local-first|private ip|vendored' "$PKG_DIR/dist" "$PKG_DIR/README.md"; then
  echo "    FAIL: internal reference found in published artifact"
  exit 1
fi
echo "    ok: published bundle is clean"

echo "✅ consumer smoke test passed"
