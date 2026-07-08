#!/usr/bin/env bash
#
# Consumer smoke test.
#
# Builds and packs the SDK, then installs the resulting tarball into a throwaway
# project exactly as a customer would — and verifies that the public API
# type-checks and that redaction actually fires. This catches the class of bug
# that unit tests miss because they import from `src/` directly: missing exports,
# broken `exports` maps, and raw-TS publishing.
#
# It also runs an internal-reference guard that greps the JS + Python SOURCE
# trees and every customer-facing README (not just the packed dist, whose
# minification would strip readable .ts comment leaks) for internal markers —
# dev artifacts, internal spec refs, internal architecture names, proprietary
# logic identifiers, crosswalk helpers, and known historical codenames — and
# fails the build with the offending file+line if any leak is found.
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
const _err: Error = new ShieldBlockedError('block', 'blocked', null, []);
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

echo "==> Asserting no internal references leaked into source or published artifacts"
PKG_DIR="$WORK/node_modules/@g8r-security/agent-shield-sdk"
# Repo (monorepo) root, computed from this script's own location so the guard
# works regardless of the caller's cwd. Script lives at <root>/js/scripts.
REPO_ROOT="$(dirname "$SDK_DIR")"

# Internal-reference markers. grep -riE, boundary-anchored (\b) so short tokens
# like T3 or I-4 don't match ordinary words. Grouped by category:
#
#   dev-artifact      leftover work markers (bug ids, TODO/FIXME/HACK/XXX)
#   internal-spec-ref internal roadmap / spec / foundation identifiers
#   internal-arch     internal service + module names never shipped to users
#   proprietary-logic internal detector/judge identifiers
#   crosswalk         internal verdict/rollup helper names
#   codenames         specific historical codenames + partner phrasings
#
# NOTE: bare C01..C08 are PUBLISHED architecture labels and are intentionally
# NOT flagged — only C0N-N SUB-refs (a hyphen + digit) match via \bC0[0-9]-[0-9].
INTERNAL_MARKERS='BUG-[0-9]{2,4}|\b(TODO|FIXME|HACK|XXX)\b'                            # dev-artifact
INTERNAL_MARKERS+='|foundation-[0-9]|\bF0[0-9]\b|\bR-P[0-9]|\bIMP-[0-9]|\brm-w[0-9]'  # internal-spec-ref
INTERNAL_MARKERS+='|\baprs-?[0-9]|\bRM-PR[0-9]|\bI-[0-9]\b|\bSB-[0-9A-Z]\b'           # internal-spec-ref
INTERNAL_MARKERS+='|\bC0[0-9]-[0-9]|\bT[0-9][a-z]?\b|pdp-legacy'                      # internal-spec-ref
INTERNAL_MARKERS+='|gf-(compliance|identity|pdp|egress|management|audit|registry)'   # internal-arch
INTERNAL_MARKERS+='|internal/(pdp|detect|judge|benchmark)'                           # internal-arch
INTERNAL_MARKERS+='|llm_judge|requiredDetectors|slow.?detector|F8 judge'             # proprietary-logic
INTERNAL_MARKERS+='|compute_control_verdict|compute_domain_rollup'                   # crosswalk
INTERNAL_MARKERS+='|\bC2\b|\bG1\b|\bG2\b|unauthorized partner data access|filevine'  # codenames

# Scan the SOURCE trees + every customer-facing README, plus the packed dist as
# belt-and-suspenders. tsup minification strips .ts comments, so a dist-only
# scan misses readable source leaks — hence the source-tree scan is primary.
INTERNAL_SCAN_TARGETS=()
for t in \
  "$REPO_ROOT/js/src" \
  "$REPO_ROOT/python/g8r_shield" \
  "$REPO_ROOT/python"/example_*.py \
  "$REPO_ROOT/python/README.md" \
  "$REPO_ROOT/js/README.md" \
  "$REPO_ROOT/README.md" \
  "$PKG_DIR/dist" \
  "$PKG_DIR/README.md" \
; do
  [ -e "$t" ] && INTERNAL_SCAN_TARGETS+=("$t")
done

# grep -n prints file:line:match; -r recurses the src dirs; -H forces the
# filename prefix even when a single file is passed, so hits are always
# attributable (-H is portable to both BSD/macOS and GNU/Linux grep, unlike the
# GNU-only --with-filename long form). A match means a leak -> fail; no match is
# the clean path.
if grep -rniE -H --exclude-dir=__pycache__ --exclude='*.pyc' --exclude='*.map' "$INTERNAL_MARKERS" "${INTERNAL_SCAN_TARGETS[@]}"; then
  echo "    FAIL: internal reference found (file:line printed above)"
  exit 1
fi
echo "    ok: no internal references in source, READMEs, or published bundle"

echo "✅ consumer smoke test passed"
