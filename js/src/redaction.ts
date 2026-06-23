/**
 * Local-First Sensitive Data Redaction
 *
 * Best-effort redaction of common secret and PII formats BEFORE prompts reach
 * the policy gateway. Covers cryptographic key formats, custodial identifiers,
 * high-entropy strings, and common PII (card numbers validated via Luhn, US
 * SSNs, email addresses, and phone numbers).
 *
 * IMPORTANT — this is a defense-in-depth layer, NOT a guarantee of completeness.
 * Pattern- and entropy-based redaction cannot catch every secret or PII shape
 * (e.g. unstructured PII, names, novel token formats, or values below the
 * entropy threshold). Do not rely on it as a sole control; keep downstream
 * safeguards and human review in place.
 *
 * It helps *support* (does not by itself satisfy) controls such as GDPR Art. 32
 * and PCI-DSS PAN-handling by reducing sensitive-data exposure to the gateway.
 */

export interface RedactionResult {
  /** The input with all sensitive tokens replaced by placeholder strings. */
  redacted: string;
  /** The original sensitive token strings that were replaced. */
  tokensReplaced: string[];
}

/**
 * Shannon entropy: calculates bits per character.
 * High entropy (> 4.5) indicates likely cryptographic material.
 */
function shannonEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ── Signing Key Patterns ─────────────────────────────────────────────────────

/** BIP-32 extended public/private keys: xpub, xprv, ypub, zpub, zprv, etc. */
const BIP32_PATTERN = /\b[xyz](?:pub|prv)[a-zA-Z0-9]{99,111}\b/g;

/**
 * WIF (Wallet Import Format) private keys.
 * Base58Check encoded, starts with 5 (uncompressed) or K/L (compressed), 51–52 chars.
 */
const WIF_PATTERN = /\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b/g;

/**
 * Raw hex 256-bit keys — exactly 64 hex characters, optionally 0x-prefixed.
 * Matches Ethereum private keys, secp256k1 scalars, etc.
 */
const HEX_KEY_PATTERN = /\b(?:0x)?[0-9a-fA-F]{64}\b/g;

/** PEM-encoded private or public key blocks (multi-line). */
const PEM_PATTERN =
  /-----BEGIN (?:RSA |EC |OPENSSH )?(?:PRIVATE|PUBLIC) KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?(?:PRIVATE|PUBLIC) KEY-----/g;

// ── Custodial ID Patterns ─────────────────────────────────────────────────────

/** Custodial-id format: `custodial-id:abc123xyz` */
const CUSTODIAL_ID_PATTERN = /\bcustodial-id:[A-Za-z0-9_-]+\b/g;

/** Short custodial references: `cust-98765` */
const CUST_PATTERN = /\bcust-\d+\b/gi;

/** Wallet identifiers: `wallet-id:wlt-abc999` */
const WALLET_ID_PATTERN = /\bwallet-id:[A-Za-z0-9_-]+\b/g;

/** Vault identifiers: `vault-id:v-secure-001` */
const VAULT_ID_PATTERN = /\bvault-id:[A-Za-z0-9_-]+\b/g;

// ── PII Patterns (best-effort) ────────────────────────────────────────────────

/** Email addresses. */
const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

/** US Social Security Numbers in dashed or spaced form, e.g. `123-45-6789`. */
const SSN_PATTERN = /\b\d{3}[ -]\d{2}[ -]\d{4}\b/g;

/**
 * Phone numbers with explicit separators (avoids matching arbitrary digit runs).
 * Optional country code, then 3-3-4 with space/dot/hyphen between groups.
 */
const PHONE_PATTERN = /\b(?:\+?\d{1,3}[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b/g;

/**
 * Candidate card-number runs: 13–19 digits with optional single space/hyphen
 * separators. Validated with Luhn before redacting to avoid false positives on
 * arbitrary long numbers (order/invoice IDs, etc.).
 */
const CARD_CANDIDATE_PATTERN = /\b\d(?:[ -]?\d){12,18}\b/g;

/**
 * Luhn checksum — used to gate card-number redaction so we only mask digit runs
 * that actually pass the check digit, not every long number.
 */
function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

// ── Entropy Detection Constants ───────────────────────────────────────────────

/** Minimum Shannon entropy (bits/char) to flag a token as likely cryptographic material. */
const ENTROPY_THRESHOLD = 4.5;

/** Minimum token length to apply entropy analysis (shorter strings are too ambiguous). */
const ENTROPY_MIN_LENGTH = 32;

/**
 * Find tokens in the string that exceed the entropy threshold.
 * Splits on whitespace and common delimiters to isolate candidates.
 */
function extractHighEntropyTokens(input: string): string[] {
  const candidates = input.split(/[\s,;:"'`(){}[\]<>]+/).filter(Boolean);
  return candidates.filter(
    (token) => token.length >= ENTROPY_MIN_LENGTH && shannonEntropy(token) >= ENTROPY_THRESHOLD
  );
}

/**
 * Redact sensitive data from a prompt string before it reaches the gateway.
 *
 * Processing order (important — PEM first to avoid splitting on inner patterns):
 * 1. PEM private/public key blocks
 * 2. BIP-32 extended keys
 * 3. WIF private keys
 * 4. Raw hex 256-bit keys
 * 5. Custodial IDs (all four variants)
 * 6. PII — card numbers (Luhn-validated), SSNs, emails, phone numbers
 * 7. High-entropy string catch-all
 */
export function redactSensitiveData(input: string): RedactionResult {
  const tokensReplaced: string[] = [];
  let redacted = input;

  function replaceAll(pattern: RegExp, label: string): void {
    redacted = redacted.replace(pattern, (match) => {
      tokensReplaced.push(match);
      return `[REDACTED:${label}]`;
    });
  }

  replaceAll(PEM_PATTERN, 'PEM_KEY');
  replaceAll(BIP32_PATTERN, 'BIP32_KEY');
  replaceAll(WIF_PATTERN, 'WIF_KEY');
  replaceAll(HEX_KEY_PATTERN, 'HEX_KEY');
  replaceAll(CUSTODIAL_ID_PATTERN, 'CUSTODIAL_ID');
  replaceAll(CUST_PATTERN, 'CUST_ID');
  replaceAll(WALLET_ID_PATTERN, 'WALLET_ID');
  replaceAll(VAULT_ID_PATTERN, 'VAULT_ID');

  // PII (best-effort). Card numbers first, gated by Luhn so we don't mask every
  // long digit run; then structured SSN / email / phone formats.
  redacted = redacted.replace(CARD_CANDIDATE_PATTERN, (match) => {
    const digits = match.replace(/\D/g, '');
    if (digits.length >= 13 && digits.length <= 19 && luhnValid(digits)) {
      tokensReplaced.push(match);
      return '[REDACTED:CARD]';
    }
    return match;
  });
  replaceAll(SSN_PATTERN, 'SSN');
  replaceAll(EMAIL_PATTERN, 'EMAIL');
  replaceAll(PHONE_PATTERN, 'PHONE');

  // High-entropy catch-all — runs on the already-redacted string to avoid double-replacing.
  const highEntropyTokens = extractHighEntropyTokens(redacted);
  for (const token of highEntropyTokens) {
    if (!redacted.includes(token)) continue;
    tokensReplaced.push(token);
    redacted = redacted.split(token).join('[REDACTED:HIGH_ENTROPY]');
  }

  return { redacted, tokensReplaced };
}
