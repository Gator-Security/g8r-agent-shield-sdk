"""
BitGo VPC sensitive-data redaction.

Redacts cryptographic keys, custodial identifiers, and high-entropy strings
BEFORE prompts reach the G8R policy gateway — a local-first redaction layer.
This is the Python parity port of the TypeScript SDK's ``redaction.ts``.

Compliance:
  - GDPR Art. 32: Security of Processing — appropriate technical measures.
  - PCI-DSS 3.4: Render sensitive data unreadable wherever transmitted.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field


@dataclass(frozen=True)
class RedactionResult:
    """Outcome of redacting a prompt before it leaves the process."""

    # The input with every sensitive token replaced by a placeholder.
    redacted: str
    # The original sensitive token strings that were replaced.
    tokens_replaced: list[str] = field(default_factory=list)


def _shannon_entropy(value: str) -> float:
    """Return Shannon entropy in bits per character.

    High entropy (> 4.5) indicates likely cryptographic material.
    """
    if not value:
        return 0.0
    length = len(value)
    entropy = 0.0
    for count in Counter(value).values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


# ── Signing-key patterns ─────────────────────────────────────────────────────

#: BIP-32 extended public/private keys: xpub, xprv, ypub, zpub, zprv, etc.
_BIP32_PATTERN = re.compile(r"\b[xyz](?:pub|prv)[a-zA-Z0-9]{99,111}\b")

#: WIF (Wallet Import Format) private keys — Base58Check, 51-52 chars.
_WIF_PATTERN = re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")

#: Raw hex 256-bit keys — exactly 64 hex chars, optionally 0x-prefixed.
_HEX_KEY_PATTERN = re.compile(r"\b(?:0x)?[0-9a-fA-F]{64}\b")

#: PEM-encoded private/public key blocks (multi-line).
_PEM_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?(?:PRIVATE|PUBLIC) KEY-----"
    r"[\s\S]*?"
    r"-----END (?:RSA |EC |OPENSSH )?(?:PRIVATE|PUBLIC) KEY-----"
)

# ── Custodial-id patterns ────────────────────────────────────────────────────

_CUSTODIAL_ID_PATTERN = re.compile(r"\bcustodial-id:[A-Za-z0-9_-]+\b")
_CUST_PATTERN = re.compile(r"\bcust-\d+\b", re.IGNORECASE)
_WALLET_ID_PATTERN = re.compile(r"\bwallet-id:[A-Za-z0-9_-]+\b")
_VAULT_ID_PATTERN = re.compile(r"\bvault-id:[A-Za-z0-9_-]+\b")

#: Labelled patterns applied in order. PEM first so its multi-line body is
#: not split on inner patterns; custodial ids before the high-entropy
#: catch-all.
_LABELLED_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_PEM_PATTERN, "PEM_KEY"),
    (_BIP32_PATTERN, "BIP32_KEY"),
    (_WIF_PATTERN, "WIF_KEY"),
    (_HEX_KEY_PATTERN, "HEX_KEY"),
    (_CUSTODIAL_ID_PATTERN, "CUSTODIAL_ID"),
    (_CUST_PATTERN, "CUST_ID"),
    (_WALLET_ID_PATTERN, "WALLET_ID"),
    (_VAULT_ID_PATTERN, "VAULT_ID"),
)

# ── Entropy-detection constants ──────────────────────────────────────────────

#: Minimum Shannon entropy (bits/char) to flag a token as crypto material.
_ENTROPY_THRESHOLD = 4.5

#: Minimum token length for entropy analysis (shorter strings are ambiguous).
_ENTROPY_MIN_LENGTH = 32

#: Delimiters that isolate candidate tokens for entropy analysis.
_TOKEN_DELIMITERS = re.compile(r"""[\s,;:"'`(){}\[\]<>]+""")


def _extract_high_entropy_tokens(value: str) -> list[str]:
    """Return tokens above the entropy threshold.

    Splits on whitespace and common delimiters to isolate candidates.
    """
    return [
        token
        for token in _TOKEN_DELIMITERS.split(value)
        if token
        and len(token) >= _ENTROPY_MIN_LENGTH
        and _shannon_entropy(token) >= _ENTROPY_THRESHOLD
    ]


def redact_sensitive_data(value: str) -> RedactionResult:
    """Redact sensitive data from a prompt before it reaches the gateway.

    Processing order — PEM blocks first (so the body is not split on inner
    patterns), then BIP-32 / WIF / raw-hex keys, then the four custodial-id
    variants, then a high-entropy catch-all run on the already-redacted text.
    """
    tokens_replaced: list[str] = []
    redacted = value

    for pattern, label in _LABELLED_PATTERNS:
        matches = [match.group(0) for match in pattern.finditer(redacted)]
        if not matches:
            continue
        tokens_replaced.extend(matches)
        redacted = pattern.sub(f"[REDACTED:{label}]", redacted)

    # High-entropy catch-all — on the already-redacted string, so tokens the
    # labelled patterns already replaced are not double-counted.
    for token in _extract_high_entropy_tokens(redacted):
        if token not in redacted:
            continue
        tokens_replaced.append(token)
        redacted = redacted.replace(token, "[REDACTED:HIGH_ENTROPY]")

    return RedactionResult(redacted=redacted, tokens_replaced=tokens_replaced)
