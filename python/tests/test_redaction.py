"""
Tests for g8r_shield.redaction — the local-first redaction layer.

Covers each signing-key / custodial-id pattern, the high-entropy catch-all,
the clean-prompt no-op path, and that AgentShield redacts before any prompt
leaves the process — parity with the TypeScript SDK.
"""

from __future__ import annotations

import json

import responses

from g8r_shield.redaction import RedactionResult, redact_sensitive_data

from .conftest import CHECK_URL, LOG_URL, allowed_response, log_response

# A 44-char mixed-case alphanumeric token: high Shannon entropy, and it
# matches none of the signing-key / custodial-id patterns.
HIGH_ENTROPY_TOKEN = "Zq7Wm3Kx9Ld2Rp5Tn8Bv4Hc1Js6Yf0Ge3Uo7Ai2El5Dr"


class TestRedactSensitiveData:
    def test_clean_prompt_is_unchanged(self):
        result = redact_sensitive_data("What is our Q3 revenue forecast?")
        assert result.redacted == "What is our Q3 revenue forecast?"
        assert result.tokens_replaced == []

    def test_empty_string(self):
        result = redact_sensitive_data("")
        assert result == RedactionResult(redacted="", tokens_replaced=[])

    def test_redacts_hex_256bit_key(self):
        key = "0x" + "deadbeef" * 8  # 64 hex chars, 0x-prefixed
        result = redact_sensitive_data(f"sign with {key} please")
        assert "[REDACTED:HEX_KEY]" in result.redacted
        assert key not in result.redacted
        assert key in result.tokens_replaced

    def test_redacts_bip32_extended_key(self):
        key = "xprv" + "a1B2c3D4" * 13  # prefix + 104 alphanumerics
        result = redact_sensitive_data(f"wallet seed {key} here")
        assert "[REDACTED:BIP32_KEY]" in result.redacted
        assert key not in result.redacted

    def test_redacts_wif_private_key(self):
        key = "5" + "K" * 51  # [5KL] + 51 Base58 chars
        result = redact_sensitive_data(f"import {key} now")
        assert "[REDACTED:WIF_KEY]" in result.redacted
        assert key not in result.redacted

    def test_redacts_pem_block(self):
        pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4\n"
            "-----END PRIVATE KEY-----"
        )
        result = redact_sensitive_data(f"key follows:\n{pem}\nthanks")
        assert "[REDACTED:PEM_KEY]" in result.redacted
        assert "BEGIN PRIVATE KEY" not in result.redacted

    def test_redacts_custodial_id_variants(self):
        prompt = "refs: custodial-id:abc_123 cust-98765 wallet-id:wlt-9 vault-id:v-1"
        result = redact_sensitive_data(prompt)
        assert "[REDACTED:CUSTODIAL_ID]" in result.redacted
        assert "[REDACTED:CUST_ID]" in result.redacted
        assert "[REDACTED:WALLET_ID]" in result.redacted
        assert "[REDACTED:VAULT_ID]" in result.redacted
        assert len(result.tokens_replaced) == 4

    def test_redacts_high_entropy_token(self):
        result = redact_sensitive_data(f"the secret is {HIGH_ENTROPY_TOKEN} ok")
        assert "[REDACTED:HIGH_ENTROPY]" in result.redacted
        assert HIGH_ENTROPY_TOKEN not in result.redacted
        assert HIGH_ENTROPY_TOKEN in result.tokens_replaced

    def test_records_every_replaced_token(self):
        key = "0x" + "abcdef12" * 8
        result = redact_sensitive_data(f"{key} and custodial-id:xyz999")
        assert key in result.tokens_replaced
        assert "custodial-id:xyz999" in result.tokens_replaced

    def test_low_entropy_long_token_is_kept(self):
        # Long but repetitive — below the entropy threshold, must not redact.
        result = redact_sensitive_data("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        assert result.tokens_replaced == []


class TestAgentShieldRedaction:
    @responses.activate
    def test_check_redacts_before_send(self, shield):
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)
        key = "0x" + "deadbeef" * 8
        decision = shield.check(f"please sign {key}")

        # The /check POST must carry the redacted prompt, never the raw key.
        check_body = json.loads(responses.calls[0].request.body)
        assert key not in check_body["input"]
        assert "[REDACTED:HEX_KEY]" in check_body["input"]

        # The audit-log POST must be redacted too — no endpoint sees raw.
        log_body = json.loads(responses.calls[1].request.body)
        assert key not in log_body["input"]
        assert "[REDACTED:HEX_KEY]" in log_body["input"]

        # The decision surfaces what was stripped (parity with redactedTokens).
        assert key in decision.redacted_tokens

    @responses.activate
    def test_clean_prompt_has_empty_redacted_tokens(self, shield):
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        decision = shield.check("summarize the meeting notes", log=False)
        assert decision.redacted_tokens == []
