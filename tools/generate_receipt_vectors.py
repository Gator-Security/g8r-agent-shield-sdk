#!/usr/bin/env python3
"""Generate repeatable test fixtures. These public test keys are not for production."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from receipt_reference import (  # noqa: E402
    ALGORITHM, RECEIPT_TYPE, Ed25519PrivateKey, base64url, build_receipt_request,
    canonical_json, demo_decision, public_pem, request_hash, serialization,
)

NOW = 1_800_000_000
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
KID = "public-test-key-1"
ISSUER = "g8r-test-issuer"
AUDIENCE = "g8r-test-sdk"
HEADER = {"alg": ALGORITHM, "typ": RECEIPT_TYPE, "kid": KID}
CONFIG = {
    "issuer": ISSUER, "audience": AUDIENCE, "publicKeys": {KID: public_pem(KEY)},
    "clockSkewSeconds": 5, "maxLifetimeSeconds": 60,
}
BODY = {
    "downstream_url": "sdk://wrap", "method": "POST", "action_hint": "llm_prompt",
    "target_hint": "llm_prompt", "body": {"prompt": "demo:allow"},
    "correlation_id": "request-test-1", "action_type": "tool_call",
    "sessionId": "session-test-1", "parentAgents": ["root", "planner"],
}
HEADERS = {
    "Authorization": "Bearer never-hash-this-test-credential",
    "X-GF-Tenant-ID": "tenant-test", "X-GF-Agent-ID": "agent-test",
    "x-gf-session-id": "session-test-1", "x-gf-agent-chain": "planner,root",
    "x-gf-parent-agent-id": "planner",
}
REQUEST = build_receipt_request(
    endpoint="/decide", tenant_id="tenant-test", agent_id="agent-test",
    request_id="request-test-1", headers=HEADERS, body=BODY,
    nonce=base64url(bytes(range(64, 96))),
)


def claims_for(request: dict[str, Any], decision: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "version": 1, "iss": ISSUER, "aud": AUDIENCE, "iat": NOW, "exp": NOW + 30,
        "jti": "public-test-receipt-0001", "nonce": request["nonce"],
        "tenantId": request["tenantId"], "agentId": request["agentId"],
        "requestId": request["requestId"], "requestHash": request_hash(request),
        "decision": demo_decision("demo:allow") if decision is None else decision,
    }


def raw_sign(claims: Any, *, header: Any = None, key: Ed25519PrivateKey = KEY,
             header_bytes: bytes | None = None, payload_bytes: bytes | None = None) -> str:
    h = canonical_json(HEADER if header is None else header) if header_bytes is None else header_bytes
    p = canonical_json(claims) if payload_bytes is None else payload_bytes
    message = base64url(h) + "." + base64url(p)
    return message + "." + base64url(key.sign(message.encode("ascii")))


def main() -> None:
    base = claims_for(REQUEST)
    valid = raw_sign(base)
    cases: list[dict[str, Any]] = []

    def add(name: str, *, accept: bool = False, receipt: Any = valid,
            request: Any = None, claims: Any = None, header: Any = None,
            config: Any = None, now: int = NOW + 1, expected: str | None = None,
            **kwargs: Any) -> None:
        if claims is not None or header is not None or kwargs:
            receipt = raw_sign(base if claims is None else claims, header=header, **kwargs)
        cases.append({
            "name": name, "accept": accept, "receipt": receipt,
            "request": copy.deepcopy(REQUEST if request is None else request),
            "config": copy.deepcopy(CONFIG if config is None else config), "now": now,
            **({"decision": expected or (claims or base)["decision"]["decision"]} if accept else {}),
        })

    def changed_claim(name: str, field: str, value: Any) -> None:
        claims = copy.deepcopy(base); claims[field] = value; add(name, claims=claims)

    def changed_decision(name: str, field: str, value: Any) -> None:
        claims = copy.deepcopy(base); claims["decision"][field] = value; add(name, claims=claims)

    add("valid_allow", accept=True)
    for prompt in ("demo:deny", "demo:approval"):
        claims = claims_for(REQUEST, demo_decision(prompt))
        add("valid_" + prompt.split(":")[1], accept=True, claims=claims)
    pending = demo_decision("demo:deny"); pending["requiresApproval"] = True
    add("valid_pending_registration", accept=True, claims=claims_for(REQUEST, pending))
    revoked = demo_decision("demo:deny"); revoked["sessionRevoked"] = True
    add("valid_session_revoked", accept=True, claims=claims_for(REQUEST, revoked))
    mapping = copy.deepcopy(base)
    mapping["decision"]["complianceMappings"] = [{
        "regulation": "EXAMPLE-NOT-A-COMPLIANCE-CLAIM", "controlId": "test-1",
        "controlName": "Example", "description": "Test metadata only",
    }]
    add("valid_compliance_metadata", accept=True, claims=mapping)
    add("valid_just_before_skew_expiration", accept=True, now=NOW + 34)
    add("invalid_at_skew_expiration", now=NOW + 35)
    add("valid_iat_at_skew_limit", accept=True, now=NOW - 5)
    add("invalid_iat_beyond_skew_limit", now=NOW - 6)
    no_skew = {**CONFIG, "clockSkewSeconds": 0}
    add("valid_without_clock_skew", accept=True, config=no_skew, now=NOW + 29)
    add("expired_without_clock_skew", config=no_skew, now=NOW + 30)
    rotated = copy.deepcopy(CONFIG); rotated["publicKeys"]["public-test-key-2"] = public_pem(OTHER_KEY)
    add("valid_rotated_key", accept=True, config=rotated,
        header={**HEADER, "kid": "public-test-key-2"}, key=OTHER_KEY)
    add("valid_old_key_during_rotation", accept=True, config=rotated)
    retired = copy.deepcopy(rotated); retired["publicKeys"].pop(KID)
    add("retired_key_rejected", config=retired)
    console_body = {
        "input": "demo:allow", "tenantId": "tenant-test", "agentId": "agent-test",
        "requestId": "request-test-1", "department": "General", "userId": "unknown",
        "aiModel": "unknown",
    }
    console_request = build_receipt_request(
        endpoint="/api/sdk/v1/check", tenant_id="tenant-test", agent_id="agent-test",
        request_id="request-test-1", headers={}, body=console_body, nonce=REQUEST["nonce"],
    )
    add("valid_console_check", accept=True, request=console_request, claims=claims_for(console_request))
    unicode_request = copy.deepcopy(REQUEST)
    unicode_request["body"]["body"]["prompt"] = "Japanese: 日本語; Hebrew: שלום; emoji: 🚀; é / é"
    unicode_request["body"]["metadata"] = {"": 1, "😀": 2, "a": "\t\n\"\\/ "}
    add("valid_unicode_and_utf16_order", accept=True, request=unicode_request, claims=claims_for(unicode_request))
    reordered = dict(reversed(list(REQUEST.items())))
    reordered["body"] = dict(reversed(list(REQUEST["body"].items())))
    add("equivalent_object_key_order", accept=True, request=reordered)
    integer_request = copy.deepcopy(REQUEST)
    integer_request["body"]["metadata"] = [-9007199254740991, 0, 9007199254740991, True, False, None]
    add("valid_safe_integer_bounds", accept=True, request=integer_request, claims=claims_for(integer_request))

    for name, receipt in [("empty_token", ""), ("missing_token", None), ("object_token", {}),
                          ("two_segments", "a.b"), ("four_segments", "a.b.c.d"),
                          ("oversized_token", "x" * 65537), ("token_whitespace", " " + valid),
                          ("token_trailing_newline", valid + "\n")]:
        add(name, receipt=receipt)
    h, p, s = valid.split(".")
    add("base64url_padding", receipt=h + "." + p + "." + s + "=")
    add("base64url_bad_character", receipt=h + "." + p + "." + s[:-1] + "!")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    index = alphabet.index(s[-1]); alternative = alphabet[index | 1]
    add("noncanonical_signature_pad_bits", receipt=h + "." + p + "." + s[:-1] + alternative)
    add("signature_tampered", receipt=h + "." + p + "." + ("A" if s[0] != "A" else "B") + s[1:])
    add("signature_short", receipt=h + "." + p + "." + base64url(bytes(63)))
    add("signature_long", receipt=h + "." + p + "." + base64url(bytes(65)))
    altered = copy.deepcopy(base); altered["decision"]["reason"] = "tampered"
    add("payload_tampered_without_resigning", receipt=h + "." + base64url(canonical_json(altered)) + "." + s)
    add("signature_from_untrusted_key", key=OTHER_KEY)
    for alg in ("none", "HS256", "EdDSA", "Ed448", "RS256"):
        add("forbidden_algorithm_" + alg, header={**HEADER, "alg": alg})
    for typ in ("JWT", "other-token+jwt", "g8r-decision-receipt+jwt "):
        add("wrong_type_" + typ.strip(), header={**HEADER, "typ": typ})
    add("unknown_key", header={**HEADER, "kid": "unknown"})
    add("kid_newline", header={**HEADER, "kid": KID + "\n"})
    add("kid_not_string", header={**HEADER, "kid": [KID]})
    for field, value in [("jwk", {"kty": "OKP"}), ("jku", "https://attacker.invalid/keys"),
                         ("x5u", "https://attacker.invalid/cert"), ("crit", ["extra"]),
                         ("b64", False), ("extra", True)]:
        add("forbidden_header_" + field, header={**HEADER, field: value})
    add("duplicate_header_member", header_bytes=(canonical_json(HEADER)[:-1] + b',"alg":"Ed25519"}'))
    add("noncanonical_header_order", header_bytes=json.dumps(HEADER, separators=(",", ":")).encode())
    add("header_invalid_utf8", header_bytes=b'\xff')
    add("payload_invalid_utf8", payload_bytes=b'\xff')
    add("payload_utf8_bom", payload_bytes=b'\xef\xbb\xbf' + canonical_json(base))
    add("duplicate_payload_member", payload_bytes=canonical_json(base)[:-1] + b',"version":1}')
    add("payload_whitespace", payload_bytes=b' ' + canonical_json(base))
    add("noncanonical_numeric_encoding", payload_bytes=canonical_json(base).replace(b'"version":1', b'"version":1.0'))
    add("noncanonical_unicode_escape", payload_bytes=canonical_json(base).replace(b'g8r-test-issuer', b'g8r-test-issue\\u0072'))
    add("payload_array", payload_bytes=b'[]')
    add("payload_not_json", payload_bytes=b'not-json')
    for field, value in [("iss", "wrong"), ("aud", "wrong"), ("aud", [AUDIENCE]),
                         ("tenantId", "other-tenant"), ("agentId", "other-agent"),
                         ("requestId", "other-request"), ("nonce", base64url(bytes(32))),
                         ("nonce", None), ("requestHash", "0" * 64),
                         ("requestHash", base["requestHash"].upper()),
                         ("requestHash", base["requestHash"] + "\n"),
                         ("version", 2), ("version", True), ("version", "1"),
                         ("jti", "short"), ("jti", "non-ascii-日本語-receipt-id"),
                         ("jti", "test-receipt-id\n"), ("exp", NOW), ("exp", NOW + 61),
                         ("iat", -1), ("iat", str(NOW)), ("iat", True), ("exp", None)]:
        changed_claim(f"invalid_claim_{field}_{len(cases)}", field, value)
    for field in sorted(base):
        missing = copy.deepcopy(base); missing.pop(field); add("missing_claim_" + field, claims=missing)
    changed_claim("unknown_claim_conditions", "conditions", ["human-approval"])
    changed_claim("decision_not_object", "decision", "allowed")
    for field, value in [("decision", "ALLOW"), ("decision", "unknown"),
                         ("requiresApproval", "false"), ("requiresApproval", 0),
                         ("requiresApproval", True), ("sessionRevoked", True),
                         ("reason", 123), ("reason", "x" * 4097), ("violatedRule", ""),
                         ("complianceMappings", {}), ("complianceMappings", [{}]),
                         ("conditions", ["approval"]), ("reason", "🚀" * 1025)]:
        changed_decision(f"invalid_decision_{field}_{len(cases)}", field, value)
    for field in sorted(base["decision"]):
        missing = copy.deepcopy(base); missing["decision"].pop(field)
        add("missing_decision_field_" + field, claims=missing)
    malformed_escalation = claims_for(REQUEST, demo_decision("demo:approval"))
    malformed_escalation["decision"]["requiresApproval"] = False
    add("escalation_without_approval", claims=malformed_escalation)
    contradictory_revocation = claims_for(REQUEST, pending)
    contradictory_revocation["decision"]["sessionRevoked"] = True
    add("revocation_with_pending_approval", claims=contradictory_revocation)

    for field, value in [("nonce", base64url(bytes(32))), ("endpoint", "/other"),
                         ("method", "GET"), ("version", 2), ("tenantId", "other"),
                         ("agentId", "other"), ("requestId", "other")]:
        altered_request = copy.deepcopy(REQUEST); altered_request[field] = value
        add("request_changed_" + field, request=altered_request)
    for name, mutation in [
        ("prompt", lambda r: r["body"]["body"].update(prompt="different")),
        ("session_header", lambda r: r["governanceHeaders"].update({"x-gf-session-id": "different"})),
        ("new_governance_header", lambda r: r["governanceHeaders"].update({"x-gf-new": "different"})),
        ("parent_order", lambda r: r["body"].update(parentAgents=["planner", "root"])),
        ("department", lambda r: r["body"].update(department="Finance")),
        ("nonce_padding", lambda r: r.update(nonce=r["nonce"] + "=")),
        ("header_case", lambda r: r["governanceHeaders"].update({"X-GF-Test": "value"})),
        ("header_newline", lambda r: r["governanceHeaders"].update({"x-gf-extra": "value\n"})),
    ]:
        altered_request = copy.deepcopy(REQUEST); mutation(altered_request)
        add("request_changed_" + name, request=altered_request)
    add("cross_endpoint_receipt_swap", request=console_request)
    for name, config in [
        ("zero_trusted_keys", {**CONFIG, "publicKeys": {}}),
        ("private_key_in_config", {**CONFIG, "publicKeys": {KID: KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()}}),
        ("malformed_public_key", {**CONFIG, "publicKeys": {KID: "not a public key"}}),
        ("wrong_public_key", {**CONFIG, "publicKeys": {KID: public_pem(OTHER_KEY)}}),
        ("excessive_clock_skew", {**CONFIG, "clockSkewSeconds": 31}),
        ("negative_clock_skew", {**CONFIG, "clockSkewSeconds": -1}),
        ("zero_max_lifetime", {**CONFIG, "maxLifetimeSeconds": 0}),
        ("excessive_max_lifetime", {**CONFIG, "maxLifetimeSeconds": 301}),
        ("boolean_clock_skew", {**CONFIG, "clockSkewSeconds": True}),
    ]:
        add(name, config=config)

    canonical_values: list[tuple[str, Any]] = [
        ("utf16_property_order", {"": 1, "😀": 2, "\r": 3, "a": 4, "1": 5}),
        ("control_characters", "\b\t\n\f\r\x00\x1f\"\\/  "),
        ("no_unicode_normalization", ["é", "é"]),
        ("nested_integer_profile", {"a": [-9007199254740991, 0, 9007199254740991], "b": True, "c": None}),
        ("prototype_named_properties", {"__proto__": {"polluted": True}, "constructor": "data"}),
    ]
    result = {
        "warning": "PUBLIC, PREDICTABLE TEST KEYS. NEVER USE AS A PRODUCTION TRUST ANCHOR.",
        "format": "g8r-decision-receipts-test-v1", "now": NOW,
        "testOnlyPrivateKeyPem": KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
        "baseRequest": REQUEST, "baseClaims": base, "baseHeader": HEADER,
        "requestCanonicalBase64": base64url(canonical_json(REQUEST)), "requestHash": request_hash(REQUEST),
        "validReceipt": valid, "config": CONFIG,
        "canonicalCases": [{"name": name, "value": val, "canonicalBase64": base64url(canonical_json(val))} for name, val in canonical_values],
        "cases": cases,
    }
    target = ROOT / "test-vectors" / "decision-receipts-v1.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n")
    print(f"Wrote {len(cases)} shared receipt cases and {len(canonical_values)} canonicalization cases")


if __name__ == "__main__":
    main()
