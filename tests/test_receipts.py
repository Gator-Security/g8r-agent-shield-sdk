"""Standalone receipt tests. Run with tools/run_receipt_tests.py."""
from __future__ import annotations

import copy
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python" / "g8r_shield"))
sys.path.insert(0, str(ROOT / "tools"))
from receipts import (
    ReceiptVerificationConfig, ReceiptVerificationError, ReceiptVerifier,
    assert_receipt_transport, base64url, build_receipt_request, canonical_json,
    parse_json, request_hash,
)
from receipt_reference import (
    DEV_AUDIENCE, DEV_ISSUER, DEV_KID, DEV_TOKEN, make_server,
    public_pem, run_demo, sign_decision, demo_decision, write_exclusive,
)

VECTORS = json.loads((ROOT / "test-vectors" / "decision-receipts-v1.json").read_text())


def config_from_wire(value):
    return ReceiptVerificationConfig(
        issuer=value["issuer"], audience=value["audience"], public_keys=value["publicKeys"],
        clock_skew_seconds=value.get("clockSkewSeconds", 5),
        max_lifetime_seconds=value.get("maxLifetimeSeconds", 60),
    )


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_shared_receipt_vectors(case):
    if case["accept"]:
        receipt = ReceiptVerifier(config_from_wire(case["config"])).verify(
            case["receipt"], case["request"], now=case["now"],
        )
        assert receipt.decision["decision"] == case["decision"]
        assert receipt.token == case["receipt"]
    else:
        with pytest.raises(ReceiptVerificationError):
            ReceiptVerifier(config_from_wire(case["config"])).verify(
                case["receipt"], case["request"], now=case["now"],
            )


@pytest.mark.parametrize("case", VECTORS["canonicalCases"], ids=lambda c: c["name"])
def test_canonical_bytes(case):
    assert base64url(canonical_json(case["value"])) == case["canonicalBase64"]


def test_request_digest_golden():
    assert request_hash(VECTORS["baseRequest"]) == VECTORS["requestHash"]
    assert base64url(canonical_json(VECTORS["baseRequest"])) == VECTORS["requestCanonicalBase64"]


@pytest.mark.parametrize("value", [1.5, 1.0, float("nan"), float("inf"), 9007199254740992,
                                 -9007199254740992, b"not-json", {1: "bad-key"}, "\ud800"])
def test_unsupported_canonical_values(value):
    with pytest.raises(ReceiptVerificationError):
        canonical_json(value)


def test_structure_and_size_limits():
    cyclic = []; cyclic.append(cyclic)
    deep = None
    for _ in range(35):
        deep = [deep]
    for value in (cyclic, deep, "x" * 1048577, [None] * 100001):
        with pytest.raises(ReceiptVerificationError):
            canonical_json(value)


@pytest.mark.parametrize("data", [b'{"a":1,"a":2}', b'\xff', b'NaN', b'Infinity',
                                 b'{"a":1.1}', b'{"a":9007199254740992}', b'{"a":"\\ud800"}'])
def test_strict_request_json_parser(data):
    with pytest.raises(ReceiptVerificationError):
        parse_json(data)


def test_fresh_nonce_snapshot_and_credentials_excluded():
    original = copy.deepcopy(VECTORS["baseRequest"])
    kwargs = dict(
        endpoint=original["endpoint"], tenant_id=original["tenantId"],
        agent_id=original["agentId"], request_id=original["requestId"],
        headers={**original["governanceHeaders"], "Authorization": "Bearer sensitive-test"},
        body=original["body"],
    )
    first, second = build_receipt_request(**kwargs), build_receipt_request(**kwargs)
    assert first["nonce"] != second["nonce"]
    assert request_hash(first) != request_hash(second)
    assert b"sensitive-test" not in canonical_json(first)
    kwargs["body"]["body"]["prompt"] = "changed"
    kwargs["headers"]["x-gf-agent-id"] = "changed"
    assert first["body"]["body"]["prompt"] == "demo:allow"
    assert first["governanceHeaders"]["x-gf-agent-id"] == "agent-test"


def test_duplicate_case_insensitive_governance_header_rejected():
    r = VECTORS["baseRequest"]
    with pytest.raises(ReceiptVerificationError):
        build_receipt_request(
            endpoint=r["endpoint"], tenant_id=r["tenantId"], agent_id=r["agentId"],
            request_id=r["requestId"], body=r["body"],
            headers={**r["governanceHeaders"], "X-GF-Agent-ID": "agent-test"},
        )


def test_unsigned_outer_allow_cannot_override_signed_deny():
    case = next(c for c in VECTORS["cases"] if c["name"] == "valid_deny")
    receipt = ReceiptVerifier(config_from_wire(case["config"])).verify_response(
        {"receipt": case["receipt"], "decision": "allowed", "requiresApproval": False},
        case["request"], now=case["now"],
    )
    assert receipt.decision["decision"] == "blocked"


@pytest.mark.parametrize("response", [{"decision": "allowed"}, {}, None, [], {"receipt": None}])
def test_required_receipt_never_downgrades(response):
    with pytest.raises(ReceiptVerificationError):
        ReceiptVerifier(config_from_wire(VECTORS["config"])).verify_response(
            response, VECTORS["baseRequest"], now=VECTORS["now"],
        )


@pytest.mark.parametrize("case_name", ["valid_deny", "valid_compliance_metadata"])
def test_returned_claims_cannot_change_verified_result(case_name):
    case = next(c for c in VECTORS["cases"] if c["name"] == case_name)
    receipt = ReceiptVerifier(config_from_wire(case["config"])).verify(
        case["receipt"], case["request"], now=case["now"],
    )
    original = copy.deepcopy(receipt.claims)
    returned = receipt.claims
    returned["tenantId"] = "changed-tenant"
    returned["decision"]["decision"] = "escalated"
    returned["decision"]["complianceMappings"].append({"controlId": "changed"})
    receipt.decision["complianceMappings"].clear()
    assert receipt.claims == original
    assert receipt.decision == original["decision"]
    assert receipt.token == case["receipt"]


def test_low_level_verification_is_not_token_consumption():
    verifier = ReceiptVerifier(config_from_wire(VECTORS["config"]))
    first = verifier.verify(VECTORS["validReceipt"], VECTORS["baseRequest"], now=VECTORS["now"])
    second = verifier.verify(VECTORS["validReceipt"], VECTORS["baseRequest"], now=VECTORS["now"])
    assert first.token == second.token


def test_key_configuration_snapshot_and_wrong_curve():
    cfg = copy.deepcopy(VECTORS["config"])
    verifier = ReceiptVerifier(config_from_wire(cfg))
    cfg["publicKeys"].clear()
    assert verifier.verify(VECTORS["validReceipt"], VECTORS["baseRequest"], now=VECTORS["now"])
    wrong_curve = Ed448PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    with pytest.raises(ReceiptVerificationError):
        ReceiptVerifier(ReceiptVerificationConfig("issuer", "audience", {"key": wrong_curve}))


@pytest.mark.parametrize("url", ["http://example.com", "ftp://example.com", "https://a:b@example.com",
                                "https://example.com/#fragment", "https://example.com/?q=x", "not-a-url",
                                "https://exam\nple.com"])
def test_signed_sdk_transport_restrictions(url):
    with pytest.raises(ReceiptVerificationError):
        assert_receipt_transport(url)


def test_valid_https_transport():
    assert_receipt_transport("https://pep.example.com:8443/prefix")


def test_reference_signer_rejects_invalid_decision():
    key = Ed25519PrivateKey.generate()
    invalid = demo_decision("demo:allow"); invalid["requiresApproval"] = True
    with pytest.raises(ReceiptVerificationError):
        sign_decision(key, kid="key", issuer="issuer", audience="audience",
                      request=VECTORS["baseRequest"], decision=invalid)


@pytest.fixture
def mock_server(tmp_path):
    key = Ed25519PrivateKey.generate()
    public_file = tmp_path / "public.pem"; public_file.write_text(public_pem(key))
    server = make_server(key, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        yield server.server_port, public_file
    finally:
        server.shutdown(); thread.join(timeout=5); server.server_close()


def test_python_live_mock_demo(mock_server):
    port, public_file = mock_server
    assert run_demo(public_file, port) == ["allowed", "blocked", "escalated"]


def test_typescript_live_mock_both_endpoints(mock_server):
    if not os.environ.get("G8R_RECEIPTS_JS"):
        pytest.skip("Run tools/run_receipt_tests.py to compile TypeScript and enable live cross-language test")
    port, public_file = mock_server
    process = subprocess.run(
        ["node", str(ROOT / "tests" / "live_receipt_client.cjs"), str(port), str(public_file)],
        text=True, capture_output=True, timeout=20, check=True,
    )
    assert "6 signed evaluations verified" in process.stdout


@pytest.mark.parametrize("path,headers,body,status", [
    ("/decide", {}, b'{}', 401),
    ("/unknown", {}, b'{}', 404),
    ("/decide", {"Authorization": "Bearer " + DEV_TOKEN, "Content-Type": "application/json"}, b'{"a":1,"a":2}', 400),
    ("/decide", {"Authorization": "Bearer " + DEV_TOKEN, "Content-Type": "application/json"}, b'{}', 400),
])
def test_mock_rejects_invalid_requests(mock_server, path, headers, body, status):
    connection = http.client.HTTPConnection("127.0.0.1", mock_server[0], timeout=5)
    try:
        connection.request("POST", path, body, headers)
        response = connection.getresponse(); response.read()
        assert response.status == status
    finally:
        connection.close()


def test_generated_key_permissions_and_no_overwrite(tmp_path):
    target = tmp_path / "key.pem"
    write_exclusive(target, b"test", 0o600)
    assert target.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        write_exclusive(target, b"overwrite", 0o600)
    assert target.read_bytes() == b"test"
