#!/usr/bin/env python3
"""Development signer and local mock PEP. Not a production policy service.

This signs three fixed demo decisions. It does not run Cedar, authenticate real
identities, control tools, track receipt use, or write audit records.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
from pathlib import Path
import secrets
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
import uuid

# Allow the demo to run from this bundle without installing the full SDK.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python" / "g8r_shield"))
from receipts import (  # noqa: E402
    ALGORITHM, RECEIPT_TYPE, ENDPOINTS, MAX_JSON_BYTES,
    ReceiptVerificationConfig, ReceiptVerificationError, ReceiptVerifier,
    base64url, build_receipt_request, canonical_json, parse_json, request_hash,
    validate_decision,
)
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

DEV_ISSUER = "g8r-development-mock"
DEV_AUDIENCE = "g8r-sdk-development"
DEV_TOKEN = "development-only-not-a-production-credential"
DEV_KID = "development-key-1"


def public_pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def sign_decision(
    key: Ed25519PrivateKey, *, kid: str, issuer: str, audience: str,
    request: dict[str, Any], decision: dict[str, Any],
    now: int | None = None, lifetime: int = 30,
) -> str:
    """Sign a decision. Keep the private key on the service, not in the SDK.

    The real service must authenticate the caller and evaluate policy first.
    This helper only creates the receipt.
    """
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected an Ed25519 private key")
    if type(lifetime) is not int or not 1 <= lifetime <= 60:
        raise ValueError("Reference signer lifetime must be 1..60 seconds")
    issued = int(time.time()) if now is None else now
    validate_decision(decision)
    claims = {
        "version": 1, "iss": issuer, "aud": audience,
        "iat": issued, "exp": issued + lifetime, "jti": str(uuid.uuid4()),
        "nonce": request["nonce"], "tenantId": request["tenantId"],
        "agentId": request["agentId"], "requestId": request["requestId"],
        "requestHash": request_hash(request), "decision": decision,
    }
    header = {"alg": ALGORITHM, "typ": RECEIPT_TYPE, "kid": kid}
    signing_input = (base64url(canonical_json(header)) + "." + base64url(canonical_json(claims)))
    token = signing_input + "." + base64url(key.sign(signing_input.encode("ascii")))
    ReceiptVerifier(ReceiptVerificationConfig(
        issuer=issuer, audience=audience, public_keys={kid: public_pem(key)},
    )).verify(token, request, now=issued)
    return token


def demo_decision(prompt: str) -> dict[str, Any]:
    outcomes = {"demo:allow": "allowed", "demo:deny": "blocked", "demo:approval": "escalated"}
    if prompt not in outcomes:
        raise ValueError("Only demo:allow, demo:deny, and demo:approval are supported")
    outcome = outcomes[prompt]
    return {
        "decision": outcome, "reason": "Development demonstration only; no Cedar evaluation",
        "violatedRule": None if outcome == "allowed" else "development-example-rule",
        "requiresApproval": outcome == "escalated", "sessionRevoked": False,
        "complianceMappings": [],
    }


def make_server(
    key: Ed25519PrivateKey, *, port: int = 8765, kid: str = DEV_KID,
    issuer: str = DEV_ISSUER, audience: str = DEV_AUDIENCE,
) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "G8R-Development-Mock/1"

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, fmt: str, *args: Any) -> None:
            pass

        def respond(self, status: int, value: dict[str, Any]) -> None:
            data = canonical_json(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:
            if self.path not in ENDPOINTS:
                self.respond(404, {"error": "unknown endpoint"})
                return
            for header in self.headers.keys():
                if len(self.headers.get_all(header) or []) != 1:
                    self.respond(400, {"error": "duplicate HTTP header"})
                    return
            if not secrets.compare_digest(
                self.headers.get("Authorization", ""), "Bearer " + DEV_TOKEN,
            ):
                self.respond(401, {"error": "development credential required"})
                return
            if (self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json"):
                self.respond(400, {"error": "expected length-delimited JSON"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= length <= MAX_JSON_BYTES:
                    raise ValueError("invalid content length")
                data = self.rfile.read(length)
                if len(data) != length:
                    raise ValueError("incomplete body")
                body = parse_json(data)
                if type(body) is not dict or self.headers.get("X-G8R-Receipt-Version") != "1":
                    raise ValueError("receipt protocol v1 required")
                if self.path == "/decide":
                    tenant = self.headers.get("X-GF-Tenant-ID", "")
                    agent = self.headers.get("X-GF-Agent-ID", "")
                    request_id = body.get("correlation_id", "")
                    prompt = body["body"]["prompt"]
                else:
                    tenant = body.get("tenantId", "")
                    agent = body.get("agentId", "")
                    request_id = body.get("requestId", "")
                    prompt = body["input"]
                request = build_receipt_request(
                    endpoint=self.path, tenant_id=tenant, agent_id=agent, request_id=request_id,
                    headers=dict(self.headers.items()), body=body,
                    nonce=self.headers.get("X-G8R-Receipt-Nonce", ""),
                )
                receipt = sign_decision(
                    key, kid=kid, issuer=issuer, audience=audience,
                    request=request, decision=demo_decision(prompt),
                )
            except (ValueError, KeyError, TypeError, OSError, ReceiptVerificationError):
                self.respond(400, {"error": "invalid development request"})
                return
            self.respond(200, {"receipt": receipt})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


def load_private(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected an Ed25519 private key")
    return key


def write_exclusive(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def run_demo(public_key_file: Path, port: int) -> list[str]:
    verifier = ReceiptVerifier(ReceiptVerificationConfig(
        issuer=DEV_ISSUER, audience=DEV_AUDIENCE,
        public_keys={DEV_KID: public_key_file.read_text()},
    ))
    outcomes: list[str] = []
    for prompt in ("demo:allow", "demo:deny", "demo:approval"):
        request_id = str(uuid.uuid4())
        headers = {
            "Authorization": "Bearer " + DEV_TOKEN, "Content-Type": "application/json",
            "X-GF-Tenant-ID": "development-tenant", "X-GF-Agent-ID": "development-agent",
        }
        body = {
            "downstream_url": "sdk://wrap", "method": "POST", "action_hint": "llm_prompt",
            "target_hint": "llm_prompt", "body": {"prompt": prompt},
            "correlation_id": request_id, "action_type": "tool_call",
        }
        request = build_receipt_request(
            endpoint="/decide", tenant_id="development-tenant", agent_id="development-agent",
            request_id=request_id, headers=headers, body=body,
        )
        headers["X-G8R-Receipt-Nonce"] = request["nonce"]
        headers["X-G8R-Receipt-Version"] = "1"
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("POST", "/decide", canonical_json(body), headers)
            response = connection.getresponse()
            data = response.read(MAX_JSON_BYTES + 1)
            if response.status != 200:
                raise RuntimeError(f"Mock returned HTTP {response.status}")
        finally:
            connection.close()
        receipt = verifier.verify_response(parse_json(data), request)
        decision = receipt.decision["decision"]
        outcomes.append(decision)
        print(f"{prompt}: signature verified, decision={decision}, "
              f"demo callback {'may run' if decision == 'allowed' else 'must not run'}")
    return outcomes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen", help="generate fresh development keys without overwriting existing files")
    keygen.add_argument("--out", type=Path, required=True)
    serve = sub.add_parser("serve", help="run the development mock on loopback")
    serve.add_argument("--private-key", type=Path, required=True)
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--acknowledge-development-only", action="store_true", required=True)
    demo = sub.add_parser("demo", help="verify allow, deny, and approval receipts from the mock")
    demo.add_argument("--public-key", type=Path, required=True)
    demo.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if args.command == "keygen":
        args.out.mkdir(parents=True, exist_ok=True, mode=0o700)
        if any((args.out / name).exists() for name in ("private.pem", "public.pem")):
            parser.error("Refusing to overwrite existing key files")
        key = Ed25519PrivateKey.generate()
        write_exclusive(args.out / "private.pem", key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()), 0o600)
        write_exclusive(args.out / "public.pem", public_pem(key).encode("ascii"), 0o644)
        print(f"Fresh DEVELOPMENT ONLY keys written to {args.out}")
    elif args.command == "serve":
        if not 1 <= args.port <= 65535:
            parser.error("Port must be 1..65535")
        server = make_server(load_private(args.private_key), port=args.port)
        print(f"DEVELOPMENT ONLY mock listening on 127.0.0.1:{args.port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    else:
        if not 1 <= args.port <= 65535:
            parser.error("Port must be 1..65535")
        run_demo(args.public_key, args.port)


if __name__ == "__main__":
    main()
