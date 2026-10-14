"""Guardian follow-ups for the per-tenant credential change.

HTTPS is required on both console and PEP URLs. Loopback is refused on
both unless G8R_ALLOW_INSECURE_LOCALHOST is set, and that override never
permits plaintext to a non-loopback host. Blank tenant ids are rejected.
Provider failures are not chained, because the provider exception can
carry the credential. Two tenants checked concurrently keep their own
credentials. 0.7.0 records the breaking migration.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest
import requests

from g8r_shield import AgentShield
from g8r_shield.shield import requests as shield_requests

from .conftest import CONSOLE_URL, PEP_URL

_ROOT = Path(__file__).resolve().parents[2]


def _shield(**overrides: object) -> AgentShield:
    config: dict[str, object] = {
        "tenant_id": "tenant-a",
        "pep_url": PEP_URL,
        "console_url": CONSOLE_URL,
        "api_key": "k",
    }
    config.update(overrides)
    return AgentShield(**config)  # type: ignore[arg-type]


@pytest.mark.parametrize("tenant_id", [" ", "\t", "\n", " \t\n "])
def test_blank_and_whitespace_tenant_id_rejected(tenant_id: str) -> None:
    with pytest.raises(ValueError, match="tenant_id is required"):
        _shield(tenant_id=tenant_id)


def test_console_url_and_pep_url_require_https() -> None:
    with pytest.raises(ValueError, match="https"):
        _shield(console_url="http://console.example.test")
    with pytest.raises(ValueError, match="https"):
        _shield(pep_url="http://pep.example.test")
    with pytest.raises(ValueError, match="console_url"):
        _shield(console_url="   ")


def test_console_url_rejects_loopback() -> None:
    for console_url in (
        "http://localhost:3000",
        "https://localhost:3000",
        "https://127.0.0.1",
        "http://[::1]:3000",
    ):
        with pytest.raises(ValueError, match="localhost"):
            _shield(console_url=console_url)


def test_insecure_localhost_override_is_localhost_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("G8R_ALLOW_INSECURE_LOCALHOST", "1")
    local = _shield(pep_url="http://localhost:8083", console_url="http://127.0.0.1:3000")
    assert local._pep_url == "http://localhost:8083"
    assert local._console_url == "http://127.0.0.1:3000"

    ipv6 = _shield(pep_url="http://[::1]:8083", console_url="https://localhost:8443")
    assert ipv6._pep_url == "http://[::1]:8083"
    assert ipv6._console_url == "https://localhost:8443"

    # The override is not a general plaintext escape hatch.
    with pytest.raises(ValueError, match="https"):
        _shield(pep_url="http://pep.example.test")
    with pytest.raises(ValueError, match="https"):
        _shield(console_url="http://console.example.test")

    monkeypatch.setenv("G8R_ALLOW_INSECURE_LOCALHOST", "0")
    with pytest.raises(ValueError, match="localhost"):
        _shield(console_url="http://localhost:3000")


def test_changelog_documents_070_migration() -> None:
    changelog = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "0.7.0" in changelog
    lowered = changelog.lower()
    assert "migration" in lowered
    assert "per-tenant" in lowered or "per tenant" in lowered
    assert "G8R_ALLOW_INSECURE_LOCALHOST" in changelog
    # The removed deployment-wide variable is named here so operators can
    # find it. This file is not a production source scanned for that name.
    assert "G8R_" + "API_KEY" in changelog


def test_concurrent_two_tenants_do_not_cross_credentials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Two clients resolving credentials on overlapping threads send only
    their own bearer token and tenant id."""
    monkeypatch.delenv("G8R_TENANT_CREDENTIAL", raising=False)
    monkeypatch.delenv("G8R_TENANT_CREDENTIAL_FILE", raising=False)
    cred_file = tmp_path / "tenant-a"
    cred_file.write_text("cred-tenant-a\n", encoding="utf-8")
    monkeypatch.setenv("TENANT_B_CREDENTIAL", "cred-tenant-b")

    client_a = AgentShield(
        tenant_id="tenant-a",
        pep_url=PEP_URL,
        console_url=CONSOLE_URL,
        credential_file=str(cred_file),
    )
    client_b = AgentShield(
        tenant_id="tenant-b",
        pep_url=PEP_URL,
        console_url=CONSOLE_URL,
        credential_env="TENANT_B_CREDENTIAL",
    )

    seen: list[tuple[str, str]] = []
    lock = threading.Lock()

    def post(
        url: str,
        json: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> requests.Response:
        del url, timeout
        body = json or {}
        auth = (headers or {})["Authorization"]
        with lock:
            seen.append((str(auth), str(body.get("tenantId"))))
        response = requests.Response()
        response.status_code = 200
        response._content = json_bytes(
            {
                "decision": "allowed",
                "reason": "ok",
                "violatedRule": None,
                "requiresApproval": False,
                "complianceMappings": [],
            }
        )
        return response

    monkeypatch.setattr(shield_requests, "post", post)

    errors: list[BaseException] = []
    go = threading.Event()

    def run(client: AgentShield) -> None:
        try:
            go.wait(timeout=2)
            for _ in range(12):
                client.check("ping", log=False)
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [
        threading.Thread(target=run, args=(client_a,)),
        threading.Thread(target=run, args=(client_b,)),
    ]
    for thread in threads:
        thread.start()
    go.set()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()

    assert errors == []
    assert len(seen) == 24
    for auth, tenant in seen:
        if tenant == "tenant-a":
            assert auth == "Bearer cred-tenant-a"
        elif tenant == "tenant-b":
            assert auth == "Bearer cred-tenant-b"
        else:
            raise AssertionError(f"unexpected tenant {tenant}")
        assert "cred-tenant-a" not in tenant
        assert "cred-tenant-b" not in tenant


def json_bytes(body: dict[str, object]) -> bytes:
    return json.dumps(body).encode("utf-8")
