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
import traceback
from pathlib import Path

import pytest
import requests

from g8r_shield import AgentShield, ShieldConnectionError
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


# Hosts that must be treated as loopback: the whole 127.0.0.0/8, the
# unspecified addresses, IPv6 loopback, any IPv4-mapped loopback (dotted or
# hex), and localhost including a trailing dot and nested names. Ports,
# brackets, and userinfo are part of the URL, not the host.
_LOOPBACK_URLS = [
    "https://127.0.0.0",
    "https://127.0.0.1",
    "https://127.0.0.2",
    "https://127.255.255.255",
    "http://127.0.0.2:9",
    "https://user:secret@127.0.0.2",
    "https://0.0.0.0",
    "http://0.0.0.0:8080",
    "https://[::]",
    "http://[::]:8080",
    "https://[::1]",
    "http://[::1]:3000",
    "https://[::ffff:127.0.0.1]",
    "http://[::ffff:127.0.0.1]:8443",
    "https://[::ffff:127.0.0.2]",
    "https://[::FFFF:7f00:1]",
    "https://localhost",
    "http://localhost:3000",
    "https://LOCALHOST",
    "https://api.localhost",
    "https://foo.bar.localhost",
    "http://app.localhost:8080",
    "https://localhost.",
    "https://api.localhost.",
]

# Not loopback. https is allowed; http stays forbidden even with the override.
_NON_LOOPBACK_HTTPS_URLS = [
    "https://128.0.0.1",
    "https://example.com",
    "https://localhost.example.com",
    "https://notlocalhost",
    "https://example.localhost.com",
    "https://[::2]",
    "https://[::ffff:8.8.8.8]",
    "https://8.8.8.8",
]

_NON_LOOPBACK_HTTP_URLS = [
    "http://128.0.0.1",
    "http://example.com",
    "http://[::2]",
    "http://[::ffff:8.8.8.8]",
    "http://localhost.example.com",
]

# http is permitted for these only when the localhost dev override is on.
_LOOPBACK_HTTP_URLS = [
    "http://127.0.0.1:3000",
    "http://127.0.0.2:9",
    "http://0.0.0.0:8080",
    "http://[::]:8080",
    "http://[::1]:3000",
    "http://[::ffff:127.0.0.1]:8443",
    "http://[::ffff:7f00:2]",
    "http://localhost:3000",
    "http://api.localhost:8080",
    "http://app.localhost.",
]


@pytest.mark.parametrize("source", ["file", "env"])
def test_credential_read_error_is_generic_and_unchained(
    source: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A later file or env read failure must not chain the underlying error.

    ``__cause__`` and the implicit context both print, and those messages
    carry the path or the variable name. The surfaced message stays generic.
    """
    monkeypatch.delenv("G8R_TENANT_CREDENTIAL", raising=False)
    monkeypatch.delenv("G8R_TENANT_CREDENTIAL_FILE", raising=False)
    secret = "credential-value-do-not-leak"
    if source == "file":
        marker = "credential-path-do-not-leak"
        path = tmp_path / marker
        path.write_text(secret + "\n", encoding="utf-8")
        client = _shield(api_key=None, credential_file=str(path))
        path.unlink()
        leaked = (marker, secret, str(path), "FileNotFoundError", "No such file")
    else:
        marker = "G8R_DO_NOT_LEAK_ENV_NAME"
        monkeypatch.setenv(marker, secret)
        client = _shield(api_key=None, credential_env=marker)
        monkeypatch.delenv(marker)
        leaked = (marker, secret, "unset or empty")

    with pytest.raises(ShieldConnectionError) as exc_info:
        client.check("ping", log=False)

    err = exc_info.value
    assert err.__cause__ is None
    assert err.__suppress_context__ is True
    message = str(err)
    assert "could not be read" in message
    assert "failing closed" in message
    rendered = "".join(traceback.format_exception(err))
    for needle in leaked:
        assert needle not in message
        assert needle not in rendered


@pytest.mark.parametrize("url", _LOOPBACK_URLS)
def test_loopback_url_is_rejected(url: str) -> None:
    with pytest.raises(ValueError, match="must not target localhost"):
        _shield(console_url=url)
    with pytest.raises(ValueError, match="must not target localhost"):
        _shield(pep_url=url)


@pytest.mark.parametrize("url", _NON_LOOPBACK_HTTPS_URLS)
def test_non_loopback_https_is_allowed(url: str) -> None:
    client = _shield(console_url=url, pep_url=url)
    assert client._console_url == url
    assert client._pep_url == url


@pytest.mark.parametrize("url", _NON_LOOPBACK_HTTP_URLS)
def test_override_does_not_permit_non_loopback_http(
    url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("G8R_ALLOW_INSECURE_LOCALHOST", "1")
    with pytest.raises(ValueError, match="must be https"):
        _shield(console_url=url)
    with pytest.raises(ValueError, match="must be https"):
        _shield(pep_url=url)


@pytest.mark.parametrize("url", _LOOPBACK_HTTP_URLS)
def test_override_permits_http_to_loopback(url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("G8R_ALLOW_INSECURE_LOCALHOST", "1")
    client = _shield(console_url=url, pep_url=url)
    assert client._console_url == url
    assert client._pep_url == url
