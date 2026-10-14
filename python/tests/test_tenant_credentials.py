"""Per-tenant credential contract.

The SDK has no shared or default secret. Each client must be given that
tenant's or agent's credential at runtime — an explicit value, a file path
(for example a 1Password or broker mount), or the name of an env var — and
must refuse to start without one. The credential is never logged.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import responses
from structlog.testing import capture_logs

from g8r_shield import AgentShield

from .conftest import CHECK_URL, CONSOLE_URL, PEP_URL, allowed_response

# Names of the removed deployment-wide secret. Built here so production
# sources can be scanned for them without this file embedding a credential.
_SHARED_SECRET_NAMES = (
    "GF_SDK_" + "SHARED_SECRET",
    "G8R_" + "API_KEY",
)
_HARDCODED_SECRET = re.compile(r"""['\"]sk-[^'\"]+['\"]""")


def _production_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for base in (root / "python" / "g8r_shield", root / "js" / "src"):
        files.extend(
            path for path in base.rglob("*") if path.is_file() and path.suffix in {".py", ".ts"}
        )
    files.extend(
        [
            root / "README.md",
            root / "python" / "README.md",
            root / "python" / "example_bedrock.py",
            root / "js" / "README.md",
        ]
    )
    return files


def test_no_credential_raises_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """No per-tenant credential — including when only the old deployment-wide
    variable is present — refuses to start with an error that names the gap."""
    monkeypatch.delenv("G8R_TENANT_CREDENTIAL", raising=False)
    monkeypatch.delenv("G8R_TENANT_CREDENTIAL_FILE", raising=False)
    monkeypatch.setenv(_SHARED_SECRET_NAMES[1], "shared-deployment-secret")

    with pytest.raises(ValueError, match="per-tenant credential") as exc_info:
        AgentShield(tenant_id="tenant-a", pep_url=PEP_URL, console_url=CONSOLE_URL)

    message = str(exc_info.value)
    assert "shared-deployment-secret" not in message
    assert "no shared or default" in message


@responses.activate
def test_two_clients_send_their_own_tenant_credentials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Two clients configured with different tenant credentials send those
    credentials, not a process-wide secret, and never log them."""
    monkeypatch.setenv(_SHARED_SECRET_NAMES[1], "shared-deployment-secret")
    monkeypatch.setenv("TENANT_B_CREDENTIAL", "cred-for-tenant-b")
    cred_file = tmp_path / "tenant-a"
    cred_file.write_text("cred-for-tenant-a\n", encoding="utf-8")

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
        agent_id="agent-b",
        credential_env="TENANT_B_CREDENTIAL",
    )

    responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
    responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

    with capture_logs() as logs:
        client_a.check("hello from a", log=False)
        client_b.check("hello from b", log=False)

    auth_a = responses.calls[0].request.headers["Authorization"]
    auth_b = responses.calls[1].request.headers["Authorization"]
    assert auth_a == "Bearer cred-for-tenant-a"
    assert auth_b == "Bearer cred-for-tenant-b"
    assert "shared-deployment-secret" not in auth_a
    assert "shared-deployment-secret" not in auth_b
    body_a = responses.calls[0].request.body
    body_b = responses.calls[1].request.body
    text_a = body_a.decode() if isinstance(body_a, bytes) else str(body_a)
    text_b = body_b.decode() if isinstance(body_b, bytes) else str(body_b)
    assert "cred-for-tenant-a" not in text_a
    assert "cred-for-tenant-b" not in text_b

    leaked = json.dumps(logs) + repr(client_a) + repr(client_b)
    for secret in ("cred-for-tenant-a", "cred-for-tenant-b", "shared-deployment-secret"):
        assert secret not in leaked


@responses.activate
def test_credential_file_is_reread_when_rotated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A broker can replace the mounted file; the next request sends the new value."""
    monkeypatch.delenv("G8R_TENANT_CREDENTIAL", raising=False)
    cred_file = tmp_path / "tenant-a"
    cred_file.write_text("cred-before-rotation\n", encoding="utf-8")
    client = AgentShield(
        tenant_id="tenant-a",
        pep_url=PEP_URL,
        console_url=CONSOLE_URL,
        credential_file=str(cred_file),
    )
    responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
    responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

    client.check("first", log=False)
    cred_file.write_text("cred-after-rotation\n", encoding="utf-8")
    client.check("second", log=False)

    assert responses.calls[0].request.headers["Authorization"] == "Bearer cred-before-rotation"
    assert responses.calls[1].request.headers["Authorization"] == "Bearer cred-after-rotation"
    assert "cred-before-rotation" not in repr(client)
    assert "cred-after-rotation" not in repr(client)


def test_empty_credential_file_refuses_to_start(tmp_path: Path) -> None:
    cred_file = tmp_path / "empty"
    cred_file.write_text("\n", encoding="utf-8")
    with pytest.raises(ValueError, match="per-tenant credential") as exc_info:
        AgentShield(
            tenant_id="tenant-a",
            pep_url=PEP_URL,
            console_url=CONSOLE_URL,
            credential_file=str(cred_file),
        )
    assert "per-tenant credential" in str(exc_info.value)


def test_both_process_credential_env_vars_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("G8R_TENANT_CREDENTIAL", "from-env")
    monkeypatch.setenv("G8R_TENANT_CREDENTIAL_FILE", "/tmp/does-not-matter")
    with pytest.raises(ValueError, match="both set") as exc_info:
        AgentShield(tenant_id="tenant-a", pep_url=PEP_URL, console_url=CONSOLE_URL)
    message = str(exc_info.value)
    assert "from-env" not in message
    assert "no shared or default" in message


def test_no_hardcoded_or_default_secret() -> None:
    """Production SDK sources and public docs contain no shared-secret
    identifier and no hard-coded credential literal."""
    root = Path(__file__).resolve().parents[2]
    hits: list[str] = []
    for path in _production_files(root):
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(root).as_posix()
        for needle in _SHARED_SECRET_NAMES:
            if needle in text:
                hits.append(f"{rel}: contains {needle}")
        if path.suffix in {".py", ".ts", ".md"} and _HARDCODED_SECRET.search(text):
            hits.append(f"{rel}: hard-coded sk- secret literal")
    assert hits == [], "shared or default SDK secret remains:\n" + "\n".join(hits)
