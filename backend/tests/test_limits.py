"""Tests for H-2 (rate limiting + body caps) and H-3 (AI consent).

Rate budgets reset per test via conftest; the model client and PyMISP are
faked in-process and real sockets are blocked. No test performs network I/O
or real external requests.
"""

import json
import socket
from typing import Any

import pytest
import requests
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.services import analyzer, misp_client
from tests.conftest import (
    FIXTURE_PATH,
    canned_json,
    consent_headers,
    csrf_headers,
    fake_client,
    fake_completion,
    login_as,
)
from tests.test_misp import create_body, package
from tests.test_sharing import share_payload
from tests.test_stix import make_response
from tests.conftest import canned_analysis


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATLENS_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("THREATLENS_HISTORY_DB", str(tmp_path / "history.db"))
    monkeypatch.setenv("THREATLENS_MISP_STORE", str(tmp_path / "misp.json"))
    return tmp_path


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("network I/O is forbidden in limit tests")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(requests.Session, "request", blocked)


def _install_fake(monkeypatch, behavior=None):
    client, completions = fake_client(
        behavior if behavior is not None else fake_completion(canned_json())
    )
    monkeypatch.setattr(analyzer, "build_client", lambda settings: client)
    return completions


def _analyze(client: TestClient, headers) -> Any:
    with open(FIXTURE_PATH, "rb") as fh:
        return client.post(
            "/api/analyze",
            headers=headers,
            files={"file": ("synthetic_ics_report.txt", fh, "text/plain")},
        )


class _FakeMISP:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def get_user(self, scope: str) -> dict[str, Any]:
        return {
            "User": {"org_id": "1"},
            "Role": {"perm_add": True, "perm_publish": False},
            "Organisation": {"id": "1", "name": "T"},
        }

    def add_event(self, event: Any) -> dict[str, Any]:
        return {"Event": {"id": "7", "uuid": "u" * 36}}


# --- H-2: rate limits ---


def test_analyze_limited_per_session(
    client: TestClient, monkeypatch, api_key: str
) -> None:
    _install_fake(monkeypatch)
    headers = consent_headers(client)
    for _ in range(10):
        assert _analyze(client, headers).status_code == 200
    limited = _analyze(client, headers)
    assert limited.status_code == 429
    body = limited.json()["detail"]
    assert body["code"] == "rate_limited"
    assert "Retry in" in body["message"]
    assert "test-key" not in limited.text
    assert limited.headers["retry-after"].isdigit()


def test_rate_budget_is_per_session(
    client: TestClient, monkeypatch, api_key: str
) -> None:
    _install_fake(monkeypatch)
    headers = consent_headers(client)
    for _ in range(10):
        assert _analyze(client, headers).status_code == 200
    assert _analyze(client, headers).status_code == 429
    other = TestClient(app)
    other_headers = consent_headers(other)
    assert _analyze(other, other_headers).status_code == 200


def test_anonymous_analyze_rejected_before_limit(
    client: TestClient, api_key: str
) -> None:
    with open(FIXTURE_PATH, "rb") as fh:
        response = client.post(
            "/api/analyze",
            files={"file": ("r.txt", fh, "text/plain")},
        )
    assert response.status_code == 401


def test_misp_write_limited(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(misp_client, "PyMISP", _FakeMISP)
    monkeypatch.setattr(settings, "misp_url", "https://misp.test")
    monkeypatch.setattr(settings, "misp_api_key", "not-real")
    monkeypatch.setattr(settings, "misp_allowed_distributions", "0,1,2,3,4")
    headers = csrf_headers(client)
    pkg = package()
    for _ in range(20):
        response = client.post(
            "/api/misp/create", json=create_body(pkg), headers=headers
        )
        assert response.status_code == 200
    limited = client.post("/api/misp/create", json=create_body(pkg), headers=headers)
    assert limited.status_code == 429
    assert limited.headers["retry-after"].isdigit()


def test_misp_read_limited(client: TestClient) -> None:
    headers = csrf_headers(client)
    pkg = package().model_dump(mode="json")
    for _ in range(60):
        response = client.post(
            "/api/misp/preview",
            json={"package": pkg, "destination": {"distribution": 1}},
            headers=headers,
        )
        assert response.status_code == 200
    assert (
        client.post(
            "/api/misp/preview",
            json={"package": pkg, "destination": {"distribution": 1}},
            headers=headers,
        ).status_code
        == 429
    )


def test_share_limited(client: TestClient) -> None:
    headers = csrf_headers(client)
    payload = share_payload(
        analysis=make_response(canned_analysis()).model_dump(mode="json")
    )
    for _ in range(60):
        assert (
            client.post("/api/share/prepare", json=payload, headers=headers).status_code
            == 200
        )
    assert (
        client.post("/api/share/prepare", json=payload, headers=headers).status_code
        == 429
    )


def test_oversized_json_rejected(client: TestClient, tmp_path) -> None:
    headers = csrf_headers(client)
    payload = share_payload(
        analysis=make_response(canned_analysis()).model_dump(mode="json")
    )
    payload["justification"] = "x" * (3 * 1024 * 1024)
    response = client.post("/api/share/prepare", json=payload, headers=headers)
    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "body_too_large"
    # Rejected before handling: the prepare handler never ran or audited.
    audit_log = tmp_path / "audit.log"
    events = (
        [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
        if audit_log.exists()
        else []
    )
    assert all(e["event"] != "prepared" for e in events)


def test_oversized_upload_rejected(client: TestClient) -> None:
    headers = consent_headers(client)
    big = b"x" * (13 * 1024 * 1024)
    response = client.post(
        "/api/analyze",
        headers=headers,
        files={"file": ("big.txt", big, "text/plain")},
    )
    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "body_too_large"


# --- H-3: AI consent ---


def test_analyze_without_consent_forbidden_and_model_untouched(
    client: TestClient, monkeypatch, api_key: str
) -> None:
    completions = _install_fake(monkeypatch)
    headers = csrf_headers(client)  # logged in, no acknowledgment
    response = _analyze(client, headers)
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "consent_required"
    assert completions.calls == []


def test_consent_grants_analysis(client: TestClient, tmp_path) -> None:
    headers = csrf_headers(client)
    assert client.get("/api/auth/status").json()["ai_consent"] is False
    granted = client.post(
        "/api/auth/consent", json={"acknowledged": True}, headers=headers
    )
    assert granted.json() == {"acknowledged": True}
    assert client.get("/api/auth/status").json()["ai_consent"] is True
    # Idempotent: re-acknowledging succeeds without duplicate audit spam.
    assert (
        client.post(
            "/api/auth/consent", json={"acknowledged": True}, headers=headers
        ).status_code
        == 200
    )
    events = [
        json.loads(line)
        for line in (tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()
    ]
    granted_events = [e for e in events if e["event"] == "ai_consent"]
    assert len(granted_events) == 1
    assert granted_events[0]["analyst"] == "operator"


def test_consent_requires_auth_and_csrf(client: TestClient) -> None:
    assert client.post("/api/auth/consent", json={"acknowledged": True}).status_code == 401
    login_as(client)
    assert (
        client.post("/api/auth/consent", json={"acknowledged": True}).status_code == 403
    )
    headers = csrf_headers(client)
    refused = client.post(
        "/api/auth/consent", json={"acknowledged": False}, headers=headers
    )
    assert refused.status_code == 400


def test_consent_audit_has_no_contents_or_secrets(
    client: TestClient, monkeypatch, api_key: str, tmp_path
) -> None:
    _install_fake(monkeypatch)
    headers = consent_headers(client)
    assert _analyze(client, headers).status_code == 200
    blob = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert "Blue Mesa" not in blob  # report content
    assert "test-operator-key" not in blob
    assert "ai_consent" in blob


def test_consent_is_per_session(
    client: TestClient, monkeypatch, api_key: str
) -> None:
    completions = _install_fake(monkeypatch)
    consent_headers(client)
    assert _analyze(client, consent_headers(client)).status_code == 200
    assert len(completions.calls) == 1
    other = TestClient(app)
    with open(FIXTURE_PATH, "rb") as fh:
        login_as(other)
        denied = other.post(
            "/api/analyze",
            headers=csrf_headers(other),
            files={"file": ("r.txt", fh, "text/plain")},
        )
    assert denied.status_code == 403
    assert len(completions.calls) == 1  # second session sent nothing
