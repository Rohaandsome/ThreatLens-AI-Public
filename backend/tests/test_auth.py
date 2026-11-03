"""Tests for operator authentication (C-1 remediation).

Covers login/logout, session cookies, CSRF enforcement, fail-closed behavior,
anonymous rejection on every protected route, forged-identity rejection, role
escalation blocking, and administrator-only MISP publishing. MISP is faked;
no test performs network I/O or real external requests.
"""

import socket
from typing import Any

import pytest
import requests
from fastapi.testclient import TestClient

from app.config import settings
from app.services import authz
from tests.conftest import ADMIN_KEY, OPERATOR_KEY, csrf_headers, login_as


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATLENS_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("THREATLENS_HISTORY_DB", str(tmp_path / "history.db"))
    monkeypatch.setenv("THREATLENS_MISP_STORE", str(tmp_path / "misp.json"))
    return tmp_path


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("network I/O is forbidden in auth tests")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(requests.Session, "request", blocked)


def test_login_grants_role_cookie_and_csrf(client: TestClient) -> None:
    response = client.post("/api/auth/login", json={"key": OPERATOR_KEY})
    assert response.status_code == 200
    body = response.json()
    assert body["role"] == "analyst"
    assert len(body["csrf_token"]) >= 32
    assert body["expires_in_seconds"] == settings.session_timeout_seconds
    cookie = response.headers.get("set-cookie", "")
    assert "threatlens_session=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie or "samesite=lax" in cookie.lower()
    # Session works: status reflects the role with fresh CSRF + config flags.
    status = client.get("/api/auth/status").json()
    assert status["authenticated"] is True
    assert status["role"] == "analyst"
    assert status["csrf_token"] == body["csrf_token"]
    assert status["distribution_enabled"] is True


def test_admin_login_gets_administrator_role(client: TestClient) -> None:
    body = client.post("/api/auth/login", json={"key": ADMIN_KEY}).json()
    assert body["role"] == "administrator"
    assert client.get("/api/auth/status").json()["role"] == "administrator"


def test_wrong_key_rejected_without_oracle(client: TestClient) -> None:
    first = client.post("/api/auth/login", json={"key": "wrong-key-0000000000000000000000"})
    assert first.status_code == 401
    assert first.json()["detail"]["code"] == "invalid_credentials"
    assert "threatlens_session" not in first.headers.get("set-cookie", "")
    assert client.get("/api/auth/status").json()["authenticated"] is False


def test_login_throttled_after_burst(client: TestClient) -> None:
    for _ in range(10):
        client.post("/api/auth/login", json={"key": "nope-nope-nope-00000000000000000"})
    limited = client.post("/api/auth/login", json={"key": OPERATOR_KEY})
    assert limited.status_code == 429
    assert limited.json()["detail"]["code"] == "login_throttled"


def test_unconfigured_auth_fails_closed(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(settings, "operator_api_key", "")
    monkeypatch.setattr(settings, "admin_api_key", "")
    login = client.post("/api/auth/login", json={"key": OPERATOR_KEY})
    assert login.status_code == 503
    assert login.json()["detail"]["code"] == "auth_not_configured"
    gated = client.post("/api/share/prepare", json={})
    assert gated.status_code == 503
    status = client.get("/api/auth/status").json()
    assert status["auth_configured"] is False


def test_short_or_equal_secrets_fail_closed(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(settings, "operator_api_key", "short")
    monkeypatch.setattr(settings, "admin_api_key", "short")
    assert client.post("/api/auth/login", json={"key": "short"}).status_code == 503
    # Equal long secrets collapse to operator-only (no silent admin).
    monkeypatch.setattr(settings, "operator_api_key", OPERATOR_KEY)
    monkeypatch.setattr(settings, "admin_api_key", OPERATOR_KEY)
    body = client.post("/api/auth/login", json={"key": OPERATOR_KEY}).json()
    assert body["role"] == "analyst"


def test_logout_destroys_session(client: TestClient) -> None:
    headers = csrf_headers(client)
    assert client.get("/api/auth/status").json()["authenticated"] is True
    response = client.post("/api/auth/logout", headers=headers)
    assert response.json() == {"logged_out": True}
    assert client.get("/api/auth/status").json()["authenticated"] is False
    # Old CSRF token no longer authorizes anything.
    gated = client.post("/api/share/prepare", json={}, headers=headers)
    assert gated.status_code == 401


def test_logout_needs_csrf_when_logged_in(client: TestClient) -> None:
    login_as(client)
    assert client.post("/api/auth/logout").status_code == 403
    assert client.get("/api/auth/status").json()["authenticated"] is True


def test_expired_session_rejected(client: TestClient) -> None:
    headers = login_as(client)
    assert client.get("/api/history/records").status_code == 200
    for session in authz._sessions.values():
        session.expires_at = 0.0
    assert client.get("/api/history/records").status_code == 401
    assert client.post("/api/share/prepare", json={}, headers=headers).status_code == 401


def test_csrf_required_on_mutations(client: TestClient) -> None:
    login_as(client)  # valid cookie, no CSRF header
    assert client.post("/api/share/prepare", json={}).status_code == 403
    bad = client.post(
        "/api/share/prepare", json={}, headers={"X-CSRF-Token": "forged"}
    )
    assert bad.status_code == 403
    assert bad.json()["detail"]["code"] == "csrf_required"


def test_anonymous_rejected_everywhere(client: TestClient) -> None:
    routing = [
        ("POST", "/api/analyze"),
        ("POST", "/api/export/stix"),
        ("POST", "/api/share/prepare"),
        ("POST", "/api/share/pdf"),
        ("POST", "/api/share/stix"),
        ("POST", "/api/misp/test"),
        ("POST", "/api/misp/preview"),
        ("POST", "/api/misp/create"),
        ("POST", "/api/misp/publish"),
        ("POST", "/api/distribution/demo-006/approve"),
        ("GET", "/api/history/records"),
        ("GET", "/api/history/records/demo-001"),
        ("GET", "/api/audit/events"),
    ]
    for method, path in routing:
        response = client.request(method, path, json={} if method == "POST" else None)
        assert response.status_code == 401, (method, path, response.text)
    # Public surface stays minimal and detail-free.
    health = client.get("/api/health")
    assert health.status_code == 200
    assert set(health.json()) == {"status", "service", "version", "timestamp"}
    assert client.get("/").status_code == 200


def test_forged_actor_labels_ignored(client: TestClient, tmp_path) -> None:
    """A hostile analyst label must not reach audit attribution."""
    from app.schemas import SharePrepareRequest
    from app.services import sharing
    from tests.test_sharing import share_payload
    from tests.test_stix import make_response
    from tests.conftest import canned_analysis

    headers = csrf_headers(client)
    payload = share_payload(
        analysis=make_response(canned_analysis()).model_dump(mode="json")
    )
    payload["approval"]["analyst"] = "attacker-impersonating-soc"
    # Service level: actor wins over any label.
    package = sharing.build_package(
        SharePrepareRequest.model_validate(payload), "operator"
    )
    assert package.package_id
    # HTTP level: forged label accepted as workflow text, never as identity.
    response = client.post("/api/share/prepare", json=payload, headers=headers)
    assert response.status_code == 200
    blob = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert "attacker-impersonating-soc" not in blob
    assert '"analyst": "operator"' in blob


def test_operator_cannot_publish(client: TestClient) -> None:
    headers = csrf_headers(client)  # operator role
    response = client.post(
        "/api/misp/publish",
        json={"event_uuid": "u" * 36, "approval": {"approved": True, "confirmed": True}},
        headers=headers,
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "forbidden"


def test_admin_publish_reaches_handler(client: TestClient, monkeypatch) -> None:
    """Administrator passes the gate; the handler then applies its own rules."""
    from tests.conftest import ADMIN_KEY

    headers = csrf_headers(client, ADMIN_KEY)
    response = client.post(
        "/api/misp/publish",
        json={"event_uuid": "u" * 36, "approval": {"approved": True, "confirmed": True}},
        headers=headers,
    )
    # Unknown UUID -> the handler's 404 (proves the admin gate passed).
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "unknown_event"


def test_role_claims_cannot_escalate(client: TestClient) -> None:
    headers = csrf_headers(client)  # operator session
    escalate = dict(headers)
    escalate["X-Role"] = "administrator"
    response = client.post(
        "/api/misp/publish",
        json={"event_uuid": "u" * 36, "approval": {"approved": True, "confirmed": True}},
        headers=escalate,
    )
    assert response.status_code == 403
