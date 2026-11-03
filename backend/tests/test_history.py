"""Tests for Phase 4 history, audit, and distribution management.

No authentication exists, so every HTTP caller is anonymous: reads serve
labelled demo data (history) or the real append-only log (audit), and every
distribution mutation is denied + audited. The state machine itself is
exercised with explicit roles at the service level. No test may perform
network I/O or real external distribution.
"""

import json
import socket
from typing import Any

import pytest
import requests
from fastapi.testclient import TestClient

from app.errors import AnalysisError
from app.services import audit, authz, distribution, history_store
from app.services.authz import Role
from tests.conftest import csrf_headers, login_as


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATLENS_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("THREATLENS_HISTORY_DB", str(tmp_path / "history.db"))
    return tmp_path


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("network I/O is forbidden in history tests")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(requests.Session, "request", blocked)


def audit_lines(tmp_path) -> list[dict[str, Any]]:
    path = tmp_path / "audit.log"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# --- auth status ---


def test_auth_status_is_anonymous(client: TestClient) -> None:
    body = client.get("/api/auth/status").json()
    assert body == {
        "authenticated": False,
        "role": "anonymous",
        "distribution_enabled": False,
        "auth_configured": True,
        "csrf_token": None,
        "model_api_configured": False,
        "misp_configured": False,
        "ai_consent": False,
    }


def test_client_identity_claims_are_ignored(client: TestClient) -> None:
    """Headers, cookies, and params never authenticate anyone (req 5)."""
    response = client.post(
        "/api/distribution/demo-006/approve?role=administrator",
        headers={
            "X-Role": "administrator",
            "X-User": "root",
            "Authorization": "Bearer admin-token",
        },
        cookies={"session": "admin"},
    )
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "authentication_required"
    assert client.get("/api/auth/status").json()["role"] == "anonymous"


# --- history reads ---


def test_history_lists_labelled_demo_seeds(client: TestClient) -> None:
    login_as(client)
    body = client.get("/api/history/records").json()
    assert body["total"] == 10
    assert body["demo"] is True
    assert body["distribution_enabled"] is True
    assert all(r["demo"] is True for r in body["records"])
    # Newest first.
    assert body["records"][0]["id"] == "demo-007"
    assert body["records"][0]["created_at"] >= body["records"][-1]["created_at"]
    # Full field coverage (req 2).
    first = body["records"][0]
    assert first["report_id"] == "synthetic_scada_incident.txt"
    assert first["classification"] == "TLP:AMBER"
    assert first["destination_label"] == "Internal review board"
    assert first["findings"] == {"cves": 1, "iocs": 0, "systems": 2, "techniques": 2}
    assert first["approved_at"] is None
    assert first["status"] == "pending_review"
    assert first["misp_event_uuid"] is None
    published = [r for r in body["records"] if r["status"] == "published"][0]
    assert published["misp_event_uuid"] == "11111111-1111-4111-8111-111111111111"


def test_history_filters(client: TestClient) -> None:
    login_as(client)
    get = lambda params: client.get("/api/history/records", params=params).json()
    assert get({"status": "pending_review"})["total"] == 2
    assert get({"status": "approved"})["total"] == 2
    assert get({"status": "exported"})["total"] == 2
    assert get({"classification": "amber"})["total"] == 3
    assert get({"classification": "TLP:RED"})["total"] == 2
    assert get({"report": "synthetic_ics_report"})["total"] == 2
    assert get({"recipient": "Partner SOC"})["total"] == 2
    assert get({"recipient": "sharing group"})["total"] == 1
    window = get({"since": "2026-10-30T00:00:00+00:00"})
    assert window["total"] == 4
    window = get(
        {"since": "2026-10-30T00:00:00+00:00", "until": "2026-10-30T23:59:59+00:00"}
    )
    assert window["total"] == 2
    page = get({"limit": 3, "offset": 0})
    assert (page["total"], len(page["records"])) == (10, 3)
    page2 = get({"limit": 3, "offset": 3})
    assert len(page2["records"]) == 3
    assert page["records"][0]["id"] != page2["records"][0]["id"]
    combo = get({"status": "approved", "classification": "TLP:GREEN"})
    assert combo["total"] == 1 and combo["records"][0]["id"] == "demo-010"


def test_history_rejects_invalid_filters(client: TestClient) -> None:
    login_as(client)
    response = client.get("/api/history/records", params={"status": "nope"})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_status"
    response = client.get("/api/history/records", params={"classification": "TLP:BOGUS"})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_tlp"


def test_history_get_one_and_404(client: TestClient) -> None:
    login_as(client)
    body = client.get("/api/history/records/demo-002").json()
    assert body["status"] == "draft"
    assert body["destination_detail"] == {"distribution": 1, "sharing_group_id": None}
    response = client.get("/api/history/records/zzz")
    assert response.status_code == 404


# --- distribution denial ---


@pytest.mark.parametrize("action", ["approve", "send", "cancel"])
def test_distribution_actions_denied_and_audited(
    client: TestClient, tmp_path, action: str
) -> None:
    before = history_store.get_record("demo-006")
    assert before is not None and before["status"] == "pending_review"
    response = client.post(f"/api/distribution/demo-006/{action}")
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "authentication_required"
    # Nothing mutated.
    after = history_store.get_record("demo-006")
    assert after is not None and after["status"] == "pending_review"
    # Attempt audited with metadata only.
    denied = [e for e in audit_lines(tmp_path) if e["event"] == "distribution_denied"]
    assert len(denied) == 1
    entry = denied[0]
    assert entry["action"] == action
    assert entry["record_id"] == "demo-006"
    assert entry["role"] == "anonymous"
    assert "logged-in" in entry["reason"]
    assert set(entry) == {"id", "ts", "event", "action", "record_id", "role", "reason"}


def test_operator_approve_succeeds_and_audits(
    client: TestClient, tmp_path
) -> None:
    headers = csrf_headers(client)
    response = client.post(
        "/api/distribution/demo-006/approve", headers=headers
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["record"]["status"] == "approved"
    assert history_store.get_record("demo-006")["status"] == "approved"
    moved = [
        e for e in audit_lines(tmp_path) if e["event"] == "distribution_transition"
    ]
    assert len(moved) == 1
    assert moved[0]["analyst"] == "operator"
    assert moved[0]["to_status"] == "approved"


def test_denied_attempt_on_unknown_record(client: TestClient, tmp_path) -> None:
    """Deny-first: no existence probe, still audited."""
    response = client.post("/api/distribution/zzz/send")
    assert response.status_code == 401
    denied = [e for e in audit_lines(tmp_path) if e["event"] == "distribution_denied"]
    assert len(denied) == 1 and denied[0]["record_id"] == "zzz"


def test_denied_audits_carry_no_secrets_or_bodies(
    client: TestClient, tmp_path
) -> None:
    client.post("/api/distribution/demo-006/approve")
    client.post("/api/distribution/demo-005/send")
    blob = (tmp_path / "audit.log").read_text(encoding="utf-8")
    lowered = blob.lower()
    for needle in ("api_key", "apikey", "secret", "password", "token", "bearer"):
        assert needle not in lowered
    # Reasons reference statuses, never report content.
    for entry in audit_lines(tmp_path):
        assert "synthetic" not in json.dumps(entry).lower()


# --- state machine (explicit roles, service level) ---


def test_analyst_review_flow() -> None:
    record = history_store.get_record("demo-006")
    assert record is not None
    approved = distribution.transition(
        record, "approved", Role.analyst, now="2026-10-31T10:00:00+00:00"
    )
    assert approved["status"] == "approved"
    assert approved["approved_at"] == "2026-10-31T10:00:00+00:00"
    assert approved["updated_at"] == "2026-10-31T10:00:00+00:00"
    # Persisted.
    assert history_store.get_record("demo-006")["status"] == "approved"
    draft = distribution.transition(approved, "draft", Role.analyst)
    assert draft["status"] == "draft"
    failed = distribution.transition(
        draft, "failed", Role.analyst, error="MISP unreachable."
    )
    assert failed["status"] == "failed"
    assert failed["error"] == "MISP unreachable."
    # Failure requeues to approved with the error cleared.
    again = distribution.transition(failed, "approved", Role.analyst)
    assert again["status"] == "approved"
    assert again["error"] is None


def test_publish_needs_administrator() -> None:
    record = history_store.get_record("demo-002")
    assert record is not None and record["status"] == "draft"
    with pytest.raises(AnalysisError) as excinfo:
        distribution.transition(record, "published", Role.analyst)
    assert excinfo.value.code == "forbidden"
    assert history_store.get_record("demo-002")["status"] == "draft"
    published = distribution.transition(record, "published", Role.administrator)
    assert published["status"] == "published"


def test_anonymous_cannot_transition() -> None:
    record = history_store.get_record("demo-006")
    assert record is not None
    with pytest.raises(AnalysisError) as excinfo:
        distribution.transition(record, "approved", Role.anonymous)
    assert excinfo.value.code == "distribution_disabled"


def test_illegal_transitions_rejected() -> None:
    published = history_store.get_record("demo-001")
    assert published is not None
    with pytest.raises(AnalysisError) as excinfo:
        distribution.transition(published, "approved", Role.administrator)
    assert excinfo.value.code == "illegal_transition"
    pending = history_store.get_record("demo-006")
    assert pending is not None
    with pytest.raises(AnalysisError) as excinfo:
        distribution.transition(pending, "published", Role.administrator)
    assert excinfo.value.code == "illegal_transition"
    with pytest.raises(AnalysisError) as excinfo:
        distribution.transition(pending, "launched", Role.administrator)
    assert excinfo.value.code == "invalid_status"
    for status in distribution.TERMINAL:
        assert distribution.allowed_targets(status, Role.administrator) == []


def test_send_target_by_destination_kind() -> None:
    misp_approved = history_store.get_record("demo-005")
    assert misp_approved is not None
    assert distribution.send_target(misp_approved) == "draft"
    pdf_approved = history_store.get_record("demo-010")
    assert pdf_approved is not None
    assert distribution.send_target(pdf_approved) == "exported"
    pending = history_store.get_record("demo-006")
    assert pending is not None
    with pytest.raises(AnalysisError) as excinfo:
        distribution.send_target(pending)
    assert excinfo.value.code == "illegal_transition"


# --- audit log API ---


def test_audit_read_newest_first_with_filters(
    client: TestClient, tmp_path
) -> None:
    login_as(client)
    audit.record("prepared", {"package_id": "p1"})
    audit.record("distribution_denied", {"action": "send"})
    audit.record("prepared", {"package_id": "p2"})
    body = client.get("/api/audit/events").json()
    assert body["total"] == 3
    assert [e["event"] for e in body["events"]] == [
        "prepared",
        "distribution_denied",
        "prepared",
    ]
    assert body["events"][0]["package_id"] == "p2"
    only = client.get("/api/audit/events", params={"event": "prepared"}).json()
    assert only["total"] == 2
    first_ts = body["events"][-1]["ts"]
    last_ts = body["events"][0]["ts"]
    assert (
        client.get("/api/audit/events", params={"since": last_ts}).json()["total"]
        >= 1
    )
    assert (
        client.get("/api/audit/events", params={"until": first_ts}).json()["total"]
        >= 1
    )
    page = client.get("/api/audit/events", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 3 and len(page["events"]) == 1


def test_audit_read_empty_and_malformed(tmp_path) -> None:
    events, total = audit.read_events()
    assert (events, total) == ([], 0)
    path = tmp_path / "audit.log"
    path.write_text(
        '{"event": "prepared", "ts": "2026-10-31T00:00:00+00:00"}\n'
        "not json\n"
        '{"no_event": true}\n',
        encoding="utf-8",
    )
    events, total = audit.read_events()
    assert total == 1 and events[0]["event"] == "prepared"


def test_audit_is_append_only_via_api(client: TestClient, tmp_path) -> None:
    audit.record("prepared", {"package_id": "p1"})
    before = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert client.put("/api/audit/events", json={}).status_code == 405
    assert client.patch("/api/audit/events", json={}).status_code == 405
    assert client.delete("/api/audit/events").status_code == 405
    assert client.post("/api/audit/events", json={}).status_code == 405
    assert client.put("/api/history/records/demo-001", json={}).status_code == 405
    assert client.delete("/api/history/records/demo-001").status_code == 405
    assert client.delete("/api/history/records").status_code == 405
    # Recording only appends; earlier bytes untouched.
    audit.record("prepared", {"package_id": "p2"})
    after = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert after.startswith(before)
    assert after.count("\n") == before.count("\n") + 1


def test_full_denied_flow_visible_in_audit_api(
    client: TestClient, tmp_path
) -> None:
    client.post("/api/distribution/demo-006/send")
    login_as(client)
    body = client.get("/api/audit/events", params={"event": "distribution_denied"}).json()
    assert body["total"] == 1
    assert body["events"][0]["record_id"] == "demo-006"
