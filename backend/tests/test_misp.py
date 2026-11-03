"""Tests for Phase 3 MISP integration.

The PyMISP client is faked in-process and real sockets are blocked: no test
in this module may perform network I/O. Secrets are fake values, and a final
test asserts they never leak into responses, audits, or the export store.
"""

import json
import socket
from typing import Any

import pytest
import requests
from fastapi.testclient import TestClient

from app.config import Settings, settings
from app.schemas import SharePrepareRequest, SharePrepareResponse
from app.services import misp_client, sharing
from app.services.misp_export import build_misp_event
from app.services.stix_export import load_attack_data
from tests.conftest import ADMIN_KEY, canned_analysis, csrf_headers, login_as
from tests.test_sharing import share_payload
from tests.test_stix import make_response

FAKE_URL = "https://misp.test"
FAKE_KEY = "misp-key-not-real-12345"
BODIES: list[str] = []  # every response body, for the leak test


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATLENS_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("THREATLENS_MISP_STORE", str(tmp_path / "misp.json"))
    return tmp_path


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Block real network paths (TestClient itself stays in-process)."""

    def blocked(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("network I/O is forbidden in MISP tests")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(requests.Session, "request", blocked)


@pytest.fixture()
def misp_settings(monkeypatch):
    monkeypatch.setattr(settings, "misp_url", FAKE_URL)
    monkeypatch.setattr(settings, "misp_api_key", FAKE_KEY)
    monkeypatch.setattr(settings, "misp_verify_ssl", True)
    monkeypatch.setattr(settings, "misp_timeout_seconds", 7)
    # Tests opt into a permissive allowlist; production defaults to "0"/"".
    monkeypatch.setattr(settings, "misp_allowed_distributions", "0,1,2,3,4")
    monkeypatch.setattr(settings, "misp_allowed_sharing_groups", "7")
    return settings


class FakeMISP:
    """Scripted in-process stand-in for PyMISP."""

    instances: list["FakeMISP"] = []

    def __init__(self, url: str, key: str, **kwargs: Any) -> None:
        self.url = url
        self.key = key
        self.kwargs = kwargs
        self.calls: list[tuple[str, Any]] = []
        self.user_payload: dict[str, Any] = {
            "User": {"id": "1", "org_id": "1"},
            "Role": {"name": "analyst", "perm_add": True, "perm_publish": False},
            "Organisation": {"id": "1", "name": "Test Org"},
        }
        self.user_error: Exception | None = None
        self.add_result: dict[str, Any] = {"Event": {"id": "42", "uuid": "u" * 36}}
        self.add_error: Exception | None = None
        self.group_payload: dict[str, Any] = {
            "SharingGroup": {"id": "7", "name": "Energy ISAC", "active": True},
            "Organisation": [{"id": "1", "name": "Test Org"}],
            "SharingGroupOrg": [{"org_id": "1"}],
        }
        self.group_error: Exception | None = None
        self.event_payload: dict[str, Any] = {"Event": {"id": "42", "distribution": 0}}
        self.event_error: Exception | None = None
        self.publish_error: Exception | None = None
        FakeMISP.instances.append(self)

    def get_user(self, scope: str) -> dict[str, Any]:
        self.calls.append(("get_user", scope))
        if self.user_error is not None:
            raise self.user_error
        return self.user_payload

    def add_event(self, event: Any) -> dict[str, Any]:
        self.calls.append(("add_event", event))
        if self.add_error is not None:
            raise self.add_error
        return self.add_result

    def get_sharing_group(self, group_id: int) -> dict[str, Any]:
        self.calls.append(("get_sharing_group", group_id))
        if self.group_error is not None:
            raise self.group_error
        return self.group_payload

    def get_event(self, uuid: str) -> dict[str, Any]:
        self.calls.append(("get_event", uuid))
        if self.event_error is not None:
            raise self.event_error
        return self.event_payload

    def publish(self, event_id: Any, alert: bool = False) -> dict[str, Any]:
        self.calls.append(("publish", (event_id, alert)))
        if self.publish_error is not None:
            raise self.publish_error
        return {}


@pytest.fixture()
def fake_misp(monkeypatch):
    FakeMISP.instances.clear()
    monkeypatch.setattr(misp_client, "PyMISP", FakeMISP)
    return FakeMISP


def package(
    proposed: str = "TLP:AMBER", verified: bool = True, **overrides: Any
) -> SharePrepareResponse:
    analysis = canned_analysis()
    if verified:
        for ioc in analysis["indicators_of_compromise"]:
            ioc["verified_in_source"] = True
        for cve in analysis["cves"]:
            cve["verified_in_source"] = True
    payload = share_payload(
        analysis=make_response(analysis).model_dump(mode="json"),
        proposed_marking=proposed,
        analyst_notes="Reviewed for MISP draft.",
        **overrides,
    )
    return sharing.build_package(SharePrepareRequest.model_validate(payload), "operator")


def pkg_json(pkg: SharePrepareResponse) -> dict[str, Any]:
    return pkg.model_dump(mode="json")


def post(client: TestClient, path: str, body: dict[str, Any]):
    # Publish needs the administrator role; everything else uses the operator.
    key = ADMIN_KEY if path == "/api/misp/publish" else None
    headers = csrf_headers(client, key) if key else csrf_headers(client)
    response = client.post(path, json=body, headers=headers)
    BODIES.append(response.text)
    return response


def audit_events(tmp_path) -> list[dict[str, Any]]:
    path = tmp_path / "audit.log"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# --- health ---


def test_config_flags_need_a_session(
    client: TestClient, misp_settings, monkeypatch
) -> None:
    assert "misp_configured" not in client.get("/api/health").json()
    login_as(client)
    assert client.get("/api/auth/status").json()["misp_configured"] is True
    monkeypatch.setattr(settings, "misp_api_key", "")
    assert client.get("/api/auth/status").json()["misp_configured"] is False


# --- preview ---


def test_preview_maps_full_event(client: TestClient, misp_settings) -> None:
    response = post(
        client,
        "/api/misp/preview",
        {"package": pkg_json(package()),
         "destination": {"distribution": 1}},
    )
    assert response.status_code == 200
    body = response.json()
    event = body["event"]
    assert event["published"] is False
    assert event["distribution"] == 1
    assert event["threat_level_id"] == 4
    assert event["analysis"] == 2
    assert "[TLP:AMBER]" in event["info"]
    assert "synthetic_ics_report.txt" in event["info"]
    assert body["tlp_tag"] == "tlp:amber"
    assert "tlp:amber" in event["tags"]
    assert body["warnings"] == []
    assert body["attribute_count"] == len(event["attributes"]) == 11

    by_value = {a["value"]: a for a in event["attributes"]}
    ip_attr = by_value["192.0.2.44"]
    assert ip_attr["type"] == "ip-dst"
    assert ip_attr["category"] == "Network activity"
    assert ip_attr["to_ids"] is True
    assert "direction not specified" in ip_attr["comment"]
    assert "192.0.2.44 over TCP/443" in ip_attr["comment"]
    dom_attr = by_value["turbine-updates.example.com"]
    assert dom_attr["type"] == "domain"
    assert dom_attr["to_ids"] is True
    cve_attr = by_value["CVE-2026-44107"]
    assert cve_attr["type"] == "vulnerability"
    assert cve_attr["to_ids"] is False
    host = by_value["BM-ENG-WS04"]
    assert host["type"] == "text"
    assert "confirmed" in host["comment"]
    assert "turbine-control" in host["comment"]
    rec = by_value["Isolate BM-ENG-WS04 and reimage from known-good media."]
    assert "priority: critical" in rec["comment"]
    assert by_value["One operator opened the attachment"]["type"] == "text"
    assert by_value["Reviewed for MISP draft."]["comment"] == "Analyst notes"
    attribution = [a for a in event["attributes"]
                   if a["comment"] == "Source attribution and sharing reference"]
    assert len(attribution) == 1
    assert "synthetic_ics_report.txt" in attribution[0]["value"]
    assert "muse-spark-1.3" in attribution[0]["value"]

    galaxies = [t for t in event["tags"] if t.startswith("misp-galaxy:")]
    assert len(galaxies) == 2
    assert any("T1566.002" in t for t in galaxies)
    assert any("T1078" in t for t in galaxies)
    # Official ATT&CK names, not the model's paraphrase.
    official = load_attack_data()["techniques"]
    assert any(official["T1566.002"]["name"] in t for t in galaxies)
    assert not any("Spearphishing Attachment" in t for t in galaxies)

    check = body["destination_check"]
    assert check["safe"] is True
    assert check["verified"] is False
    assert "This community only" in check["reason"]


def test_attributes_inherit_event_distribution() -> None:
    event, _ = build_misp_event(package(), 1, None)
    node = json.loads(event.to_json())
    assert node["distribution"] == "1"
    assert node["published"] is False
    for attr in node["Attribute"]:
        assert "distribution" not in attr
        assert "sharing_group_id" not in attr


def test_preview_marks_unverified_leads(client: TestClient) -> None:
    body = post(
        client, "/api/misp/preview",
        {"package": pkg_json(package(verified=False))},
    ).json()
    by_value = {a["value"]: a for a in body["event"]["attributes"]}
    ip_attr = by_value["192.0.2.44"]
    assert ip_attr["to_ids"] is False
    assert "UNVERIFIED lead" in ip_attr["comment"]
    assert "CVE-2026-44107" not in by_value
    assert any("CVE-2026-44107" in w for w in body["warnings"])


def test_preview_red_flags_wider_destination(client: TestClient) -> None:
    response = post(
        client,
        "/api/misp/preview",
        {"package": pkg_json(package(proposed="TLP:RED")),
         "destination": {"distribution": 2}},
    )
    assert response.status_code == 200
    check = response.json()["destination_check"]
    assert check["safe"] is False
    assert check["verified"] is False
    assert "organisation only" in check["reason"]


def test_preview_without_destination_defaults_org_only(client: TestClient) -> None:
    body = post(
        client, "/api/misp/preview", {"package": pkg_json(package())}
    ).json()
    assert body["event"]["distribution"] == 0
    assert body["destination_check"] is None


def test_preview_rejects_bad_destination(client: TestClient) -> None:
    pkg = pkg_json(package())
    response = post(
        client, "/api/misp/preview",
        {"package": pkg, "destination": {"distribution": 9}},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_destination"
    response = post(
        client, "/api/misp/preview",
        {"package": pkg, "destination": {"distribution": 4}},
    )
    assert response.status_code == 400


def test_preview_rejects_invalid_marking(client: TestClient) -> None:
    pkg = pkg_json(package())
    pkg["classification"]["proposed"] = "TLP:BOGUS"
    response = post(client, "/api/misp/preview", {"package": pkg})
    assert response.status_code == 400


# --- draft creation ---


def create_body(pkg: SharePrepareResponse, dist: int = 1,
                group: int | None = None, **approval: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "package": pkg_json(pkg),
        "analyst": "analyst-1",
        "destination": {"distribution": dist, "sharing_group_id": group},
        "approval": {"approved": True, "confirmed": True},
    }
    if approval:
        body["approval"] = approval
    return body


def test_create_draft_success(
    client: TestClient, misp_settings, fake_misp, tmp_path
) -> None:
    pkg = package()
    response = post(client, "/api/misp/create", create_body(pkg))
    assert response.status_code == 200
    body = response.json()
    assert body["event_id"] == "42"
    assert body["duplicate"] is False
    assert body["url"] == f"{FAKE_URL}/events/view/42"
    assert body["warnings"] == []

    instance = FakeMISP.instances[-1]
    assert instance.url == FAKE_URL
    assert instance.kwargs["timeout"] == 7
    assert instance.kwargs["ssl"] is True
    kinds = [kind for kind, _ in instance.calls]
    assert kinds == ["get_user", "add_event"]
    sent = instance.calls[1][1]
    node = json.loads(sent.to_json())
    assert node["published"] is False
    assert node["distribution"] == "1"
    assert len(node["Attribute"]) == 11

    store = json.loads((tmp_path / "misp.json").read_text(encoding="utf-8"))
    assert len(store["exports"]) == 1
    entry = store["exports"][0]
    assert entry["status"] == "draft"
    assert entry["package_id"] == pkg.package_id
    assert entry["distribution"] == 1

    created = [e for e in audit_events(tmp_path) if e["event"] == "misp_created"]
    assert len(created) == 1
    assert created[0]["analyst"] == "operator"
    assert created[0]["distribution"] == 1
    assert created[0]["attribute_count"] == 11


def test_create_is_idempotent(
    client: TestClient, misp_settings, fake_misp, tmp_path
) -> None:
    pkg = package()
    first = post(client, "/api/misp/create", create_body(pkg))
    second = post(client, "/api/misp/create", create_body(pkg))
    assert first.status_code == second.status_code == 200
    assert second.json()["duplicate"] is True
    assert second.json()["event_id"] == "42"
    adds = [c for i in FakeMISP.instances for c in i.calls if c[0] == "add_event"]
    assert len(adds) == 1
    dupes = [e for e in audit_events(tmp_path) if e["event"] == "misp_duplicate"]
    assert len(dupes) == 1


def test_create_requires_approval_and_confirmation(
    client: TestClient, misp_settings, fake_misp
) -> None:
    pkg = package()
    for approval in ({}, {"approved": True}, {"approved": True, "confirmed": False},
                     {"approved": False, "confirmed": True}):
        body = create_body(pkg)
        body["approval"] = approval
        response = post(client, "/api/misp/create", body)
        assert response.status_code == 422
        assert response.json()["detail"]["code"] == "approval_required"
    body = create_body(pkg)
    del body["approval"]
    assert post(client, "/api/misp/create", body).status_code == 422
    assert FakeMISP.instances == []


def test_create_red_blocked_for_wider_distribution(
    client: TestClient, misp_settings, fake_misp, tmp_path
) -> None:
    pkg = package(proposed="TLP:RED")
    response = post(client, "/api/misp/create", create_body(pkg, dist=1))
    assert response.status_code == 403
    assert FakeMISP.instances == []
    rejected = [e for e in audit_events(tmp_path) if e["event"] == "misp_rejected"]
    assert rejected and rejected[0]["code"] == "unsafe_destination"


def test_create_red_org_only_allowed(
    client: TestClient, misp_settings, fake_misp
) -> None:
    response = post(
        client, "/api/misp/create",
        create_body(package(proposed="TLP:RED"), dist=0),
    )
    assert response.status_code == 200
    node = json.loads(FakeMISP.instances[-1].calls[1][1].to_json())
    assert node["distribution"] == "0"


def test_create_unconfigured(client: TestClient, fake_misp, monkeypatch) -> None:
    monkeypatch.setattr(settings, "misp_url", "")
    monkeypatch.setattr(settings, "misp_api_key", "")
    response = post(client, "/api/misp/create", create_body(package()))
    assert response.status_code == 503
    assert FakeMISP.instances == []


def test_create_denied_without_add_permission(
    client: TestClient, misp_settings, fake_misp, monkeypatch, tmp_path
) -> None:
    def restricted(url: str, key: str, **kwargs: Any) -> FakeMISP:
        inst = FakeMISP(url, key, **kwargs)
        inst.user_payload["Role"]["perm_add"] = False
        return inst

    monkeypatch.setattr(misp_client, "PyMISP", restricted)
    response = post(client, "/api/misp/create", create_body(package()))
    assert response.status_code == 403
    assert not (tmp_path / "misp.json").exists()
    rejected = [e for e in audit_events(tmp_path) if e["event"] == "misp_rejected"]
    assert rejected and rejected[0]["code"] == "permission_denied"


def test_create_api_error(
    client: TestClient, misp_settings, fake_misp, monkeypatch, tmp_path
) -> None:
    from pymisp.exceptions import PyMISPError

    def failing(url: str, key: str, **kwargs: Any) -> FakeMISP:
        inst = FakeMISP(url, key, **kwargs)
        inst.add_error = PyMISPError("boom")
        return inst

    monkeypatch.setattr(misp_client, "PyMISP", failing)
    response = post(client, "/api/misp/create", create_body(package()))
    assert response.status_code == 502
    rejected = [e for e in audit_events(tmp_path) if e["event"] == "misp_rejected"]
    assert rejected and rejected[0]["code"] == "misp_api_error"


def test_create_auth_failure(
    client: TestClient, misp_settings, fake_misp, monkeypatch
) -> None:
    def unauthorized(url: str, key: str, **kwargs: Any) -> FakeMISP:
        inst = FakeMISP(url, key, **kwargs)
        inst.user_error = _http_error(401)
        return inst

    monkeypatch.setattr(misp_client, "PyMISP", unauthorized)
    response = post(client, "/api/misp/create", create_body(package()))
    assert response.status_code == 503


def test_create_sharing_group_verified(
    client: TestClient, misp_settings, fake_misp
) -> None:
    response = post(
        client, "/api/misp/create", create_body(package(), dist=4, group=7)
    )
    assert response.status_code == 200
    instance = FakeMISP.instances[-1]
    kinds = [kind for kind, _ in instance.calls]
    assert kinds == ["get_user", "get_sharing_group", "add_event"]
    node = json.loads(instance.calls[2][1].to_json())
    assert node["distribution"] == "4"
    assert node["sharing_group_id"] == "7"


def test_create_sharing_group_unverifiable(
    client: TestClient, misp_settings, fake_misp, monkeypatch, tmp_path
) -> None:
    def outsider(url: str, key: str, **kwargs: Any) -> FakeMISP:
        inst = FakeMISP(url, key, **kwargs)
        inst.group_payload = {
            "SharingGroup": {"id": "7", "name": "Other", "active": True},
            "Organisation": [{"id": "99", "name": "Other Org"}],
            "SharingGroupOrg": [{"org_id": "99"}],
        }
        return inst

    monkeypatch.setattr(misp_client, "PyMISP", outsider)
    response = post(
        client, "/api/misp/create", create_body(package(), dist=4, group=7)
    )
    assert response.status_code == 403
    rejected = [e for e in audit_events(tmp_path) if e["event"] == "misp_rejected"]
    assert rejected and rejected[0]["code"] == "recipient_unverifiable"


# --- publishing ---


def publish_body(uuid: str, **approval: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "event_uuid": uuid,
        "analyst": "analyst-1",
        "approval": {"approved": True, "confirmed": True},
    }
    if approval:
        body["approval"] = approval
    return body


def _publisher(**tweaks: Any):
    def factory(url: str, key: str, **kwargs: Any) -> FakeMISP:
        inst = FakeMISP(url, key, **kwargs)
        inst.user_payload["Role"]["perm_publish"] = True
        for name, value in tweaks.items():
            setattr(inst, name, value)
        return inst

    return factory


def test_publish_success(
    client: TestClient, misp_settings, fake_misp, monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(misp_client, "PyMISP", _publisher())
    created = post(client, "/api/misp/create", create_body(package(), dist=0))
    uuid = created.json()["event_uuid"]

    response = post(client, "/api/misp/publish", publish_body(uuid))
    assert response.status_code == 200
    assert response.json() == {"event_uuid": uuid, "published": True}

    calls = [c for i in FakeMISP.instances for c in i.calls]
    publishes = [c for c in calls if c[0] == "publish"]
    assert publishes == [("publish", ("42", False))]
    assert any(c[0] == "get_event" for c in calls)

    store = json.loads((tmp_path / "misp.json").read_text(encoding="utf-8"))
    assert store["exports"][0]["status"] == "published"
    published = [e for e in audit_events(tmp_path)
                 if e["event"] == "misp_published"]
    assert len(published) == 1
    assert published[0]["event_uuid"] == uuid


def test_publish_requires_approval(
    client: TestClient, misp_settings, fake_misp
) -> None:
    uuid = post(client, "/api/misp/create", create_body(package())).json()[
        "event_uuid"
    ]
    before = len(FakeMISP.instances)
    response = post(client, "/api/misp/publish",
                    publish_body(uuid, approved=True, confirmed=False))
    assert response.status_code == 422
    assert len(FakeMISP.instances) == before  # no new client, no network


def test_publish_unknown_event(
    client: TestClient, misp_settings, fake_misp
) -> None:
    response = post(client, "/api/misp/publish", publish_body("nope"))
    assert response.status_code == 404
    assert FakeMISP.instances == []


def test_publish_denied_without_permission(
    client: TestClient, misp_settings, fake_misp, tmp_path
) -> None:
    uuid = post(client, "/api/misp/create", create_body(package())).json()[
        "event_uuid"
    ]
    response = post(client, "/api/misp/publish", publish_body(uuid))
    assert response.status_code == 403
    rejected = [e for e in audit_events(tmp_path)
                if e["event"] == "misp_publish_rejected"]
    assert rejected and rejected[0]["code"] == "permission_denied"


def test_publish_red_blocks_moved_distribution(
    client: TestClient, misp_settings, fake_misp, monkeypatch
) -> None:
    monkeypatch.setattr(
        misp_client, "PyMISP",
        _publisher(event_payload={"Event": {"id": "42", "distribution": 1}}),
    )
    uuid = post(
        client, "/api/misp/create",
        create_body(package(proposed="TLP:RED"), dist=0),
    ).json()["event_uuid"]
    response = post(client, "/api/misp/publish", publish_body(uuid))
    assert response.status_code == 403
    assert not [c for i in FakeMISP.instances for c in i.calls
                if c[0] == "publish"]


def test_publish_is_idempotent(
    client: TestClient, misp_settings, fake_misp, monkeypatch
) -> None:
    monkeypatch.setattr(
        misp_client, "PyMISP",
        _publisher(event_payload={"Event": {"id": "42", "distribution": 1}}),
    )
    uuid = post(client, "/api/misp/create", create_body(package())).json()[
        "event_uuid"
    ]
    first = post(client, "/api/misp/publish", publish_body(uuid))
    second = post(client, "/api/misp/publish", publish_body(uuid))
    assert first.json()["published"] is True
    assert second.json()["published"] is True
    publishes = [c for i in FakeMISP.instances for c in i.calls
                 if c[0] == "publish"]
    assert len(publishes) == 1


# --- connection test ---


def test_test_connection_success(client: TestClient, misp_settings, fake_misp,
                                 tmp_path) -> None:
    response = post(client, "/api/misp/test", {})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["org"] == "Test Org"
    assert body["can_add"] is True
    assert body["can_publish"] is False
    tested = [e for e in audit_events(tmp_path) if e["event"] == "misp_tested"]
    assert tested and tested[0]["ok"] is True


def test_test_connection_failure(client: TestClient, misp_settings, fake_misp,
                                 monkeypatch, tmp_path) -> None:
    def down(url: str, key: str, **kwargs: Any) -> FakeMISP:
        inst = FakeMISP(url, key, **kwargs)
        inst.user_error = requests.ConnectionError("refused")
        return inst

    monkeypatch.setattr(misp_client, "PyMISP", down)
    response = post(client, "/api/misp/test", {})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "misp_unreachable"


def test_test_connection_unconfigured(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(settings, "misp_url", "")
    monkeypatch.setattr(settings, "misp_api_key", "")
    body = post(client, "/api/misp/test", {}).json()
    assert body["ok"] is False
    assert body["error"]["code"] == "misp_not_configured"


# --- error mapping ---


def _http_error(status: int) -> Exception:
    response = requests.Response()
    response.status_code = status
    exc = Exception(f"HTTP {status}")
    exc.response = response  # type: ignore[attr-defined]
    return exc


def test_map_error_kinds() -> None:
    assert misp_client.map_error(requests.Timeout(), "x").code == "misp_timeout"
    assert misp_client.map_error(requests.ConnectionError(), "x").code == \
        "misp_unreachable"
    assert misp_client.map_error(_http_error(401), "x").code == "misp_auth_failed"
    denied = misp_client.map_error(_http_error(403), "x")
    assert (denied.code, denied.status_code) == ("permission_denied", 403)
    assert misp_client.map_error(ValueError("weird"), "x").code == "misp_api_error"


# --- H-1 destination allowlist ---


def test_allowlist_parsing() -> None:
    assert Settings(misp_allowed_distributions="0, 2").misp_distribution_allowlist == {0, 2}
    assert Settings(misp_allowed_sharing_groups="").misp_sharing_group_allowlist == set()
    # Malformed entries fail closed (deny everything).
    assert Settings(misp_allowed_distributions="0,all").misp_distribution_allowlist == set()
    assert Settings(misp_allowed_sharing_groups="7,-1").misp_sharing_group_allowlist == set()
    # Fail-closed production defaults (field defaults, env-independent).
    assert Settings.model_fields["misp_allowed_distributions"].default == "0"
    assert Settings.model_fields["misp_allowed_sharing_groups"].default == ""


def test_create_rejects_non_allowlisted_distribution(
    client: TestClient, misp_settings, fake_misp, monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(settings, "misp_allowed_distributions", "0,1")
    response = post(client, "/api/misp/create", create_body(package(), dist=3))
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "destination_not_allowed"
    assert FakeMISP.instances == []  # denied before any MISP traffic
    rejected = [e for e in audit_events(tmp_path) if e["event"] == "misp_rejected"]
    assert rejected and rejected[0]["code"] == "destination_not_allowed"
    assert rejected[0]["distribution"] == 3


def test_create_rejects_non_allowlisted_sharing_group(
    client: TestClient, misp_settings, fake_misp, tmp_path
) -> None:
    response = post(
        client, "/api/misp/create", create_body(package(), dist=4, group=99)
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "destination_not_allowed"
    assert FakeMISP.instances == []
    rejected = [e for e in audit_events(tmp_path) if e["event"] == "misp_rejected"]
    assert rejected and rejected[0]["sharing_group_id"] == 99


def test_create_rejects_sharing_group_when_none_allowed(
    client: TestClient, misp_settings, fake_misp, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "misp_allowed_sharing_groups", "")
    response = post(
        client, "/api/misp/create", create_body(package(), dist=4, group=7)
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "destination_not_allowed"
    assert FakeMISP.instances == []


def test_create_denied_even_for_duplicate_after_revocation(
    client: TestClient, misp_settings, fake_misp, monkeypatch
) -> None:
    body = create_body(package(), dist=1)
    assert post(client, "/api/misp/create", body).status_code == 200
    monkeypatch.setattr(settings, "misp_allowed_distributions", "0")
    response = post(client, "/api/misp/create", body)
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "destination_not_allowed"


def test_preview_flags_non_allowlisted_destination(
    client: TestClient, misp_settings, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "misp_allowed_distributions", "0")
    response = post(
        client,
        "/api/misp/preview",
        {"package": pkg_json(package()),
         "destination": {"distribution": 1}},
    )
    assert response.status_code == 200
    check = response.json()["destination_check"]
    assert check["safe"] is False
    assert "allowlist" in check["reason"]


def test_preview_flags_non_allowlisted_sharing_group(
    client: TestClient, misp_settings, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "misp_allowed_sharing_groups", "")
    response = post(
        client,
        "/api/misp/preview",
        {"package": pkg_json(package()),
         "destination": {"distribution": 4, "sharing_group_id": 7}},
    )
    assert response.status_code == 200
    check = response.json()["destination_check"]
    assert check["safe"] is False
    assert "Sharing group 7" in check["reason"]


def test_publish_denied_after_destination_revoked(
    client: TestClient, misp_settings, fake_misp, monkeypatch, tmp_path
) -> None:
    uuid = post(client, "/api/misp/create", create_body(package(), dist=1)).json()[
        "event_uuid"
    ]
    monkeypatch.setattr(settings, "misp_allowed_distributions", "0")
    response = post(client, "/api/misp/publish", publish_body(uuid))
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "destination_not_allowed"
    assert not [c for i in FakeMISP.instances for c in i.calls
                if c[0] == "publish"]
    rejected = [e for e in audit_events(tmp_path)
                if e["event"] == "misp_publish_rejected"]
    assert rejected and rejected[0]["code"] == "destination_not_allowed"


def test_publish_rejects_live_distribution_mismatch(
    client: TestClient, misp_settings, fake_misp, monkeypatch
) -> None:
    monkeypatch.setattr(
        misp_client, "PyMISP",
        _publisher(event_payload={"Event": {"id": "42", "distribution": 1}}),
    )
    uuid = post(client, "/api/misp/create", create_body(package(), dist=0)).json()[
        "event_uuid"
    ]
    response = post(client, "/api/misp/publish", publish_body(uuid))
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "destination_changed"
    assert not [c for i in FakeMISP.instances for c in i.calls
                if c[0] == "publish"]


def test_publish_accepts_stringified_live_destination(
    client: TestClient, misp_settings, fake_misp, monkeypatch
) -> None:
    # Real MISP serializes these fields as strings; coercion must accept them.
    monkeypatch.setattr(
        misp_client, "PyMISP",
        _publisher(event_payload={
            "Event": {"id": "42", "distribution": "4", "sharing_group_id": "7"}
        }),
    )
    uuid = post(
        client, "/api/misp/create", create_body(package(), dist=4, group=7)
    ).json()["event_uuid"]
    response = post(client, "/api/misp/publish", publish_body(uuid))
    assert response.status_code == 200
    assert response.json()["published"] is True


def test_publish_rejects_live_group_mismatch(
    client: TestClient, misp_settings, fake_misp, monkeypatch
) -> None:
    monkeypatch.setattr(
        misp_client, "PyMISP",
        _publisher(event_payload={
            "Event": {"id": "42", "distribution": 4, "sharing_group_id": 9}
        }),
    )
    uuid = post(
        client, "/api/misp/create", create_body(package(), dist=4, group=7)
    ).json()["event_uuid"]
    response = post(client, "/api/misp/publish", publish_body(uuid))
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "destination_changed"


def _group_flap_factory(monkeypatch, group_payload: dict[str, Any]):
    """First client (create) sees the healthy group; later ones see `group_payload`."""
    calls = {"n": 0}

    def factory(url: str, key: str, **kwargs: Any) -> FakeMISP:
        inst = FakeMISP(url, key, **kwargs)
        inst.user_payload["Role"]["perm_publish"] = True
        inst.event_payload = {
            "Event": {"id": "42", "distribution": 4, "sharing_group_id": 7}
        }
        calls["n"] += 1
        if calls["n"] > 1:
            inst.group_payload = group_payload
        return inst

    monkeypatch.setattr(misp_client, "PyMISP", factory)


def test_publish_rejects_deactivated_group(
    client: TestClient, misp_settings, fake_misp, monkeypatch
) -> None:
    _group_flap_factory(monkeypatch, {
        "SharingGroup": {"id": "7", "name": "Energy ISAC", "active": False},
        "Organisation": [{"id": "1", "name": "Test Org"}],
        "SharingGroupOrg": [{"org_id": "1"}],
    })
    uuid = post(
        client, "/api/misp/create", create_body(package(), dist=4, group=7)
    ).json()["event_uuid"]
    response = post(client, "/api/misp/publish", publish_body(uuid))
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "recipient_unverifiable"
    assert not [c for i in FakeMISP.instances for c in i.calls
                if c[0] == "publish"]


def test_publish_rejects_lost_group_membership(
    client: TestClient, misp_settings, fake_misp, monkeypatch
) -> None:
    _group_flap_factory(monkeypatch, {
        "SharingGroup": {"id": "7", "name": "Energy ISAC", "active": True},
        "Organisation": [{"id": "2", "name": "Someone Else"}],
        "SharingGroupOrg": [{"org_id": "2"}],
    })
    uuid = post(
        client, "/api/misp/create", create_body(package(), dist=4, group=7)
    ).json()["event_uuid"]
    response = post(client, "/api/misp/publish", publish_body(uuid))
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "recipient_unverifiable"


def test_publish_live_fetch_failure(
    client: TestClient, misp_settings, fake_misp, monkeypatch, tmp_path
) -> None:
    uuid = post(client, "/api/misp/create", create_body(package(), dist=0)).json()[
        "event_uuid"
    ]

    def failing(url: str, key: str, **kwargs: Any) -> FakeMISP:
        inst = FakeMISP(url, key, **kwargs)
        inst.user_payload["Role"]["perm_publish"] = True
        inst.event_error = requests.ConnectionError("misp down")
        return inst

    monkeypatch.setattr(misp_client, "PyMISP", failing)
    response = post(client, "/api/misp/publish", publish_body(uuid))
    assert response.status_code == 502
    assert response.json()["detail"]["code"] == "misp_unreachable"
    rejected = [e for e in audit_events(tmp_path)
                if e["event"] == "misp_publish_rejected"]
    assert rejected and rejected[0]["code"] == "misp_unreachable"


def test_tlp_red_still_blocked_when_distribution_allowlisted(
    client: TestClient, misp_settings, fake_misp
) -> None:
    # The allowlist never broadens TLP:RED.
    response = post(
        client, "/api/misp/create",
        create_body(package(proposed="TLP:RED"), dist=1),
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "unsafe_destination"
    assert FakeMISP.instances == []


def test_tlp_red_org_only_allowed_with_defaults(
    client: TestClient, misp_settings, fake_misp, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "misp_allowed_distributions", "0")
    monkeypatch.setattr(settings, "misp_allowed_sharing_groups", "")
    response = post(
        client, "/api/misp/create",
        create_body(package(proposed="TLP:RED"), dist=0),
    )
    assert response.status_code == 200


def test_empty_distribution_allowlist_denies_all(
    client: TestClient, misp_settings, fake_misp, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "misp_allowed_distributions", "")
    response = post(client, "/api/misp/create", create_body(package(), dist=0))
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "destination_not_allowed"


def test_malformed_allowlist_fails_closed(
    client: TestClient, misp_settings, fake_misp, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "misp_allowed_distributions", "0,all")
    response = post(client, "/api/misp/create", create_body(package(), dist=0))
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "destination_not_allowed"


@pytest.mark.parametrize("bad_url", ["ftp://misp.test", "file:///etc/passwd",
                                     "gopher://misp.test/1", "misp.test"])
def test_invalid_misp_url_rejected(
    client: TestClient, misp_settings, fake_misp, monkeypatch, bad_url: str
) -> None:
    monkeypatch.setattr(settings, "misp_url", bad_url)
    response = post(client, "/api/misp/create", create_body(package(), dist=0))
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "misp_invalid_url"
    assert FakeMISP.instances == []


def test_client_url_smuggling_ignored(
    client: TestClient, misp_settings, fake_misp, tmp_path
) -> None:
    body = create_body(package(), dist=0)
    body["destination"]["url"] = "http://evil.test/steal"
    response = post(client, "/api/misp/create", body)
    assert response.status_code == 200
    assert FakeMISP.instances and FakeMISP.instances[0].url == FAKE_URL
    created = [e for e in audit_events(tmp_path) if e["event"] == "misp_created"]
    assert created and created[0]["url"] == FAKE_URL
    assert created[0]["destination_allowed"] is True
    assert "evil" not in response.text


def test_approved_audits_mark_destination_allowed(
    client: TestClient, misp_settings, fake_misp, monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(misp_client, "PyMISP", _publisher())
    uuid = post(client, "/api/misp/create", create_body(package(), dist=0)).json()[
        "event_uuid"
    ]
    assert post(client, "/api/misp/publish", publish_body(uuid)).status_code == 200
    created = [e for e in audit_events(tmp_path) if e["event"] == "misp_created"]
    published = [e for e in audit_events(tmp_path) if e["event"] == "misp_published"]
    assert created and created[0]["destination_allowed"] is True
    assert published and published[0]["destination_allowed"] is True
    assert published[0]["distribution"] == 0


def test_secrets_never_leaked(tmp_path) -> None:
    for body in BODIES:
        assert FAKE_KEY not in body
        assert "misp-key" not in body
    for name in ("audit.log", "misp.json"):
        path = tmp_path / name
        if path.exists():
            assert FAKE_KEY not in path.read_text(encoding="utf-8")

