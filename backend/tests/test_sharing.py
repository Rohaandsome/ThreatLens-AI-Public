"""Tests for TLP 2.0 sharing preparation (no network I/O)."""

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.services import tlp
from tests.conftest import canned_analysis, csrf_headers
from tests.test_stix import make_response


@pytest.fixture(autouse=True)
def isolated_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATLENS_AUDIT_LOG", str(tmp_path / "audit.log"))
    return tmp_path / "audit.log"


def audit_events(path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def full_selection() -> dict[str, Any]:
    canned = canned_analysis()
    return {
        "include_summary": True,
        "techniques": [0, 1],
        "iocs": [i["value"] for i in canned["indicators_of_compromise"]],
        "cves": [c["id"] for c in canned["cves"]],
        "systems": [s["system"] for s in canned["affected_systems"]],
        "recommendations": [0, 1],
        "evidence": [0],
    }


def share_payload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "analysis": make_response().model_dump(mode="json"),
        "sources": [{"name": "synthetic_ics_report.txt", "marking": "TLP:AMBER"}],
        "analyst_source_marking": None,
        "proposed_marking": "TLP:AMBER",
        "selection": full_selection(),
        "redactions": [],
        "approval": {
            "approved": True,
            "analyst": "analyst-1",
            "justification": "",
            "downgrade_accepted": False,
        },
        "audience_note": "",
    }
    base.update(overrides)
    return base


# --- TLP unit tests ---


def test_parse_markings() -> None:
    assert tlp.parse_marking("TLP:RED") == "TLP:RED"
    assert tlp.parse_marking("amber") == "TLP:AMBER"
    assert tlp.parse_marking(" tlp:green ") == "TLP:GREEN"
    assert tlp.parse_marking("AMBER+STRICT") == "TLP:AMBER+STRICT"
    assert tlp.parse_marking("clear") == "TLP:CLEAR"


def test_parse_rejects_invalid() -> None:
    for bad in ("", "TLP:BLUE", "AMBER STRICT", "TLP:YELLOW", "CONFIDENTIAL", "TLP:"):
        with pytest.raises(tlp.InvalidMarkingError):
            tlp.parse_marking(bad)


def test_most_restrictive() -> None:
    assert tlp.most_restrictive(["TLP:GREEN", "TLP:AMBER"]) == "TLP:AMBER"
    assert tlp.most_restrictive(["TLP:CLEAR", "TLP:RED"]) == "TLP:RED"
    assert tlp.most_restrictive(["TLP:AMBER", "TLP:AMBER+STRICT"]) == "TLP:AMBER+STRICT"
    assert tlp.most_restrictive(["TLP:GREEN"]) == "TLP:GREEN"
    with pytest.raises(ValueError):
        tlp.most_restrictive([])


def test_is_downgrade_matrix() -> None:
    assert tlp.is_downgrade("TLP:AMBER", "TLP:GREEN") is True
    assert tlp.is_downgrade("TLP:AMBER+STRICT", "TLP:AMBER") is True
    assert tlp.is_downgrade("TLP:GREEN", "TLP:AMBER") is False  # upgrade
    assert tlp.is_downgrade("TLP:AMBER", "TLP:AMBER+STRICT") is False  # upgrade
    assert tlp.is_downgrade("TLP:RED", "TLP:RED") is False


def test_audience_text_for_all_designations() -> None:
    seen = {tlp.audience(m) for m in tlp.CANONICAL_MARKINGS}
    assert len(seen) == 5
    assert all(len(a) > 20 for a in seen)
    assert "organization" in tlp.audience("TLP:AMBER+STRICT")
    assert "without restriction" in tlp.audience("TLP:CLEAR")


# --- Prepare route tests ---


def test_prepare_same_marking(client: TestClient, isolated_audit) -> None:
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=share_payload())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["classification"]["effective_source"] == "TLP:AMBER"
    assert body["classification"]["downgrade"] is False
    assert "clients" in body["audience"]
    assert body["content_counts"] == {
        "summary": 1,
        "techniques": 2,
        "iocs": 2,
        "cves": 1,
        "systems": 2,
        "recommendations": 2,
        "evidence": 1,
    }
    assert body["redactions_applied"] == 0
    events = audit_events(isolated_audit)
    assert [e["event"] for e in events] == ["prepared"]
    assert events[0]["analyst"] == "operator"
    assert events[0]["package_id"] == body["package_id"]
    assert body["audit_id"] == events[0]["id"]


def test_unclassified_source_requires_explicit_classification(
    client: TestClient, isolated_audit
) -> None:
    payload = share_payload(sources=[{"name": "report.txt", "marking": None}])
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=payload)
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "classification_required"
    events = audit_events(isolated_audit)
    assert events[-1]["event"] == "rejected"
    assert events[-1]["code"] == "classification_required"


def test_mixed_marked_unmarked_requires_classification(client: TestClient) -> None:
    payload = share_payload(
        sources=[
            {"name": "a.txt", "marking": "TLP:GREEN"},
            {"name": "b.txt", "marking": None},
        ]
    )
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=payload)
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "classification_required"


def test_analyst_classification_fills_gap(client: TestClient, isolated_audit) -> None:
    payload = share_payload(
        sources=[{"name": "report.txt", "marking": None}],
        analyst_source_marking="TLP:RED",
        proposed_marking="TLP:RED",
    )
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["classification"]["effective_source"] == "TLP:RED"
    assert body["classification"]["analyst_asserted"] is True
    events = audit_events(isolated_audit)
    assert [e["event"] for e in events] == ["classification", "prepared"]
    assert events[0]["asserted"] == "TLP:RED"


def test_analyst_cannot_re_mark_known_source_down(client: TestClient) -> None:
    payload = share_payload(
        analyst_source_marking="TLP:GREEN",  # source is marked AMBER
        approval={
            "approved": True,
            "analyst": "analyst-1",
            "justification": "I really want to share this widely",
            "downgrade_accepted": True,
        },
    )
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=payload)
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "downgrade_attempt"


def test_multi_source_uses_most_restrictive(client: TestClient) -> None:
    payload = share_payload(
        sources=[
            {"name": "a.txt", "marking": "TLP:GREEN"},
            {"name": "b.txt", "marking": "amber"},
        ]
    )
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=payload)
    assert resp.status_code == 200, resp.text
    assert resp.json()["classification"]["effective_source"] == "TLP:AMBER"


def test_invalid_tlp_values_rejected(client: TestClient) -> None:
    bad_source = share_payload(sources=[{"name": "a", "marking": "TLP:BLUE"}])
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=bad_source)
    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "invalid_tlp"

    bad_proposed = share_payload(proposed_marking="YELLOW")
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=bad_proposed)
    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "invalid_tlp"


def test_missing_approval_rejected(client: TestClient) -> None:
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=share_payload(approval=None))
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "approval_required"

    denied = share_payload()
    denied["approval"]["approved"] = False
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=denied)
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "approval_required"


def test_downgrade_requires_acceptance_and_justification(client: TestClient) -> None:
    base = {"proposed_marking": "TLP:GREEN"}  # source is AMBER
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=share_payload(**base))
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "downgrade_attempt"

    short = share_payload(**base)
    short["approval"]["downgrade_accepted"] = True
    short["approval"]["justification"] = "ok"
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=short)
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "downgrade_attempt"

    justified = share_payload(**base)
    justified["approval"]["downgrade_accepted"] = True
    justified["approval"]["justification"] = (
        "Sharing IOCs only with the community ISAC after removing hostnames."
    )
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=justified)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["classification"]["downgrade"] is True
    assert any("Downgrade" in w for w in body["warnings"])


def test_upgrade_allowed_without_downgrade_flag(client: TestClient) -> None:
    payload = share_payload(
        sources=[{"name": "a", "marking": "TLP:GREEN"}],
        proposed_marking="TLP:AMBER",
    )
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=payload)
    assert resp.status_code == 200, resp.text
    assert resp.json()["classification"]["downgrade"] is False


def test_invalid_selection_rejected(client: TestClient) -> None:
    bad_ioc = share_payload()
    bad_ioc["selection"]["iocs"] = ["10.0.0.99"]
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=bad_ioc)
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "invalid_selection"

    bad_idx = share_payload()
    bad_idx["selection"]["techniques"] = [7]
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=bad_idx)
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "invalid_selection"


def test_empty_selection_rejected(client: TestClient) -> None:
    payload = share_payload(
        selection={
            "include_summary": False,
            "techniques": [],
            "iocs": [],
            "cves": [],
            "systems": [],
            "recommendations": [],
            "evidence": [],
        }
    )
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=payload)
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "empty_selection"


def test_selection_filters_content(client: TestClient) -> None:
    payload = share_payload(
        selection={
            "include_summary": False,
            "techniques": [],
            "iocs": ["192.0.2.44"],
            "cves": [],
            "systems": [],
            "recommendations": [],
            "evidence": [],
        }
    )
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=payload)
    assert resp.status_code == 200, resp.text
    content = resp.json()["content"]
    assert content["executive_summary"] == ""
    assert [i["value"] for i in content["indicators_of_compromise"]] == ["192.0.2.44"]
    assert content["cves"] == []


def test_redactions_apply_to_text_not_identifiers(client: TestClient) -> None:
    payload = share_payload(
        selection={
            "include_summary": True,
            "techniques": [],
            "iocs": ["192.0.2.44"],
            "cves": [],
            "systems": [],
            "recommendations": [],
            "evidence": [],
        },
        redactions=[{"match": "192.0.2.44", "replacement": "[IP-REDACTED]"}],
    )
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["redactions_applied"] >= 1
    ioc = body["content"]["indicators_of_compromise"][0]
    assert ioc["value"] == "192.0.2.44"  # identifier intact
    assert "[IP-REDACTED]" in ioc["evidence_quote"]  # free text redacted


def test_unmatched_redaction_warns(client: TestClient) -> None:
    payload = share_payload(redactions=[{"match": "zzz-no-such-text", "replacement": "x"}])
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=payload)
    assert resp.status_code == 200, resp.text
    assert any("zzz-no-such-text" in w for w in resp.json()["warnings"])


def test_unverified_and_inferred_items_warn(client: TestClient) -> None:
    # Canned fixtures are unverified by default.
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=share_payload())
    assert resp.status_code == 200, resp.text
    warnings = resp.json()["warnings"]
    assert any("192.0.2.44" in w and "unverified" in w for w in warnings)
    assert any("CVE-2026-44107" in w and "unverified" in w for w in warnings)


def test_truncated_source_warns(client: TestClient) -> None:
    payload = share_payload()
    payload["analysis"]["truncated"] = True
    payload["analysis"]["char_count"] = 99999
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=payload)
    assert resp.status_code == 200, resp.text
    assert any("analysis window" in w for w in resp.json()["warnings"])


def test_invalid_analysis_body_rejected(client: TestClient) -> None:
    payload = share_payload()
    payload["analysis"] = {"analysis": {"executive_summary": 42}}
    resp = client.post("/api/share/prepare", headers=csrf_headers(client), json=payload)
    assert resp.status_code == 422
