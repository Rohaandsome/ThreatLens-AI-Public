"""Tests for STIX 2.1 export (no network I/O; MITRE data is vendored)."""

import copy
import json
from typing import Any

import stix2
from fastapi.testclient import TestClient

from app.schemas import AnalyzeResponse, AnalysisResult
from app.services import stix_export
from app.services.stix_export import (
    build_bundle,
    classify_mitre_id,
    classify_system,
    ioc_to_pattern,
    load_attack_data,
)
from tests.conftest import canned_analysis, csrf_headers


def make_response(
    analysis_dict: dict[str, Any] | None = None, **meta: Any
) -> AnalyzeResponse:
    analysis = AnalysisResult.model_validate(
        copy.deepcopy(analysis_dict if analysis_dict is not None else canned_analysis())
    )
    base: dict[str, Any] = {
        "filename": "synthetic_ics_report.txt",
        "file_type": "txt",
        "char_count": 2494,
        "truncated": False,
        "model": "muse-spark-1.3",
        "warnings": [],
        "analysis": analysis,
    }
    base.update(meta)
    return AnalyzeResponse.model_validate(base)


def mark_all_verified(response: AnalyzeResponse) -> AnalyzeResponse:
    for item in response.analysis.indicators_of_compromise:
        item.verified_in_source = True
    for cve in response.analysis.cves:
        cve.verified_in_source = True
    return response


def by_type(bundle: dict[str, Any], stix_type: str) -> list[dict[str, Any]]:
    return [o for o in bundle["objects"] if o["type"] == stix_type]


def test_bundle_validates_and_counts() -> None:
    bundle, warnings, counts = build_bundle(mark_all_verified(make_response()))
    assert warnings == []
    assert counts == {
        "identity": 1,
        "indicator": 2,
        "vulnerability": 1,
        "attack-pattern": 2,
        "infrastructure": 2,
        "relationship": 4,
        "report": 1,
    }
    # Independent validation: strict re-parse of the exported JSON.
    parsed = stix2.parse(json.dumps(bundle))
    assert parsed.type == "bundle"
    assert all(o["spec_version"] == "2.1" for o in bundle["objects"])
    assert len(bundle["objects"]) == sum(counts.values())


def test_attack_pattern_uses_official_mitre_data() -> None:
    dataset = load_attack_data()["techniques"]
    bundle, _, _ = build_bundle(mark_all_verified(make_response()))
    patterns = {p["name"]: p for p in by_type(bundle, "attack-pattern")}
    # Canned model data says "Spearphishing Attachment"; the dataset is authoritative.
    official = dataset["T1566.002"]["name"]
    assert official in patterns
    assert "Spearphishing Attachment" not in patterns
    link = patterns[official]
    assert link["external_references"][0]["source_name"] == "mitre-attack"
    assert link["external_references"][0]["external_id"] == "T1566.002"
    assert link["external_references"][0]["url"] == dataset["T1566.002"]["url"]
    assert "initial-access" in [
        p["phase_name"] for p in link["kill_chain_phases"]
    ]
    assert "subject" in link["description"]  # model evidence preserved


def test_mitre_dataset_is_versioned() -> None:
    data = load_attack_data()
    assert data["metadata"]["source"].startswith("https://github.com/mitre-attack/")
    import re

    assert re.match(r"^\d+\.\d+$", data["metadata"]["collection_version"])
    assert data["metadata"]["technique_count"] > 500


def test_classify_mitre_id() -> None:
    assert classify_mitre_id("T1078")[0] == "valid"
    assert classify_mitre_id(" t1078 ")[0] == "valid"  # normalized
    assert classify_mitre_id("T1566.002")[0] == "valid"
    for bad in (None, "", "abc", "T12", "T10781", "T1078.02"):
        assert classify_mitre_id(bad)[0] == "malformed", bad
    assert classify_mitre_id("T9999")[0] == "unknown"
    fake = {"techniques": {"T1000": {"name": "X", "revoked": True}}}
    assert classify_mitre_id("T1000", dataset=fake)[0] == "revoked"


def test_unknown_mitre_id_skipped_with_warning() -> None:
    dirty = canned_analysis()
    dirty["attack_techniques"] = [
        {
            "name": "Made Up",
            "mitre_id": "T9999",
            "description": "Not a real technique.",
            "evidence_quote": "nothing",
            "inferred": False,
        }
    ]
    bundle, warnings, counts = build_bundle(make_response(dirty))
    assert counts.get("attack-pattern", 0) == 0
    assert counts.get("relationship", 0) == 0
    assert any("T9999" in w and "unknown" in w for w in warnings)


def test_classify_system() -> None:
    from app.schemas import AffectedSystem

    assert (
        classify_system(
            AffectedSystem(system="a", detail="owned", evidence_quote="owned", inferred=False)
        )
        == "confirmed"
    )
    assert (
        classify_system(
            AffectedSystem(system="a", detail="maybe", evidence_quote="", inferred=True)
        )
        == "potentially-affected"
    )
    assert (
        classify_system(
            AffectedSystem(
                system="gw",
                detail="patched; no compromise observed",
                evidence_quote="no compromise observed",
                inferred=False,
            )
        )
        == "unaffected"
    )
    assert (
        classify_system(
            AffectedSystem(system="a", detail="hmm", evidence_quote="", inferred=False)
        )
        == "potentially-affected"
    )


def test_unaffected_system_has_no_relationships() -> None:
    dirty = canned_analysis()
    dirty["affected_systems"] = [
        {
            "system": "BM-VPN-GW02",
            "detail": "patched; no compromise observed",
            "evidence_quote": "no compromise observed",
            "inferred": False,
        }
    ]
    bundle, warnings, counts = build_bundle(mark_all_verified(make_response(dirty)))
    assert warnings == []
    infra = by_type(bundle, "infrastructure")[0]
    assert infra["labels"] == ["unaffected"]
    assert "unaffected" in infra["description"]
    assert counts.get("relationship", 0) == 0


def test_ioc_pattern_mapping() -> None:
    from app.schemas import IOC

    cases = [
        ("192.0.2.44", "ip", "[ipv4-addr:value = '192.0.2.44']"),
        ("2001:db8::1", "ip", "[ipv6-addr:value = '2001:db8::1']"),
        ("evil.example.com", "domain", "[domain-name:value = 'evil.example.com']"),
        ("https://x.example/a", "url", "[url:value = 'https://x.example/a']"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash", "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"),
        ("d41d8cd98f00b204e9800998ecf8427e", "hash", "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']"),
        ("a@example.com", "email", "[email-addr:value = 'a@example.com']"),
        ("evil.doc", "filename", "[file:name = 'evil.doc']"),
        ("o'clock.doc", "filename", "[file:name = 'o\\'clock.doc']"),
    ]
    for value, kind, expected in cases:
        pattern, problem = ioc_to_pattern(IOC(value=value, type=kind))  # type: ignore[arg-type]
        assert problem is None, (value, problem)
        assert pattern == expected, value


def test_malformed_iocs_skipped_with_warnings() -> None:
    dirty = canned_analysis()
    dirty["indicators_of_compromise"] = [
        {"value": "999.1.1.1", "type": "ip", "context": "", "evidence_quote": "", "verified_in_source": True},
        {"value": "xyz", "type": "hash", "context": "", "evidence_quote": "", "verified_in_source": True},
        {"value": "hxxp://evil[.]example.com/x", "type": "url", "context": "", "evidence_quote": "", "verified_in_source": True},
        {"value": "not-an-email", "type": "email", "context": "", "evidence_quote": "", "verified_in_source": True},
    ]
    bundle, warnings, counts = build_bundle(make_response(dirty))
    assert counts.get("indicator", 0) == 0
    assert len([w for w in warnings if "malformed" in w]) == 4


def test_unsupported_ioc_types_skipped() -> None:
    dirty = canned_analysis()
    dirty["indicators_of_compromise"] = [
        {"value": "Global\\MyMutex", "type": "mutex", "context": "", "evidence_quote": "", "verified_in_source": True},
    ]
    bundle, warnings, counts = build_bundle(make_response(dirty))
    assert counts.get("indicator", 0) == 0
    assert any("no STIX 2.1 mapping" in w for w in warnings)


def test_unverified_ioc_becomes_low_confidence_lead() -> None:
    dirty = canned_analysis()
    for item in dirty["indicators_of_compromise"]:
        item["verified_in_source"] = False
    bundle, warnings, _ = build_bundle(make_response(dirty))
    leads = by_type(bundle, "indicator")
    assert len(leads) == 2
    for lead in leads:
        assert lead["confidence"] == 20
        assert "unverified" in lead["labels"]
        assert "UNVERIFIED" in lead["description"]


def test_unverified_cve_skipped() -> None:
    dirty = canned_analysis()
    dirty["cves"][0]["verified_in_source"] = False
    bundle, warnings, counts = build_bundle(make_response(dirty))
    assert counts.get("vulnerability", 0) == 0
    assert any("CVE-2026-44107" in w for w in warnings)


def test_missing_evidence_tolerated() -> None:
    dirty = canned_analysis()
    dirty["indicators_of_compromise"][0]["evidence_quote"] = ""
    dirty["attack_techniques"][0]["evidence_quote"] = ""
    bundle, _, counts = build_bundle(mark_all_verified(make_response(dirty)))
    assert counts["indicator"] == 2
    assert counts["attack-pattern"] == 2
    assert "Evidence (report excerpt)" not in by_type(bundle, "indicator")[0]["description"]


def test_report_links_everything() -> None:
    bundle, _, _ = build_bundle(mark_all_verified(make_response()))
    report = by_type(bundle, "report")[0]
    assert report["labels"] == ["threat-report"]
    assert set(report["object_refs"]) == {o["id"] for o in bundle["objects"] if o["type"] != "report"}
    assert by_type(bundle, "identity")[0]["id"] in report["object_refs"]
    assert "Blue Mesa" in report["description"]


def test_truncation_noted_in_report() -> None:
    bundle, _, _ = build_bundle(
        mark_all_verified(make_response(char_count=99999, truncated=True))
    )
    assert "analysis window" in by_type(bundle, "report")[0]["description"]


def test_empty_analysis_still_valid() -> None:
    empty = {
        "executive_summary": "Nothing found.",
        "attack_techniques": [],
        "indicators_of_compromise": [],
        "cves": [],
        "affected_systems": [],
        "recommendations": [],
        "supporting_evidence": [],
    }
    bundle, warnings, counts = build_bundle(make_response(empty))
    assert counts == {"identity": 1, "report": 1}
    stix2.parse(json.dumps(bundle))
    assert by_type(bundle, "report")[0]["object_refs"] == [
        by_type(bundle, "identity")[0]["id"]
    ]


def test_export_route(client: TestClient) -> None:
    payload = mark_all_verified(make_response()).model_dump(mode="json")
    resp = client.post("/api/export/stix", headers=csrf_headers(client), json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["filename"].endswith(".stix.json")
    assert body["media_type"] == "application/json"
    assert body["object_counts"]["indicator"] == 2
    parsed = stix2.parse(json.dumps(body["bundle"]))
    assert parsed.type == "bundle"


def test_export_route_rejects_invalid_body(client: TestClient) -> None:
    resp = client.post("/api/export/stix", headers=csrf_headers(client), json={"analysis": {"executive_summary": 42}})
    assert resp.status_code == 422
