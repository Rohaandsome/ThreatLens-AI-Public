"""Tests for Phase 2 package exports: PDF reports and marked STIX (no network)."""

import copy
from typing import Any

import pymupdf
import pytest
from fastapi.testclient import TestClient

from app.schemas import SharePrepareRequest, SharePrepareResponse
from app.services import sharing
from app.services.pdf_report import build_pdf
from tests.conftest import canned_analysis, csrf_headers
from tests.test_sharing import share_payload
from tests.test_stix import make_response


@pytest.fixture(autouse=True)
def isolated_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATLENS_AUDIT_LOG", str(tmp_path / "audit.log"))
    return tmp_path / "audit.log"


def prepare(**overrides: Any) -> SharePrepareResponse:
    return sharing.build_package(SharePrepareRequest.model_validate(share_payload(**overrides)), "operator")


def Norm(text: str) -> str:
    return " ".join(text.replace("​", "").split())


def pdf_pages(data: bytes) -> list[str]:
    with pymupdf.open(stream=data, filetype="pdf") as doc:
        return [page.get_text() for page in doc]


def test_pdf_is_valid() -> None:
    data = build_pdf(prepare(), analyst="analyst-1")
    assert data.startswith(b"%PDF")
    assert len(pdf_pages(data)) >= 1


def test_pdf_tlp_on_every_page_all_markings() -> None:
    base = prepare()
    for marking in ("TLP:RED", "TLP:AMBER+STRICT", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR"):
        pkg = base.model_copy(
            update={
                "classification": base.classification.model_copy(
                    update={"proposed": marking}
                )
            }
        )
        for i, text in enumerate(pdf_pages(build_pdf(pkg))):
            assert marking in text, f"{marking} missing on page {i}"


def test_pdf_multipage_keeps_marking() -> None:
    d = canned_analysis()
    template = d["indicators_of_compromise"][0]
    d["indicators_of_compromise"] = [
        {**template, "value": f"192.0.2.{i}", "verified_in_source": True}
        for i in range(1, 61)
    ]
    payload = share_payload()
    payload["analysis"] = make_response(d).model_dump(mode="json")
    payload["selection"]["iocs"] = [f"192.0.2.{i}" for i in range(1, 61)]
    pkg = sharing.build_package(SharePrepareRequest.model_validate(payload), "operator")
    pages = pdf_pages(build_pdf(pkg))
    assert len(pages) >= 2
    for i, text in enumerate(pages):
        assert "TLP:AMBER" in text, f"marking missing on page {i}"


def test_pdf_sections_present() -> None:
    text = Norm(" ".join(pdf_pages(build_pdf(prepare()))))
    for heading in (
        "Executive Summary",
        "Attack Techniques",
        "Indicators of Compromise",
        "Vulnerabilities",
        "Affected Systems",
        "Recommendations",
        "Supporting Evidence",
        "Analyst Notes",
        "Sharing Record",
    ):
        assert heading in text, heading


def test_pdf_metadata_and_disclosure() -> None:
    pkg = prepare()
    text = Norm(" ".join(pdf_pages(build_pdf(pkg, analyst="analyst-1"))))
    assert f"TL-{pkg.package_id[:8].upper()}" in text
    assert "synthetic_ics_report.txt" in text
    assert "muse-spark-1.3" in text
    assert "analyst-1" in text
    assert "AI-assisted analysis disclosure" in text
    assert "not proof" in text  # confidence is not proof of maliciousness


def test_pdf_only_approved_content() -> None:
    payload = share_payload()
    payload["selection"]["iocs"] = ["192.0.2.44"]
    pkg = sharing.build_package(SharePrepareRequest.model_validate(payload), "operator")
    text = Norm(" ".join(pdf_pages(build_pdf(pkg))))
    assert "192.0.2.44" in text
    assert "198.51.100.23" not in text


def test_pdf_redactions_applied() -> None:
    payload = share_payload(
        redactions=[{"match": "Blue Mesa", "replacement": "[SITE]"}]
    )
    pkg = sharing.build_package(SharePrepareRequest.model_validate(payload), "operator")
    text = Norm(" ".join(pdf_pages(build_pdf(pkg))))
    assert "Blue Mesa" not in text
    assert "[SITE]" in text


def test_pdf_marks_unverified_leads() -> None:
    text = Norm(" ".join(pdf_pages(build_pdf(prepare()))))
    assert "UNVERIFIED" in text  # canned fixtures are unverified by default


def test_pdf_empty_sections_and_notes() -> None:
    payload = share_payload(
        selection={
            "include_summary": True,
            "techniques": [],
            "iocs": [],
            "cves": [],
            "systems": [],
            "recommendations": [],
            "evidence": [],
        },
        analyst_notes="Release to the ISAC on Friday.",
    )
    pkg = sharing.build_package(SharePrepareRequest.model_validate(payload), "operator")
    text = Norm(" ".join(pdf_pages(build_pdf(pkg))))
    assert "None selected for sharing." in text
    assert "Release to the ISAC on Friday." in text


def test_pdf_rejects_invalid_marking() -> None:
    from app.errors import AnalysisError

    base = prepare()
    bad = base.model_copy(
        update={
            "classification": base.classification.model_copy(
                update={"proposed": "TLP:BLUE"}
            )
        }
    )
    with pytest.raises(AnalysisError) as exc:
        build_pdf(bad)
    assert exc.value.code == "invalid_tlp"


def test_share_pdf_route(client: TestClient, isolated_audit) -> None:
    pkg = prepare()
    resp = client.post(
        "/api/share/pdf",
        headers=csrf_headers(client),
        json={"package": pkg.model_dump(mode="json"), "analyst": "analyst-1"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.headers["content-disposition"].endswith('.pdf"')
    assert resp.content.startswith(b"%PDF")
    import json as _json

    events = [_json.loads(line) for line in isolated_audit.read_text().splitlines()]
    exported = [e for e in events if e["event"] == "exported"]
    assert len(exported) == 1
    assert exported[0]["format"] == "pdf"
    assert exported[0]["package_id"] == pkg.package_id


def test_share_pdf_route_rejects_bad_marking(client: TestClient) -> None:
    pkg = prepare()
    dumped = pkg.model_dump(mode="json")
    dumped["classification"]["proposed"] = "BOGUS"
    resp = client.post(
        "/api/share/pdf",
        headers=csrf_headers(client),
        json={"package": dumped},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "invalid_tlp"


def _by_type(bundle: dict, stix_type: str) -> list[dict]:
    return [o for o in bundle["objects"] if o["type"] == stix_type]


def test_package_stix_marking_refs() -> None:
    import stix2
    from app.services.stix_export import build_package_bundle

    bundle, warnings, counts = build_package_bundle(prepare())
    markings = _by_type(bundle, "marking-definition")
    assert len(markings) == 1
    assert markings[0]["id"] == stix2.TLP_AMBER.id
    assert markings[0]["definition"] == {"tlp": "amber"}
    for obj in bundle["objects"]:
        if obj["type"] in ("marking-definition", "identity"):
            continue
        assert obj.get("object_marking_refs") == [markings[0]["id"]], obj["type"]
    report = _by_type(bundle, "report")[0]
    assert "TLP:AMBER" in report["labels"]
    assert counts["marking-definition"] == 1
    stix2.parse(__import__("json").dumps(bundle))


def test_package_stix_clear_maps_to_white() -> None:
    import stix2
    from app.services.stix_export import build_package_bundle

    base = prepare()
    pkg = base.model_copy(
        update={
            "classification": base.classification.model_copy(
                update={"proposed": "TLP:CLEAR"}
            )
        }
    )
    bundle, warnings, _ = build_package_bundle(pkg)
    markings = _by_type(bundle, "marking-definition")
    assert markings[0]["id"] == stix2.TLP_WHITE.id
    assert any("WHITE" in w for w in warnings)
    assert "TLP:CLEAR" in _by_type(bundle, "report")[0]["labels"]


def test_package_stix_amber_strict_statement() -> None:
    from app.services.stix_export import build_package_bundle

    base = prepare()
    pkg = base.model_copy(
        update={
            "classification": base.classification.model_copy(
                update={"proposed": "TLP:AMBER+STRICT"}
            )
        }
    )
    bundle, warnings, _ = build_package_bundle(pkg)
    markings = _by_type(bundle, "marking-definition")
    assert markings[0]["definition_type"] == "statement"
    assert "AMBER+STRICT" in str(markings[0]["definition"])
    assert any("statement marking" in w for w in warnings)


def test_package_stix_uses_redacted_content() -> None:
    from app.services.stix_export import build_package_bundle

    payload = share_payload(
        redactions=[{"match": "Blue Mesa", "replacement": "[SITE]"}]
    )
    pkg = sharing.build_package(SharePrepareRequest.model_validate(payload), "operator")
    bundle, _, _ = build_package_bundle(pkg)
    indicator = _by_type(bundle, "indicator")[0]
    assert "[SITE]" in indicator["description"] or "[SITE]" in str(bundle)
    assert "Blue Mesa" not in __import__("json").dumps(bundle)


def test_package_stix_analyst_notes() -> None:
    from app.services.stix_export import build_package_bundle

    payload = share_payload(analyst_notes="Call the duty officer first.")
    pkg = sharing.build_package(SharePrepareRequest.model_validate(payload), "operator")
    bundle, _, counts = build_package_bundle(pkg)
    notes = _by_type(bundle, "note")
    assert len(notes) == 1
    assert notes[0]["content"] == "Call the duty officer first."
    report = _by_type(bundle, "report")[0]
    assert notes[0]["id"] in report["object_refs"]
    assert counts["note"] == 1

    bundle2, _, counts2 = build_package_bundle(prepare())
    assert counts2.get("note", 0) == 0


def test_package_stix_rejects_bad_marking() -> None:
    from app.errors import AnalysisError
    from app.services.stix_export import build_package_bundle

    base = prepare()
    bad = base.model_copy(
        update={
            "classification": base.classification.model_copy(
                update={"proposed": "BOGUS"}
            )
        }
    )
    with pytest.raises(AnalysisError) as exc:
        build_package_bundle(bad)
    assert exc.value.code == "invalid_tlp"


def test_share_stix_route(client: TestClient, isolated_audit) -> None:
    pkg = prepare()
    resp = client.post(
        "/api/share/stix",
        headers=csrf_headers(client),
        json={"package": pkg.model_dump(mode="json"), "analyst": "analyst-1"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["filename"].endswith(".stix.json")
    assert body["object_counts"]["marking-definition"] == 1
    import json as _json

    events = [_json.loads(line) for line in isolated_audit.read_text().splitlines()]
    exported = [e for e in events if e["event"] == "exported"]
    assert len(exported) == 1
    assert exported[0]["format"] == "stix"
    assert exported[0]["package_id"] == pkg.package_id
