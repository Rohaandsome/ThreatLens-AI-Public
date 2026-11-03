"""Route tests for POST /api/analyze with a faked model client (no network I/O)."""

from fastapi.testclient import TestClient

from app.services import analyzer
from tests.conftest import (
    FIXTURE_PATH,
    canned_json,
    consent_headers,
    csrf_headers,
    fake_client,
    fake_completion,
    sdk_error,
)
from tests.test_extraction import make_pdf


def _install_fake(monkeypatch, behavior) -> None:
    client, completions = fake_client(behavior)
    monkeypatch.setattr(analyzer, "build_client", lambda settings: client)
    return completions


def test_analyze_txt_workflow(
    client: TestClient, monkeypatch, api_key: str
) -> None:
    """Full upload-to-analysis workflow for TXT with a mocked model response."""
    completions = _install_fake(monkeypatch, fake_completion(canned_json()))
    with open(FIXTURE_PATH, "rb") as fh:
        resp = client.post(
            "/api/analyze",
            headers=consent_headers(client),
            files={"file": ("synthetic_ics_report.txt", fh, "text/plain")},
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["filename"] == "synthetic_ics_report.txt"
    assert body["file_type"] == "txt"
    assert body["model"] == "muse-spark-1.3"
    assert body["truncated"] is False
    analysis = body["analysis"]
    assert "Blue Mesa" in analysis["executive_summary"]
    assert {i["value"] for i in analysis["indicators_of_compromise"]} >= {
        "192.0.2.44",
        "turbine-updates.example.com",
    }
    assert all(i["verified_in_source"] for i in analysis["indicators_of_compromise"])
    assert completions.calls[0]["model"] == "muse-spark-1.3"


def test_analyze_pdf_workflow(
    client: TestClient, monkeypatch, api_key: str
) -> None:
    completions = _install_fake(monkeypatch, fake_completion(canned_json()))
    pdf = make_pdf(["GRIDGUARD-2026-013", "beacon to 192.0.2.44 and CVE-2026-44107"])
    resp = client.post(
        "/api/analyze",
        headers=consent_headers(client),
        files={"file": ("report.pdf", pdf, "application/pdf")},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["file_type"] == "pdf"
    # turbine-updates.example.com is absent from this PDF, so it must be flagged.
    by_value = {i["value"]: i for i in body["analysis"]["indicators_of_compromise"]}
    assert by_value["192.0.2.44"]["verified_in_source"] is True
    assert by_value["turbine-updates.example.com"]["verified_in_source"] is False
    assert any("turbine-updates.example.com" in w for w in body["warnings"])
    assert completions.calls[0]["model"] == "muse-spark-1.3"


def test_analyze_rejects_oversize(client: TestClient, api_key: str) -> None:
    big = b"x" * (10 * 1024 * 1024 + 1)
    resp = client.post(
        "/api/analyze", headers=consent_headers(client), files={"file": ("big.txt", big, "text/plain")}
    )
    assert resp.status_code == 413
    assert resp.json()["detail"]["code"] == "file_too_large"


def test_analyze_rejects_bad_type(client: TestClient, api_key: str) -> None:
    resp = client.post(
        "/api/analyze", headers=consent_headers(client), files={"file": ("run.exe", b"MZ", "application/octet-stream")}
    )
    assert resp.status_code == 415
    assert resp.json()["detail"]["code"] == "unsupported_file_type"


def test_analyze_rejects_empty(client: TestClient, api_key: str) -> None:
    resp = client.post(
        "/api/analyze", headers=consent_headers(client), files={"file": ("empty.txt", b"", "text/plain")}
    )
    assert resp.status_code == 400


def test_analyze_requires_api_key(client: TestClient, monkeypatch) -> None:
    from app.config import settings

    monkeypatch.setattr(settings, "model_api_key", "")
    completions = _install_fake(monkeypatch, fake_completion(canned_json()))
    with open(FIXTURE_PATH, "rb") as fh:
        resp = client.post(
            "/api/analyze",
            headers=consent_headers(client),
            files={"file": ("synthetic_ics_report.txt", fh, "text/plain")},
        )
    assert resp.status_code == 503
    assert resp.json()["detail"]["code"] == "model_api_not_configured"
    assert completions.calls == []


def test_analyze_rate_limit_passthrough(
    client: TestClient, monkeypatch, api_key: str
) -> None:
    _install_fake(monkeypatch, sdk_error("rate_limit"))
    with open(FIXTURE_PATH, "rb") as fh:
        resp = client.post(
            "/api/analyze",
            headers=consent_headers(client),
            files={"file": ("synthetic_ics_report.txt", fh, "text/plain")},
        )
    assert resp.status_code == 429
    assert resp.json()["detail"]["code"] == "rate_limited"
    assert resp.headers.get("retry-after") == "7"


def test_health_still_ok(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
