"""Shared fixtures for ThreatLens AI backend tests.

All model-API interactions are faked in-process: no test in this suite may
perform network I/O. Canned payloads mirror backend/tests/fixtures/ so the
source-verification logic can be exercised deterministically.
"""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.services import authz, ratelimit

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "synthetic_ics_report.txt"

# Strong fake operator secrets for tests (32+ chars, distinct). Never real.
OPERATOR_KEY = "test-operator-key-0123456789abcdef" # gitleaks:allow
ADMIN_KEY = "test-admin-key-0123456789abcdefXY" # gitleaks:allow


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def auth_env(monkeypatch: pytest.MonkeyPatch):
    """Configure operator auth and isolate session/rate state per test."""
    monkeypatch.setattr(settings, "operator_api_key", OPERATOR_KEY)
    monkeypatch.setattr(settings, "admin_api_key", ADMIN_KEY)
    authz.clear_auth_state()
    ratelimit.clear_rate_state()
    yield
    authz.clear_auth_state()
    ratelimit.clear_rate_state()


def login_as(client: TestClient, key: str = OPERATOR_KEY) -> dict[str, str]:
    """Log in (cookie jar keeps the session); returns CSRF headers for POSTs."""
    response = client.post("/api/auth/login", json={"key": key})
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def csrf_headers(client: TestClient, key: str = OPERATOR_KEY) -> dict[str, str]:
    """Log in as needed; returns CSRF headers matching the client's session.

    Memoized on the client object itself (last role wins), so the returned
    token always belongs to the session in the cookie jar. No module-global
    state: conftest is imported twice under pytest (as `conftest` and as
    `tests.conftest`), so globals cannot coordinate fixtures and helpers.
    """
    state = client.__dict__.setdefault("_tl_auth", {})
    if state.get("key") != key or "token" not in state:
        state["key"] = key
        state["token"] = login_as(client, key)["X-CSRF-Token"]
    return {"X-CSRF-Token": state["token"]}


def consent_headers(client: TestClient, key: str = OPERATOR_KEY) -> dict[str, str]:
    """Log in and record AI-processing acknowledgment; returns CSRF headers."""
    headers = csrf_headers(client, key)
    state = client.__dict__.setdefault("_tl_auth", {})
    if state.get("consented") != key:
        response = client.post(
            "/api/auth/consent", json={"acknowledged": True}, headers=headers
        )
        assert response.status_code == 200, response.text
        state["consented"] = key
    return headers


@pytest.fixture()
def fixture_text() -> str:
    return FIXTURE_PATH.read_text(encoding="utf-8")


@pytest.fixture()
def api_key(monkeypatch: pytest.MonkeyPatch) -> str:
    """Pretend a model API key is configured (value is never sent anywhere)."""
    monkeypatch.setattr(settings, "model_api_key", "test-key-not-real")
    return "test-key-not-real"


def canned_analysis(extra_iocs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Canned model output grounded in the synthetic fixture."""
    iocs: list[dict[str, Any]] = [
        {
            "value": "192.0.2.44",
            "type": "ip",
            "context": "Outbound TCP/443 from engineering workstation",
            "evidence_quote": "Outbound connections were observed to 192.0.2.44 over TCP/443",
            "verified_in_source": False,
        },
        {
            "value": "turbine-updates.example.com",
            "type": "domain",
            "context": "DNS query + TLS SNI",
            "evidence_quote": "and to turbine-updates.example.com.",
            "verified_in_source": False,
        },
    ]
    if extra_iocs:
        iocs.extend(extra_iocs)
    return {
        "executive_summary": (
            "Fictional intrusion at Blue Mesa Power Unit 3: a spearphishing "
            "attachment led to credential theft and lateral movement to the "
            "plant historian, with staging to external infrastructure."
        ),
        "attack_techniques": [
            {
                "name": "Spearphishing Attachment",
                "mitre_id": "T1566.002",
                "description": "Operators received a malicious outage-schedule document.",
                "evidence_quote": 'subject "Q4 outage schedule — action required"',
                "inferred": False,
            },
            {
                "name": "Valid Accounts",
                "mitre_id": "T1078",
                "description": "Stolen operator credentials used for lateral movement.",
                "evidence_quote": "credential theft (T1078 — Valid Accounts)",
                "inferred": False,
            },
        ],
        "indicators_of_compromise": iocs,
        "cves": [
            {
                "id": "CVE-2026-44107",
                "description": "Placeholder VPN-appliance flaw mentioned in telemetry discussion.",
                "evidence_quote": "public exploit discussion of CVE-2026-44107",
                "verified_in_source": False,
            }
        ],
        "affected_systems": [
            {
                "system": "BM-ENG-WS04",
                "detail": "Engineering workstation, Unit 3 turbine control",
                "evidence_quote": "unexpected logins to the turbine-control engineering workstation",
                "inferred": False,
            },
            {
                "system": "BM-HIST-01",
                "detail": "Plant data historian",
                "evidence_quote": "lateral movement to the plant historian server",
                "inferred": False,
            },
        ],
        "recommendations": [
            {
                "recommendation": "Isolate BM-ENG-WS04 and reimage from known-good media.",
                "priority": "critical",
                "rationale": "Confirmed foothold host in this fictional scenario.",
            },
            {
                "recommendation": "Force password resets for the two targeted operators.",
                "priority": "high",
                "rationale": "Credentials were stolen via the phishing lure.",
            },
        ],
        "supporting_evidence": [
            {
                "quote": "One operator opened the attachment",
                "relevance": "Confirms initial-access vector.",
            }
        ],
    }


def fake_completion(
    content: str,
    model: str = "muse-spark-1.3",
    finish_reason: str | None = "stop",
) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=content),
                finish_reason=finish_reason,
            )
        ],
        model=model,
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=20, total_tokens=30),
    )


class FakeCompletions:
    """Fake for client.chat.completions with scripted behavior."""

    def __init__(self, behavior: Any) -> None:
        self.behavior = behavior
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if isinstance(self.behavior, Exception):
            raise self.behavior
        if isinstance(self.behavior, list):
            step = self.behavior[min(len(self.calls) - 1, len(self.behavior) - 1)]
            if isinstance(step, Exception):
                raise step
            return step
        return self.behavior


def fake_client(behavior: Any) -> tuple[SimpleNamespace, FakeCompletions]:
    completions = FakeCompletions(behavior)
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    return client, completions


def sdk_error(kind: str) -> Exception:
    """Build real openai-SDK exception instances without network I/O."""
    import openai

    request = httpx.Request("POST", "https://api.meta.ai/v1/chat/completions")
    if kind == "rate_limit":
        response = httpx.Response(
            429, request=request, headers={"retry-after": "7"}, json={"error": "slow down"}
        )
        return openai.RateLimitError("rate limited", response=response, body=None)
    if kind == "auth":
        response = httpx.Response(401, request=request, json={"error": "bad key"})
        return openai.AuthenticationError("bad key", response=response, body=None)
    if kind == "bad_request_schema":
        response = httpx.Response(400, request=request, json={"error": "bad response_format"})
        return openai.BadRequestError(
            "Invalid response_format: schema not supported", response=response, body=None
        )
    if kind == "bad_request_other":
        response = httpx.Response(400, request=request, json={"error": "bad request"})
        return openai.BadRequestError("Bad request", response=response, body=None)
    if kind == "timeout":
        return openai.APITimeoutError(request=request)
    if kind == "connection":
        return openai.APIConnectionError(request=request)
    if kind == "server":
        response = httpx.Response(500, request=request, json={"error": "boom"})
        return openai.InternalServerError("boom", response=response, body=None)
    raise ValueError(f"unknown sdk error kind: {kind}")


def canned_json(**kwargs: Any) -> str:
    return json.dumps(canned_analysis(**kwargs))
