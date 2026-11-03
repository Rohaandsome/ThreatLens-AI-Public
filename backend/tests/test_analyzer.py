"""Unit tests for the model analyzer with a faked SDK client (no network I/O)."""

import json

import pytest

from app.config import settings
from app.errors import AnalysisError
from app.services import analyzer
from tests.conftest import (
    canned_analysis,
    canned_json,
    fake_client,
    fake_completion,
    sdk_error,
)


def test_build_response_format_is_json_schema() -> None:
    fmt = analyzer.build_response_format()
    assert fmt["type"] == "json_schema"
    schema = fmt["json_schema"]["schema"]
    for key in (
        "executive_summary",
        "attack_techniques",
        "indicators_of_compromise",
        "cves",
        "affected_systems",
        "recommendations",
        "supporting_evidence",
    ):
        assert key in schema["properties"], key
        assert key in schema["required"], key


def test_response_format_schema_is_tight() -> None:
    """Every object level forbids undeclared properties (strict-schema friendly)."""

    def walk(node: object) -> None:
        assert isinstance(node, dict)
        if node.get("type") == "object":
            assert node.get("additionalProperties") is False
        for value in node.values():
            if isinstance(value, dict):
                walk(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        walk(item)

    walk(analyzer.build_response_format()["json_schema"]["schema"])


def test_strip_code_fences() -> None:
    assert analyzer.strip_code_fences('```json\n{"a": 1}\n```') == '{"a": 1}'
    assert analyzer.strip_code_fences('{"a": 1}') == '{"a": 1}'


def test_verify_item_against_source() -> None:
    source = "beacon to 192.0.2.44 and turbine-updates.example.com over https"
    assert analyzer.verify_item_against_source("192.0.2.44", source) is True
    assert analyzer.verify_item_against_source("TURBINE-UPDATES.EXAMPLE.COM", source) is True
    assert analyzer.verify_item_against_source("10.9.9.9", source) is False
    # Defanged variants count as present.
    assert analyzer.verify_item_against_source("192.0.2.44", "beacon to 192[.]0[.]2[.]44") is True
    assert (
        analyzer.verify_item_against_source(
            "http://evil.example.com", "see hxxp://evil[.]example[.]com/x"
        )
        is True
    )


def test_user_prompt_marks_report_untrusted(fixture_text: str) -> None:
    prompt = analyzer.build_user_prompt(fixture_text, "synthetic_ics_report.txt", False)
    assert "untrusted data" in prompt.lower()
    assert "GRIDGUARD-2026-013" in prompt


def test_analyze_success_marks_verified(api_key: str, fixture_text: str) -> None:
    client, completions = fake_client(fake_completion(canned_json()))
    result, model, warnings = analyzer.analyze_report_text(
        fixture_text, "synthetic_ics_report.txt", settings, client=client
    )
    assert model == "muse-spark-1.3"
    assert "Blue Mesa" in result.executive_summary
    assert all(i.verified_in_source for i in result.indicators_of_compromise)
    assert all(c.verified_in_source for c in result.cves)
    assert warnings == []
    # SDK called with the documented model and structured output.
    assert completions.calls[0]["model"] == "muse-spark-1.3"
    assert completions.calls[0]["response_format"]["type"] == "json_schema"


def test_analyze_flags_unverifiable_iocs(api_key: str, fixture_text: str) -> None:
    dirty = canned_analysis(
        extra_iocs=[
            {
                "value": "10.9.9.9",
                "type": "ip",
                "context": "not in report",
                "evidence_quote": "",
                "verified_in_source": False,
            }
        ]
    )
    client, _ = fake_client(fake_completion(json.dumps(dirty)))
    result, _, warnings = analyzer.analyze_report_text(
        fixture_text, "synthetic_ics_report.txt", settings, client=client
    )
    by_value = {i.value: i for i in result.indicators_of_compromise}
    assert by_value["10.9.9.9"].verified_in_source is False
    assert by_value["192.0.2.44"].verified_in_source is True
    assert any("10.9.9.9" in w for w in warnings)


def test_analyze_requires_api_key(fixture_text: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "model_api_key", "")
    client, completions = fake_client(fake_completion(canned_json()))
    with pytest.raises(AnalysisError) as exc:
        analyzer.analyze_report_text(fixture_text, "r.txt", settings, client=client)
    assert exc.value.status_code == 503
    assert exc.value.code == "model_api_not_configured"
    assert completions.calls == []  # never touched the (fake) API


def test_analyze_falls_back_to_json_object(api_key: str, fixture_text: str) -> None:
    client, completions = fake_client(
        [sdk_error("bad_request_schema"), fake_completion(canned_json())]
    )
    result, _, _ = analyzer.analyze_report_text(
        fixture_text, "r.txt", settings, client=client
    )
    assert "Blue Mesa" in result.executive_summary
    assert len(completions.calls) == 2
    assert completions.calls[1]["response_format"] == {"type": "json_object"}


@pytest.mark.parametrize(
    ("kind", "status", "code"),
    [
        ("rate_limit", 429, "rate_limited"),
        ("auth", 503, "model_api_auth_failed"),
        ("timeout", 504, "model_api_timeout"),
        ("connection", 502, "model_api_unreachable"),
        ("server", 502, "model_api_error"),
        ("bad_request_other", 502, "model_api_error"),
    ],
)
def test_analyze_maps_sdk_errors(
    api_key: str, fixture_text: str, kind: str, status: int, code: str
) -> None:
    client, _ = fake_client(sdk_error(kind))
    with pytest.raises(AnalysisError) as exc:
        analyzer.analyze_report_text(fixture_text, "r.txt", settings, client=client)
    assert exc.value.status_code == status
    assert exc.value.code == code


def test_analyze_rate_limit_keeps_retry_after(api_key: str, fixture_text: str) -> None:
    client, _ = fake_client(sdk_error("rate_limit"))
    with pytest.raises(AnalysisError) as exc:
        analyzer.analyze_report_text(fixture_text, "r.txt", settings, client=client)
    assert exc.value.retry_after == "7"


def test_analyze_rejects_malformed_json(api_key: str, fixture_text: str) -> None:
    client, _ = fake_client(fake_completion("this is not json"))
    with pytest.raises(AnalysisError) as exc:
        analyzer.analyze_report_text(fixture_text, "r.txt", settings, client=client)
    assert exc.value.status_code == 502
    assert exc.value.code == "model_output_malformed"


def test_analyze_rejects_wrong_shape(api_key: str, fixture_text: str) -> None:
    client, _ = fake_client(fake_completion('{"executive_summary": 42}'))
    with pytest.raises(AnalysisError) as exc:
        analyzer.analyze_report_text(fixture_text, "r.txt", settings, client=client)
    assert exc.value.code == "model_output_invalid"


def test_analyze_rejects_empty_output(api_key: str, fixture_text: str) -> None:
    client, _ = fake_client(fake_completion("   "))
    with pytest.raises(AnalysisError) as exc:
        analyzer.analyze_report_text(fixture_text, "r.txt", settings, client=client)
    assert exc.value.code == "model_output_empty"


def test_analyze_truncation_gets_own_error(api_key: str, fixture_text: str) -> None:
    """Regression test: finish_reason=length + cut JSON must report truncation.

    Mirrors the live muse-spark-1.3 failure where a 4000-token budget (with
    ~3071 hidden reasoning tokens) cut the JSON mid-string.
    """
    cut_json = canned_json()[:350]  # ends mid-string, like the live response
    assert cut_json.endswith("malicious outage-sch")
    client, _ = fake_client(fake_completion(cut_json, finish_reason="length"))
    with pytest.raises(AnalysisError) as exc:
        analyzer.analyze_report_text(fixture_text, "r.txt", settings, client=client)
    assert exc.value.status_code == 502
    assert exc.value.code == "model_output_truncated"
    assert "cut off" in exc.value.message


def test_analyze_truncation_flag_with_valid_output_warns(
    api_key: str, fixture_text: str
) -> None:
    client, _ = fake_client(fake_completion(canned_json(), finish_reason="length"))
    _, _, warnings = analyzer.analyze_report_text(
        fixture_text, "r.txt", settings, client=client
    )
    assert any("token limit" in w for w in warnings)


def test_model_max_tokens_default_covers_reasoning() -> None:
    from app.config import Settings

    assert Settings.model_fields["model_max_tokens"].default == 16000


def test_analyze_passes_token_budget_to_sdk(api_key: str, fixture_text: str) -> None:
    client, completions = fake_client(fake_completion(canned_json()))
    analyzer.analyze_report_text(fixture_text, "r.txt", settings, client=client)
    assert completions.calls[0]["max_tokens"] == settings.model_max_tokens


def test_openai_sdk_client_construction(api_key: str) -> None:
    """Verify the installed SDK accepts our base URL / key wiring (no I/O)."""
    import openai

    client = analyzer.build_client(settings)
    assert isinstance(client, openai.OpenAI)
    assert str(client.base_url).rstrip("/") == "https://api.meta.ai/v1"
