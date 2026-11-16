"""Offline checks for private-by-default optional text summarization."""

import json
import phone_osint


SAMPLE = {
    "info": {"valid": True, "formatted": "+218 912345678", "e164": "+218912345678",
             "country_name": "Libya", "carrier": "Example Operator"},
    "names": ["Sensitive Test Name"],
    "emails": ["private@example.invalid"],
    "web_hits": [{"title": "Candidate reference", "url": "https://example.invalid"}],
    "hibp_results": [{"breached": None, "error": "provider unavailable"}],
    "threat_data": [],
}


def test_optional_external_service_disabled_by_default(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "demo-only")
    monkeypatch.setenv("ANTHROPIC_MODEL", "demo-model")
    monkeypatch.delenv("CID_ALLOW_EXTERNAL_AI", raising=False)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("external model should not be contacted")

    monkeypatch.setattr(phone_osint.requests, "post", fail_if_called)
    result = phone_osint.ai_correlate(SAMPLE)
    assert result["method"] == "rules"
    assert result["risk"] == "Unassessed"


def test_opt_in_model_receives_counts_not_identifiers(monkeypatch):
    monkeypatch.setenv("CID_ALLOW_EXTERNAL_AI", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "demo-only")
    monkeypatch.setenv("ANTHROPIC_MODEL", "demo-model")
    recorded = {}

    class Response:
        status_code = 200

        def json(self):
            return {"content": [{"text": json.dumps({
                "summary": "Only limited information is available.",
                "observations": ["A web reference exists."],
                "next_steps": ["Validate the source."],
            })}]}

    def fake_post(url, **kwargs):
        recorded.update(kwargs)
        return Response()

    monkeypatch.setattr(phone_osint.requests, "post", fake_post)
    result = phone_osint.ai_correlate(SAMPLE)
    serialized = json.dumps(recorded.get("json", {}))
    assert "+218912345678" not in serialized
    assert "Sensitive Test Name" not in serialized
    assert "private@example.invalid" not in serialized
    assert result["method"] == "assisted_summary"
    assert result["risk"] == "Unassessed"
    assert result["confidence"] == phone_osint.manual_confidence(SAMPLE)["confidence"]


def test_unavailable_breach_provider_does_not_increase_source_count():
    without = dict(SAMPLE, hibp_results=[])
    a = phone_osint.calculate_confidence(without, {})
    b = phone_osint.calculate_confidence(SAMPLE, {})
    assert a["sources"] == b["sources"]
    assert a["score"] == b["score"]
