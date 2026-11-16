"""Threat-data provider error handling without real HTTP requests."""

import threat


def test_all_providers_unavailable_are_not_clean(monkeypatch):
    unavailable = lambda *args, **kwargs: {"available": False, "reason": "offline"}
    for provider in (
        "check_abuseipdb", "check_otx", "check_virustotal", "check_shodan"
    ):
        monkeypatch.setattr(threat, provider, unavailable)
    report = threat.full_threat_report("8.8.8.8")
    assert report["summary"]["level"] == "Insufficient Data"
    assert report["summary"]["risk_score"] == 0
    assert not report["summary"]["flags"]


def test_positive_indicator_produces_observation(monkeypatch):
    monkeypatch.setattr(threat, "check_abuseipdb", lambda _: {
        "available": True, "abuse_score": 80, "total_reports": 4,
    })
    monkeypatch.setattr(threat, "check_otx", lambda *a: {"available": False})
    monkeypatch.setattr(threat, "check_virustotal", lambda *a: {"available": False})
    monkeypatch.setattr(threat, "check_shodan", lambda _: {"available": False})
    report = threat.full_threat_report("8.8.8.8")
    assert report["summary"]["risk_score"] == 40
    assert len(report["summary"]["flags"]) == 1
