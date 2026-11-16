"""Deterministic scoring, API and HTML integration checks with fixtures."""

import os
os.environ.setdefault("CID_PASSWORD", "test-password-for-ci")
os.environ.setdefault("CID_API_KEY", "test-api-key-for-ci")
os.environ.setdefault("CID_SECRET_KEY", "test-session-secret-for-ci")

import app as dashboard


def empty_analysis():
    return {
        "target": "8.8.8.8", "clean": "8.8.8.8", "is_ip": True,
        "ip_info": {"status": "fail", "message": "offline"},
        "dns": None, "ports": {"error": "offline", "ports": [], "open": 0},
        "whois": None, "headers": {"error": "offline", "score": None},
        "domain_info": None, "ssl": {"error": "offline"}, "tech": None,
    }


def test_empty_evidence_is_not_clean():
    summary = dashboard.calculate_threat_score(empty_analysis())
    assert summary["score"] == 0
    assert summary["level"] == "Insufficient Data"
    assert summary["evidence_count"] == 0


def test_available_evidence_is_not_proof_of_safety():
    sample = empty_analysis()
    sample["ip_info"] = {"status": "success", "proxy": False, "hosting": False}
    summary = dashboard.calculate_threat_score(sample)
    assert summary["level"] == "No Indicators Observed"
    assert summary["evidence_count"] == 1
    assert summary["score"] == 0


def test_tls_verification_failure_is_not_cert_expiry():
    sample = empty_analysis()
    sample["ssl"] = {
        "error": "certificate verification failed",
        "expired": False, "verification_error": True,
    }
    summary = dashboard.calculate_threat_score(sample)
    assert summary["score"] == 20
    assert any("verification" in flag["msg"].lower() for flag in summary["flags"])


def test_api_analyze_uses_same_assessment_as_web(monkeypatch):
    calls = []
    monkeypatch.setattr(dashboard, "universal_analyze", lambda _: empty_analysis())
    monkeypatch.setattr(dashboard, "save_report", lambda *args: calls.append(args))
    client = dashboard.app.test_client()
    response = client.post(
        "/api/v1/analyze",
        json={"target": "8.8.8.8"},
        headers={"X-API-Key": "test-api-key-for-ci"},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["data"]["threat"]["level"] == "Insufficient Data"
    assert calls and calls[0][3]["level"] == "Insufficient Data"

    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["_csrf_token"] = "fixed-local-test-csrf-token"
    html = client.post(
        "/analyze",
        data={"target": "8.8.8.8", "csrf_token": "fixed-local-test-csrf-token"},
    )
    assert html.status_code == 200
    assert b"Insufficient Data" in html.data
    assert calls[-1][3]["level"] == "Insufficient Data"


def test_failed_headers_are_not_assigned_a_low_grade(monkeypatch):
    def failure(*args, **kwargs):
        raise ConnectionError("synthetic offline failure")
    monkeypatch.setattr(dashboard.requests, "get", failure)
    result = dashboard.check_headers("https://8.8.8.8")
    assert result["score"] is None
    assert result["grade"] == "N/A"
