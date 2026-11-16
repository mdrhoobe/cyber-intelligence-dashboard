"""Offline tests for source provenance and source availability."""

from evidence_ledger import build_evidence_ledger


def sample():
    return {
        "is_ip": False,
        "ip_info": {"status": "fail", "message": "offline"},
        "dns": {"has_any": False, "records": {}, "error": None},
        "ports": {"ports": [], "open": 0, "error": None},
        "whois": {"error": "provider timeout"},
        "headers": {"error": "offline", "score": None},
        "domain_info": {"reachable": False, "error": None},
        "ssl": {"error": "handshake failed"},
        "tech": None,
    }


def test_ledger_records_sources_and_utc_timestamp():
    ledger = build_evidence_ledger(sample(), checked_at_utc="2026-11-16T12:00:00Z")
    assert len(ledger["rows"]) == 8
    assert all(r["checked_at_utc"] == "2026-11-16T12:00:00Z" for r in ledger["rows"])
    assert sum(ledger["counts"].values()) == 8
    assert ledger["counts"]["observed"] == 1
    assert ledger["counts"]["no_data"] == 2
    assert ledger["counts"]["unavailable"] == 5


def test_ip_ledger_does_not_claim_domain_checks_failed():
    result = sample()
    result["is_ip"] = True
    result["ip_info"] = {"status": "success", "query": "8.8.8.8"}
    ledger = build_evidence_ledger(result, checked_at_utc="2026-11-16T12:00:00Z")
    assert ledger["counts"]["not_applicable"] == 5
    assert ledger["counts"]["observed"] == 2
    assert next(row for row in ledger["rows"] if row["module"] == "dns")["status"] == "not_applicable"


def test_unavailable_is_not_promoted_to_observed():
    result = sample()
    result["ports"] = None
    result["headers"] = {"error": "denied", "score": 0}
    ledger = build_evidence_ledger(result)
    assert ledger["counts"]["observed"] == 0
    assert ledger["counts"]["unavailable"] == 6
