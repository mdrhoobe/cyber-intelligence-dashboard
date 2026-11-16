"""Source availability ledger for reproducible target-analysis reports."""

from datetime import datetime, timezone


SOURCE_SPEC = (
    ("ip_info", "IP geolocation", "ip-api.com"),
    ("dns", "DNS records", "System resolver / dnspython"),
    ("ports", "TCP ports", "Local TCP connect scan"),
    ("whois", "WHOIS", "Public WHOIS service"),
    ("headers", "HTTP headers", "Target HTTP endpoint"),
    ("domain_info", "Domain HTTP check", "Target HTTP endpoints"),
    ("ssl", "TLS certificate", "Target TCP/443"),
    ("tech", "Technology hints", "Target HTTP response"),
)


def _status(key, value, is_ip):
    if is_ip and key in {"dns", "whois", "domain_info", "ssl", "tech"}:
        return "not_applicable"
    if value is None:
        return "unavailable"
    if isinstance(value, dict):
        if value.get("error") or value.get("status") in ("fail", "error"):
            return "unavailable"
        if key == "dns" and not value.get("has_any", False):
            return "no_data"
        if key == "domain_info" and not value.get("reachable", False):
            return "no_data"
        if key == "whois" and not any(v for k, v in value.items() if k not in ("domain", "error")):
            return "no_data"
        if key == "tech" and not value:
            return "no_data"
    return "observed"


def build_evidence_ledger(result, checked_at_utc=None):
    """Describe collected or unavailable sources without inferring safety."""
    checked = checked_at_utc or datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    rows = []
    counts = {name: 0 for name in (
        "observed", "no_data", "unavailable", "not_applicable"
    )}
    for key, label, source in SOURCE_SPEC:
        state = _status(key, result.get(key), bool(result.get("is_ip")))
        counts[state] += 1
        rows.append({
            "module": key,
            "label": label,
            "source": source,
            "status": state,
            "checked_at_utc": checked,
        })
    return {
        "checked_at_utc": checked,
        "rows": rows,
        "counts": counts,
        "method": "Source status is descriptive, not an indicator of risk",
    }
