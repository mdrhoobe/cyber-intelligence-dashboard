"""Ensure untrusted report text cannot break PDF generation."""

from pdf_gen import generate_pdf


def test_pdf_accepts_special_characters_in_target():
    report = {
        "id": 99, "type": "domain",
        "target": "fake.invalid <b>&</b> ' quote",
        "timestamp": "2026-11-16 12:00:00",
        "results": {"domain": "fake.invalid", "reachable": False, "server": "<test>"},
        "summary": {},
    }
    assert generate_pdf(report).startswith(b"%PDF")


def test_pdf_accepts_special_characters_in_flags():
    report = {
        "id": 100, "type": "threat", "target": "8.8.8.8",
        "timestamp": "2026-11-16 12:00:00",
        "results": {
            "sources": {},
            "summary": {
                "risk_score": 20, "level": "Medium Risk",
                "flags": ["Observed <script> & a tag"],
            },
        },
        "summary": {},
    }
    assert generate_pdf(report).startswith(b"%PDF")
