"""Reproducible portfolio demonstration using invented fixture data."""

import json
from pathlib import Path

from scripts.offline_demo import render_demo

FIXTURE = (Path(__file__).resolve().parents[1] / "examples" /
           "fixtures" / "target_analysis_synthetic.json")


def test_synthetic_example_is_labeled_and_deterministic():
    with FIXTURE.open(encoding="utf-8") as file:
        data = json.load(file)
    a = render_demo(data)
    b = render_demo(data)
    assert a == b
    assert a["synthetic"] is True
    assert a["evidence"]["checked_at_utc"] == data["checked_at_utc"]
    assert a["assessment"]["score"] == 30
    assert a["assessment"]["level"] == "Medium Risk"
    assert a["evidence"]["counts"]["observed"] == 8
    assert "Telnet" in a["assessment"]["flags"][0]["msg"]


def test_unmarked_fixture_is_refused():
    data = {"result": {}, "dataset": "real-target"}
    try:
        render_demo(data)
    except ValueError:
        pass
    else:
        raise AssertionError("Non-synthetic fixtures must be rejected")
