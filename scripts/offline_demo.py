"""Reproduce a synthetic exposure assessment without external network access.

Run from the repository root: python -m scripts.offline_demo
"""

import argparse
import json
from pathlib import Path

from app import calculate_threat_score
from evidence_ledger import build_evidence_ledger


DEFAULT_FIXTURE = Path(__file__).resolve().parents[1] / "examples" / "fixtures" / "target_analysis_synthetic.json"


def render_demo(fixture):
    if fixture.get("dataset") != "synthetic-educational-fixture-v1":
        raise ValueError("Only the explicitly synthetic demo fixture is supported")
    result = fixture["result"]
    return {
        "dataset": fixture["dataset"],
        "synthetic": True,
        "notice": "Fictional observations for demonstration; no target was scanned.",
        "target": result["target"],
        "assessment": calculate_threat_score(result),
        "evidence": build_evidence_ledger(result, fixture["checked_at_utc"]),
    }


def main():
    parser = argparse.ArgumentParser(description="Reproduce a synthetic OSINT assessment.")
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args()
    with args.fixture.open(encoding="utf-8") as file:
        fixture = json.load(file)
    print(json.dumps(render_demo(fixture), ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
