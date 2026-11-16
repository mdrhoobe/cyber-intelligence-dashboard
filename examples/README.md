# Reproducible offline demonstration

This demonstration uses a **synthetic** JSON fixture and does not send network traffic to any target.

From the repository root:

```bash
python -m pip install -r requirements-dev.txt
python -m scripts.offline_demo
python -m pytest -q
```

The script prints the labeled fixture name, a rule-based exposure assessment, and an evidence ledger with a fixed UTC timestamp. The target `demo.example`, the IP address from the RFC 5737 documentation range, the WHOIS registration, and all observations are invented. They must not be represented as real findings.

Use this as a tutorial for explaining how the pipeline combines inputs and treats missing data, not as a proof of detection accuracy. The demonstration verifies reproducibility and data contracts, **not** performance against real infrastructure.
