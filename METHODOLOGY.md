# Methodology and evaluation notes

## Research question

How reliably can a lightweight security dashboard aggregate open-source indicators while separating actual observations from missing data and uncertain inferences?

This is a learning prototype, not an independently validated scanner, compromise predictor, or identity attribution system.

## Sources and methods

- DNS: A, AAAA, MX, NS, TXT, CNAME, SOA and CAA using a recursive resolver
- Web: HTTP responses, selected headers, TLS certificates and technology hints
- Active observation: TCP connections to a small fixed port list on authorized public targets
- Reputation: independent third-party indicators, if accessible
- Phone: numbering-plan metadata, unverified public search references and optional providers

## Evidence taxonomy

1. Observed: concrete data returned by a named source
2. No indicator: source available but returned no matching signal
3. Unavailable: source absent, rate-limited, missing credentials or errored
4. Unverified: heuristic finding without independent confirmation

Missing evidence is not a clean result. Current exposure scores are hand-chosen explanatory weights, not probabilities or scientifically calibrated ratings.

## Reproducibility

Use Python 3.11 or later. Install requirements-dev.txt and run: python -m pytest -q.
Tests use synthetic targets and mocked responses; no real external scans are required.
They check rejected private addresses, authentication, CSRF, PDF rendering, provider failures, and agreement between HTML and API assessment.

## Current limitations

- False positives from username searches and heuristic detection
- Changes in DNS, regional provider coverage, and rate-limits
- IPv4 TCP scanning with a narrow fixed port list
- DNS rebinding and other network-layer risks are not eliminated
- No curated ground-truth dataset for precision, recall or false-positive rates

## Next evaluation

Use authorized test domains with known configurations. Keep timestamps and sanitized fixtures, label ground truth, compare agreement among providers, and report precision and recall separately from uptime and latency. Do not publish real private reports or identifying personal data.
