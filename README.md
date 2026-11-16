# Cyber Intelligence Dashboard

A Flask application for learning practical OSINT and network security assessment. I built it to connect small investigation utilities to one reporting interface and to understand the reliability problems that occur when different sources disagree or fail.

This is an **educational prototype**, not a penetration-testing service, identity verification system, or validated threat classifier.

## Main components

- Domain and IP reconnaissance: DNS, WHOIS, HTTP response, TLS certificate inspection and technology hints
- Network inspection: a small TCP port list and HTTP security-header presence checks
- Public-source investigation: username checks, public search references and optional reputation services
- Local reports: SQLite history, statistics, PDF export and an interactive network map
- Flask REST API: selected tools available through authenticated JSON endpoints
- Scheduled scans: interval jobs stored in SQLite

The phone module can show country-level numbering information and public search references. **It cannot locate a phone or verify the identity of its owner.** Some integrations require credentials, may be rate-limited, or may be unavailable without them.

## Environment and installation

Python 3.11 or later is recommended. Create and activate a virtual environment, then run:

```bash
python -m pip install -r requirements.txt
```

Configure the application password, API key and (optionally) a stable Flask session secret through environment variables. Do not paste real secrets into source code or commit a populated `.env` file.

PowerShell example (replace each value with your own long random secret):

```powershell
$env:CID_PASSWORD = "replace-with-a-unique-password"
$env:CID_API_KEY = "replace-with-a-long-random-api-key"
$env:CID_SECRET_KEY = "replace-with-a-long-random-session-secret"
python app.py
```

Open http://127.0.0.1:5000. The dashboard listens on localhost by default; running it on an internet-facing host requires a separate deployment security review.

API requests use the `X-API-Key` header. Keys in URL query parameters are not supported.

For providers requiring credentials, supported optional environment variables include `ABUSEIPDB_KEY`, `VIRUSTOTAL_KEY`, `OTX_KEY`, `HIBP_API_KEY` and `ANTHROPIC_API_KEY`. Phone summaries use deterministic heuristics by default. To opt in to external text assistance, explicitly set CID_ALLOW_EXTERNAL_AI=1 plus ANTHROPIC_API_KEY and ANTHROPIC_MODEL. Only aggregate counts are sent; phone numbers, names and email addresses are not included. External text does not control risk or evidence-coverage scores. Such summaries are **not independently verified**.

## Run tests

```bash
python -m pip install -r requirements-dev.txt
python -m compileall -q app.py db.py pdf_gen.py phone_osint.py scheduler.py threat.py target_validation.py
python -m pytest -q
```

Tests in this repository focus on deterministic offline validation. Passing these checks does not establish that all external OSINT providers are reachable or accurate.

## How results should be interpreted

- An HTTP 200 status is not proof a username belongs to someone; many sites return success pages for missing accounts.
- Open or closed TCP ports represent a point-in-time observation, not a complete vulnerability assessment.
- Header grades are simple presence-based heuristics. Missing a header alone does not establish exploitation risk.
- Reputation scores are exploratory rules combining third-party indicators, **not measured probabilities**.
- A failed or unavailable provider must not be interpreted as a clean result.
- Phone numbers indicate numbering geography at best; map locations are approximate country centroids, never device positions.
- External requests and DNS responses can change between runs. Targets must be authorized and publicly routable.

## Responsible use

Only investigate domains, IPs and accounts you own or have permission to assess. The application blocks common private and loopback network targets, but DNS rebinding and unusual environments remain possible; do not expose it to untrusted users. Store reports locally and avoid collecting or publishing third-party personal information without a legitimate basis.

## Current limitations and next work

The project still needs broader integration tests, rate limits, clearer separation of server and UI modules, improved source provenance, and an experimental evaluation of false-positive/false-negative rates. A future study could compare provider disagreements and reproduce findings against a curated set of authorized test targets.

## Project structure

```text
app.py                 Flask routes and scan orchestration
db.py                  SQLite report storage
phone_osint.py         Phone metadata and optional public-source collection
threat.py              External reputation-source adapters
scheduler.py           Scheduled jobs
pdf_gen.py             PDF rendering
target_validation.py   Public-target filter
templates/             Jinja HTML pages
static/                CSS and client JavaScript
tests/                 Offline regression checks
```

Built and maintained as a cybersecurity learning and portfolio project by Mohammed Salih.

For evaluation design, assumptions, and provider-failure interpretation, see [METHODOLOGY.md](METHODOLOGY.md).
