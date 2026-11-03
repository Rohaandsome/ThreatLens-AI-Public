# Fallback demo artifacts (canned synthetic data — NOT Meta AI output)

Pre-generated offline backup for the ThreatLens AI hackathon demo. Use these
files **only if live analysis fails** during the presentation (network outage,
invalid key, rate limit). When you show them, say exactly this:

> "Live analysis is unavailable right now, so here is a pre-generated
> fallback built from synthetic canned data — not Meta AI output."

## Provenance

- Source: `demo/synthetic_ics_report.txt` (exact copy of the fictional
  `backend/tests/fixtures/synthetic_ics_report.txt`; TEST-NET IPs and
  example.com domains only — no real incident, no confidential data).
- Analysis content: the canned fixture in `backend/tests/conftest.py`, with
  the same verbatim source-verification the live path applies.
- Built with the app's own export code (`stix_export`, `sharing`,
  `pdf_report`, `misp_export`) on 2026-11-02. The MISP preview was computed
  locally — no MISP server was contacted.
- The `model` field reads `canned-synthetic-fallback (NOT Meta AI output)`
  and flows into the PDF title block and package metadata, so the files
  label themselves.

## Files

| File | Equivalent live action |
| --- | --- |
| `canned-analysis.json` | `POST /api/analyze` response body |
| `threatlens-fallback.stix.json` | **STIX 2.1 JSON** button (13 objects) |
| `threatlens-fallback-package.json` | Share **PACKAGE JSON** (TLP:AMBER → TLP:AMBER, 1 redaction) |
| `threatlens-fallback-report.pdf` | Share **PDF REPORT** (TLP banner, every page) |
| `threatlens-fallback-package.stix.json` | Share **STIX BUNDLE** (TLP-marked, 15 objects) |
| `misp-preview.json` | MISP **PREVIEW EVENT**, distribution 0 (11 attributes) |

## Rules

1. Never present these as live Meta Muse Spark output.
2. Never upload a real or confidential report as a substitute input.
3. Never configure a real MISP endpoint or click Create/Publish against one.
4. Regenerate with `THREATLENS_AUDIT_LOG=/tmp/x.log ../.venv/bin/python
   /tmp/gen_fallback.py` from `backend/` if the fixtures change (the audit
   override keeps generation out of the live audit log).
