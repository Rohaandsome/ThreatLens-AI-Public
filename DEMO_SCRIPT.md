# ThreatLens AI — Hackathon Demo Script

Live walkthrough for the Meta Global AI Developer Hackathon judges. Companion:
[DEMO_CHECKLIST.md](DEMO_CHECKLIST.md) (verification boxes). Total: ~15 minutes
plus 5 minutes of pre-show setup. Everything runs on localhost; no deploy, no
real MISP, no confidential data.

> Honesty rule (read once, follow always): call a result **live Meta output**
> only when the `MUSE-SPARK-1.3 · LIVE AI RESULT` badge from a real
> `POST /api/analyze` call is on screen. Anything from `demo/fallback/` is
> **pre-generated canned backup** — say so out loud before showing it.

## 0. Cast and props (keep off-screen)

- Two terminal windows, one browser window (fresh profile, localhost allowed).
- `OPERATOR_API_KEY` (analyst) and `ADMIN_API_KEY` (administrator) copied from
  `backend/.env` into a password manager — paste, never type on camera.
- Demo input: `demo/synthetic_ics_report.txt` (fictional Blue Mesa Power
  intrusion; TEST-NET IPs, example.com domains).
- Fallback kit (sealed unless live analysis fails): `demo/fallback/`.

## 1. Pre-show setup (~5 min before)

Terminal 1 — backend (no `--reload`: restarts invalidate demo sessions):

```bash
cd /home/kali/projects/threatlens-ai
source .venv/bin/activate
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Expect: `Uvicorn running on http://127.0.0.1:8000`. Verify in a third shell:

```bash
curl http://127.0.0.1:8000/api/health
# {"status":"ok","service":"threatlens-api","version":"0.1.0",...}
```

Terminal 2 — frontend (the `export` line is only needed on machines without a
system Node 20+; this repo carries one under `.tools/`):

```bash
cd /home/kali/projects/threatlens-ai
export PATH="$PWD/.tools/node/bin:$PATH"
cd frontend
npm run dev
```

Expect: `VITE … ready`, `Local: http://localhost:5173/`. Open that URL: the
**OPERATOR LOGIN** gate appears. Do **not** log in until Act 1 (login is part
of the show). Run one analysis now as a sound check, then LOG OUT to reset —
each login mints a fresh session (analyze budget: 10/hour per session).

## 2. Act 1 — Login and consent (~2 min)

**Say:** "ThreatLens is a single-operator console for energy-sector threat
intel. Every protected route needs a session — there is no anonymous access."

**Do:** paste the operator key → **Log in**. Point at role `ANALYST` in the
TopBar. Open **Upload Intel**.

**Say:** "Reports leave this server for Meta's model, so the app discloses
that before the first analysis — and the server blocks analysis until the
operator acknowledges."

**Do:** read the **External AI processing notice** aloud; show the disabled
**Analyze** button tooltip; tick the checkbox → **Acknowledge for this
session** → `ACKNOWLEDGED FOR THIS SESSION — ANALYSIS ENABLED`.

## 3. Act 2 — Live analysis (~3 min)

**Say:** "Our input is a synthetic grid-intrusion report — fictional people,
TEST-NET addresses, nothing real."

**Do:** drag `demo/synthetic_ics_report.txt` into the dropzone (queues as
`ready to analyze`) → **Analyze**. While it runs: "Extraction plus a
`muse-spark-1.3` call — up to about a minute."

**Expect:** `Analysis: synthetic_ics_report.txt` + `MUSE-SPARK-1.3 · LIVE AI
RESULT`. If the error panel appears instead, read its hint, hit **Retry
analysis** once; on a second failure, open the fallback kit and speak the
fallback sentence from `demo/fallback/README.md`.

## 4. Act 3 — Results tour (~3 min)

**Say:** "Every finding carries its provenance — evidence or inference — and
every IOC and CVE is re-checked against the uploaded text."

**Do:** scroll the sections: **EXECUTIVE SUMMARY** → **ATTACK TECHNIQUES**
(MITRE IDs + REPORT EVIDENCE / AI INFERENCE badges) → **INDICATORS OF
COMPROMISE** (SOURCE CHECK column: VERIFIED IN REPORT vs NOT FOUND IN REPORT)
→ CVEs → systems → recommendations → supporting evidence → the
verify-before-acting footer. Click one evidence quote to show it is verbatim.

## 5. Act 4 — Share: classify, approve, export (~4 min)

**Say:** "Sharing is a classified act here, not a download button. Nothing is
assumed CLEAR."

**Do:** **SHARE INTEL** → show `UNCLASSIFIED — REVIEW REQUIRED` → set analyst
classification `TLP:AMBER`, proposed `TLP:AMBER` → deselect one finding → add
redaction `Blue Mesa Power` → `[FICTIONAL UTILITY REDACTED]` → tick approval
→ prepare.

**Expect:** `TLP:AMBER → TLP:AMBER` preview with **PERMITTED AUDIENCE**,
redaction count, and `PREPARED PACKAGE — NOTHING HAS BEEN PUBLISHED.`

**Do:** **STIX 2.1 JSON** (validated bundle download) → **PDF REPORT** (open
it: TLP banner on every page header and footer) → **PACKAGE JSON**.

## 6. Act 5 — MISP preview, zero publishing (~2 min)

**Say:** "MISP export is local-first: the full event preview is computed in
this backend. Nothing contacts a MISP server until an analyst explicitly asks
— and this demo never will."

**Do:** in the MISP section, keep `Your organisation only` → **PREVIEW
EVENT** → show the attribute table, `tlp:amber` tag, `UNPUBLISHED` label.
Show the publish section reading `Requires administrator`.

**Do (role demo):** LOG OUT → log in with the admin key → return to the same
package: the publish gate unlocks. **Stop there — do not create or publish.**
Mention: destinations are server-allowlisted, TLP:RED is org-only, drafts are
born unpublished.

## 7. Act 6 — History and audit (~1 min)

**Do:** **Sharing History** → **Distribution history** tab (DEMONSTRATION DATA
banner, status tabs, filters) → **Audit log** tab: point at the session's own
`ai_consent`, `classification`, `prepared`, `exported` entries — metadata
only, append-only, no edit API.

**Say (known limitation, one line):** "Row action buttons are still disabled
in this UI — the API beneath them already enforces login and roles."

## 8. Close (~30 s)

**Say:** "Live Meta analysis, evidence-verified findings, TLP-classified
sharing, STIX and PDF exports, local-only MISP preview, and a tamper-evident
audit trail — all on localhost, all synthetic data. Happy to take questions."

## 9. If something fails on stage

| Symptom | Recovery (in order) |
| --- | --- |
| Analysis errors once | Read the hint aloud → **Retry analysis** |
| Analysis errors twice | Open `demo/fallback/` → speak the fallback sentence → continue at Act 4 with `threatlens-fallback-package.json` on screen |
| `rate_limited` with wait seconds | Narrate the guardrail, wait or LOG OUT + log in for a fresh session budget |
| `MODEL API NOT CONFIGURED` | Backend `.env` lost its key — not recoverable live; go to fallback kit |
| Blank / `Cannot reach the backend` | Backend died: restart Terminal 1 command, refresh, log in again |
| Login fails | Wrong key pasted, or backend restarted (sessions are in-memory): re-paste |
| Port clash (`address in use`) | Kill the squatter, restart that server; never change ports mid-demo |
| Browser can't reach localhost | Check proxy bypass for localhost / `NO_PROXY=localhost,127.0.0.1` |

Never improvise with a real report, a real MISP server, or an unlabelled file.
A narrated guardrail ("watch it refuse safely") scores better than a faked
success.
