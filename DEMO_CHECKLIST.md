# ThreatLens AI — Demo Checklist

Manual end-to-end verification for the Meta Global AI Developer Hackathon
submission. Run top to bottom on localhost. Companion: [DEMO_SCRIPT.md](DEMO_SCRIPT.md)
(presentation narrative), [README.md](README.md) (setup reference).

Test status at time of writing: **206 backend + 55 frontend tests pass**,
`tsc -b` + `vite build` clean, `oxlint` 0 errors.

## 0. Preconditions (before you start)

- [ ] Ports free: nothing on `127.0.0.1:8000` or `localhost:5173`.
- [ ] `backend/.env` exists with `MODEL_API_KEY`, `OPERATOR_API_KEY` and
      `ADMIN_API_KEY` (two distinct 32+ char secrets). Never display keys.
- [ ] MISP deliberately **not** configured (`MISP_URL`/`MISP_API_KEY` empty) —
      the demo uses local-only MISP preview. No real MISP endpoint, ever.
- [ ] Demo input ready: [`demo/synthetic_ics_report.txt`](demo/synthetic_ics_report.txt)
      (fictional Blue Mesa Power scenario; TEST-NET IPs only).
- [ ] Fallback kit ready (offline backup only, never Meta output):
      [`demo/fallback/`](demo/fallback/README.md).
- [ ] Browser proxy bypasses localhost (else the UI cannot reach the backend).

Start the servers (see [DEMO_SCRIPT.md](DEMO_SCRIPT.md) §1 for exact commands):

- [ ] Backend `GET http://127.0.0.1:8000/api/health` →
      `{"status":"ok","service":"threatlens-api","version":"0.1.0",...}`.
- [ ] Frontend `http://localhost:5173` shows the **OPERATOR LOGIN** gate.

## 1. Operator login and administrator login

- [ ] Paste the **operator** key → dashboard loads; TopBar shows role `ANALYST`.
- [ ] LOG OUT → login gate returns. Paste the **admin** key → role
      `ADMINISTRATOR`.
- [ ] Wrong key → `Invalid operator key.` (no session created).
- [ ] Session cookie is HttpOnly; CSRF token lives in memory only (DevTools:
      no token in localStorage or URLs).

## 2. Meta AI data-processing consent

- [ ] Upload panel shows **External AI processing notice** (text sent to the
      Meta Model API `muse-spark-1.3`; NDA/confidential warning).
- [ ] Before acknowledging, each file's **Analyze** button is disabled with
      tooltip `Acknowledge external AI processing first`.
- [ ] Tick the checkbox → **Acknowledge for this session** → banner flips to
      `ACKNOWLEDGED FOR THIS SESSION — ANALYSIS ENABLED`.
- [ ] Audit log later shows one `ai_consent` event (actor only, no content).

## 3. Uploading the synthetic ICS report

- [ ] Drag `demo/synthetic_ics_report.txt` (or Browse) → file queues as
      `ready to analyze` with size.
- [ ] Model status line reads `MODEL API CONNECTED — ANALYSIS ENABLED`.
      (If it reads `NOT CONFIGURED`, stop: fix `MODEL_API_KEY` first.)
- [ ] Negative checks (optional, pre-demo): a `.docx` file and an empty file
      are rejected client-side with a reason; nothing is uploaded.

## 4. Live Meta Muse Spark 1.3 analysis

- [ ] Click **Analyze** → `Analyzing synthetic_ics_report.txt…` with the
      `QUERYING MUSE-SPARK-1.3` note (can take up to ~a minute).
- [ ] Success → header `Analysis: synthetic_ics_report.txt` with badge
      `MUSE-SPARK-1.3 · LIVE AI RESULT`. **Only this badge means live Meta
      output.**
- [ ] If analysis fails, a friendly panel appears (title + hint + retry):
      `model_api_auth_failed`, `model_api_timeout`, `model_api_unreachable`,
      `model_output_truncated`, `rate_limited` (with wait seconds),
      `consent_required`, `backend_unreachable`. Use **Retry analysis**, or
      switch to the labelled fallback kit — never call fallback output live.

## 5. Evidence, IOCs and MITRE ATT&CK results

- [ ] **EXECUTIVE SUMMARY** renders the incident narrative.
- [ ] **ATTACK TECHNIQUES** shows cards with MITRE IDs (expect T1078 /
      T1566.002 on the fixture) and **REPORT EVIDENCE** vs **AI INFERENCE**
      badges plus quoted evidence.
- [ ] **INDICATORS OF COMPROMISE** table lists value, type, **SOURCE CHECK**
      (**VERIFIED IN REPORT** / **NOT FOUND IN REPORT**) and evidence quotes.
- [ ] **CVES**, **AFFECTED SYSTEMS**, **RECOMMENDATIONS** (priority pills),
      **SUPPORTING EVIDENCE** sections render; unverified items carry
      warnings, never invented data.
- [ ] Footer reads `AI-GENERATED ANALYSIS VIA MUSE-SPARK-1.3 — VERIFY
      FINDINGS BEFORE ACTING…`.

## 6. STIX 2.1 JSON download

- [ ] Click **STIX 2.1 JSON** → `threatlens-….stix.json` downloads; UI
      confirms `Exported N STIX objects (…)`.
- [ ] Bundle opens as JSON: Identity `ThreatLens AI` + Report + Indicators /
      Vulnerabilities / Attack Patterns / Infrastructure / Relationships.
- [ ] Invalid MITRE IDs are skipped with warnings, never fabricated
      (covered by `test_stix.py`).

## 7. PDF report export

- [ ] Click **SHARE INTEL** → complete §8 first (package preview required).
- [ ] In the preview, click **PDF REPORT** → `threatlens-share-….pdf`
      downloads.
- [ ] PDF shows the TLP banner in **header and footer of every page**, title
      block (report ID, date, source file, model, approver, audit ref),
      AI-assisted-analysis disclosure, and all approved sections + warnings.

## 8. TLP classification and analyst approval

- [ ] Share panel opens with `UNCLASSIFIED — REVIEW REQUIRED` (source starts
      unmarked; nothing is assumed CLEAR).
- [ ] Set analyst classification (e.g. `TLP:AMBER`), proposed marking
      `TLP:AMBER`; banner flips to `EFFECTIVE SOURCE: TLP:AMBER ·
      PROPOSED: TLP:AMBER`.
- [ ] Deselect one finding, add redaction `Blue Mesa Power` →
      `[FICTIONAL UTILITY REDACTED]`, tick approval, prepare.
- [ ] Preview shows `TLP:AMBER → TLP:AMBER`, **PERMITTED AUDIENCE** text,
      redaction count, package/audit IDs, and the filtered content.
- [ ] Footer: `PREPARED PACKAGE — NOTHING HAS BEEN PUBLISHED.`
- [ ] Negative checks: unmarked source without analyst classification →
      `Source classification required.`; proposed marking below source without
      justification → `Downgrade blocked.` (server-enforced).

## 9. MISP event preview without external publishing

MISP section: **3 · MISP EXPORT — UNPUBLISHED DRAFTS ONLY**.

- [ ] (Optional) **TEST CONNECTION** with MISP unconfigured fails gracefully:
      `Connection failed: … (misp_not_configured)` — no crash, no traffic.
- [ ] Destination: `Your organisation only` (distribution 0). With a
      `TLP:RED` package, wider destinations are disabled with an explanation.
- [ ] **PREVIEW EVENT** → event info, `N ATTRIBUTE(S) · UNPUBLISHED`,
      `tlp:*` tag, destination safety verdict, and the TYPE/VALUE/CATEGORY/IDS
      attribute table. **Preview is computed locally — zero MISP traffic.**
- [ ] Do **not** click Create/Publish against any real server. Draft creation
      needs a local test MISP (see README) and is out of the judged flow.
- [ ] As analyst (non-admin), the publish section reads `Requires
      administrator — you are signed in as ANALYST.` Log in as admin to show
      the publish gate unlocked (still do not publish).

## 10. Sharing history and audit events

History view → two tabs.

- [ ] **Distribution history**: `DEMONSTRATION DATA` banner; status tabs
      (All … Denied); filters for classification / report / recipient / dates;
      records show TLP, destination, finding counts, status.
- [ ] Header shows `ROLE: … · DISTRIBUTION: ENABLED` when logged in.
- [ ] Known UI limitation (do not demo as working): row APPROVE/SEND/CANCEL
      buttons are hard-disabled in the frontend with a stale tooltip, even
      though the API endpoints enforce auth correctly. Narrate, don't click.
- [ ] **Audit log** tab: newest-first live entries — `ai_consent`,
      `classification`, `prepared`, `exported`, `misp_tested` — metadata
      only (no report text, no keys). Filter by event type works.
- [ ] No API exists to edit/delete audit entries (PUT/PATCH/DELETE → 405,
      covered by tests).

## Sign-off

- [ ] All boxes above checked on the demo machine.
- [ ] Fallback kit untouched on screen unless live analysis failed (and then
      labelled as canned, per `demo/fallback/README.md`).
- [ ] No real MISP endpoint configured or contacted; no event published.
- [ ] No confidential report uploaded at any point.
- [ ] `git status` shows only the intended new docs/demo files; nothing pushed.
