# ThreatLens AI — Security Audit

**Date:** 2026-10-31
**Scope:** Full repository (`backend/`, `frontend/`, config, Git history) covering secrets management, API security, MISP security, AI security, data privacy, dependency security, and GitHub readiness.
**Method:** Manual code review of every route, service, and config; pattern scans for secrets in tracked files, built bundles, and full Git history (values redacted); live in-process verification of key findings with isolated state (no external calls); local dependency inventory (no new tools installed, per instructions).
**Overall verdict:** Strong secure-coding foundations (server-side TLP enforcement, secret hygiene, injection resistance, append-only audit) but **not releasable beyond localhost as-is**: there is no authentication on any externally-effective endpoint, no rate limiting, and confidential uploads leave the building to a third-party model API without in-product disclosure. Fix C-1, H-1/H-2, H-3 before any deployment or public release.

> **Status note (2026-11-02): The findings below are preserved as originally reported on 2026-10-31. Since then, all Critical/High findings have been remediated — C-1 (2026-10-31, operator session authentication), H-2 (2026-11-01, rate limiting + body caps), H-3 (2026-11-01, upload disclosure + consent enforcement), H-1 (2026-11-02, MISP destination allowlist; its authentication half was already closed by the C-1 role gating). See the "Remediation log" for details, verification, and residual notes. M-series and L-series hardening items remain open.**

## Severity scale

- **Critical** — Directly exploitable with severe impact (data loss, external effects, cost). Blocks release.
- **High** — Exploitable with significant impact, or a missing control the threat model requires. Blocks release.
- **Medium** — Real weakness with bounded impact, or a missing hardening control. Fix before production.
- **Low** — Minor issue, defense-in-depth note, or hygiene item.
- Each finding is marked **Verified** (demonstrated against this repo) or **Potential** (risk inferred, not demonstrated).

## Findings summary

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| C-1 | No authentication/authorization on any effective endpoint | Critical | Verified |
| H-1 | Unauthenticated MISP event creation and publishing (third-party effects) | High | Verified |
| H-2 | No rate limiting on costly/external endpoints; unbounded request bodies | High | Verified |
| H-3 | Confidential reports sent to external Meta API with no in-product disclosure | High | Verified |
| M-1 | Audit log accepts unauthenticated appends; world-readable; default perms | Medium | Verified |
| M-2 | Upload type checked by extension only; native PDF parser exposure | Medium | Verified |
| M-3 | Uploader-controlled filename interpolated outside prompt markers | Medium | Verified |
| M-4 | Python dependencies unpinned (ranges, no lockfile); no vuln scanning in CI | Medium | Potential |
| M-5 | Unbounded local state growth; no retention/rotation policy | Medium | Verified |
| M-6 | Interactive API docs (`/docs`, `/redoc`) enabled by default | Medium | Verified |
| M-7 | CORS uses credentialed wildcard methods/headers (origins are explicit) | Medium | Verified |
| L-1 | `backend/.env.example` ignored and untracked; README references it | Low | Verified |
| L-2 | History search interpolates `%`/`_` LIKE wildcards (over-matching only) | Low | Verified |
| L-3 | `AnalyzeResponse.filename`/`model` unbounded in JSON bodies | Low | Verified |
| L-4 | `/api/health` discloses configuration booleans | Low | Verified |
| L-5 | README runs uvicorn with `--reload` (dev-only flag) | Low | Verified |
| L-6 | SDK exception strings written to backend logs | Low | Verified |

---

## Critical

### C-1 — No authentication or authorization on any effective endpoint (Verified)

**Affected files:** `backend/app/main.py` (all routes except Phase 4 distribution), `backend/app/services/misp_flow.py`, `backend/app/services/sharing.py`.

**Evidence.** No auth dependency, middleware, or key check exists anywhere (`grep` for `Depends`, `OAuth`, `APIKey`, `Bearer` in `backend/app/main.py` and `config.py` returns nothing). Every "approval" is a client-set JSON boolean, e.g. `backend/app/services/misp_flow.py:51-53` accepts any `{"approved": true, "confirmed": true}`, and `ShareApproval.approved`/`analyst` in `backend/app/schemas.py:152-158` is a self-asserted label. Demonstrated live via in-process TestClient with zero credentials:

- `POST /api/share/prepare` with `analyst: "attacker-impersonating-soc"` → **200** plus a prepared package, audited as legitimate.
- `POST /api/misp/publish` with attacker body → reached the handler (404 only because the UUID was unknown; a known UUID proceeds — see H-1).
- `GET /api/auth/status` → `{"authenticated": false, "role": "anonymous", ...}` while all of the above succeed. Only the new Phase 4 `POST /api/distribution/*` endpoints deny (by design).

**Exploitation impact.** Anyone able to reach the backend (currently only localhost via the documented run command, but any deployment, SSRF-adjacent host, or shared-network exposure changes that) can: burn paid Meta API quota via `/api/analyze`; create/publish MISP events and alerts (H-1); forge sharing packages and poison the audit trail with arbitrary analyst labels; export arbitrary STIX/PDF. Impact becomes **Critical** the moment the port leaves localhost, which "deployment or public release" implies.

**Recommended fix.**
1. Add server-side authentication (login + session tokens or API keys at minimum) and enforce `authz.require_role()` on every mutating/external route — `/api/analyze`, `/api/export/stix`, `/api/share/*`, `/api/misp/*` — before any release. The `authz` module already defines the role model and deny-first pattern; wire `resolve_role()` to verified credentials instead of returning anonymous.
2. Until then, bind to loopback only, firewall the port, and document "single-operator local use only" in the README.
3. Effort: medium (auth system) / trivial (bind + docs stopgap).

---

## High

### H-1 — Unauthenticated MISP event creation and publishing with third-party effects (Verified)

**Affected files:** `backend/app/services/misp_flow.py:141-260`, `backend/app/services/misp_client.py:149-154`, `backend/app/main.py:189-217`.

**Evidence.** Draft creation requires only body booleans (`_check_approval`, misp_flow.py:153) plus a client-supplied package; publishing requires only body booleans plus a store UUID (`misp_flow.py:229-257`, ending in `client.publish(event_id, alert=False)`). No caller authentication exists (C-1). Positive controls that **do** hold server-side and were verified: TLP:RED is restricted to distribution 0 (misp_flow.py:156), distribution is never inferred from TLP, sharing-group membership is verified live (misp_flow.py:188), drafts are created `published=false`, `perm_add`/`perm_publish` of the configured key are checked, there is no scheduler/sync/auto-publish path (only call sites are the explicit routes), and TLS verification defaults to true (`config.py:41`).

**Exploitation impact.** With MISP credentials configured, an unauthenticated caller can push arbitrary attacker-authored events into the organization's MISP (intel poisoning), trigger subscriber alerts via publish, and exhaust API quota. The TLP gates constrain *which destinations* attacker content may use, not *whether* attacker content enters MISP. Note the check `live_distribution != 0` on publish re-verification is MISP-state-dependent and correct, but irrelevant without caller auth.

**Recommended fix.** Same as C-1 (require analyst role for create, administrator for publish), plus: alert the MISP abuse contact procedure in runbooks; consider an explicit per-destination allowlist for the configured key; keep `MISP_VERIFY_SSL=true` in production and reject `false` unless `ENVIRONMENT=development`.

### H-2 — No rate limiting on costly/external endpoints; unbounded request bodies (Verified absence)

**Affected files:** `backend/app/main.py` (all routes), `backend/app/config.py`.

**Evidence.** No limiter middleware, decorator, or reverse-proxy guidance exists. `/api/analyze` spends paid model tokens per call (up to 60k input chars + 16k output tokens). `/api/misp/*` performs external writes. `POST /api/export/stix`, `/api/share/prepare`, `/api/share/pdf`, `/api/share/stix` accept unbounded JSON bodies (no `Content-Length` cap; only per-field Pydantic `max_length`s bound subsections), enabling CPU/memory DoS via reportlab/STIX rendering. Audit-generating endpoints allow disk-fill (see M-5).

**Exploitation impact.** Cost exhaustion (model spend), MISP/external spam, service DoS, disk exhaustion — all unauthenticated (compounds C-1).

**Recommended fix.** Add per-IP + per-key rate limits (e.g. slowapi or a reverse proxy): strict on `/api/analyze` and `/api/misp/*`, moderate elsewhere; cap request body size (e.g. 5–10 MB JSON); add response caching headers where safe; document production proxy settings. Effort: small–medium.

### H-3 — Confidential report content sent to external Meta API without in-product disclosure (Verified)

**Affected files:** `backend/app/services/analyzer.py:240-307`, `frontend/src/components/UploadPanel.tsx`.

**Evidence.** `analyze_report_text` sends up to `MAX_REPORT_CHARS` (60,000) characters of raw upload text to `MODEL_API_BASE_URL` (default `https://api.meta.ai/v1`). The upload UI (`UploadPanel.tsx`) says only "Drop PDF or TXT intel for AI analysis" — no notice that content leaves the building, no consent step, no retention/DPA pointer. README documents the API use, but operators uploading third-party or client-confidential reports get no just-in-time warning.

**Exploitation impact.** This is a privacy/compliance risk rather than remote exploitability: accidental exfiltration of client, incident-response, or critical-infrastructure data to a third party with unknown retention; NDA/regulatory exposure for SOC users.

**Recommended fix.** Add a visible pre-upload notice ("Reports are sent to the configured Model API for analysis — do not upload data you are not permitted to share") with a per-session acknowledge checkbox; add a `MODEL_DATA_NOTICE` doc section covering retention/region questions to resolve with Meta; consider a config flag to disable external analysis (local-only mode). Effort: small.

---

## Medium

### M-1 — Audit log accepts unauthenticated appends; world-readable; default file permissions (Verified)

**Affected files:** `backend/app/services/audit.py`, `backend/app/main.py:281-295`, all `audit.record` call sites.

**Evidence.** Demonstrated: anonymous `POST /api/share/prepare` wrote entries with attacker-chosen analyst labels. `GET /api/audit/events` exposes analyst IDs, package IDs, MISP org/role strings to anyone. Log file is created with process-umask permissions (no explicit `0o600`). **Contained:** entries are `json.dumps`-encoded per line, so newline/CRLF injection cannot forge extra records (verified by reading `audit.py:26-37`); there is intentionally no edit/delete API (PUT/PATCH/DELETE → 405, covered by tests).

**Impact.** Audit poisoning (false attribution), internal recon (org names, analyst IDs, package IDs), log spam/disk fill; on shared hosts, other users may read the log.

**Recommended fix.** Require auth for all audit-generating routes (follows C-1); restrict log file to `0o600` and document log ownership; consider hashing/chaining entries for tamper evidence later. Effort: small.

### M-2 — Upload type checked by extension only; native PDF parser exposure (Verified)

**Affected files:** `backend/app/services/extraction.py:27-44`, `backend/app/services/extraction.py:75-90`, `backend/app/main.py:74-86`.

**Evidence.** `validate_upload` accepts anything ending in `.pdf`/`.txt`; content is never magic-byte checked, so arbitrary bytes reach `pymupdf.open()` (native C parser — memory-safety exposure to malformed PDFs). Mitigations present and verified: 10 MB streaming cap with fail-fast 413, in-memory only (no disk writes), encrypted PDFs rejected, truncation to 60k chars, nothing executed.

**Impact.** Malformed-PDF DoS or, in the worst case, a parser memory-safety bug; low likelihood given caps, but the parser is the largest native attack surface in the app.

**Recommended fix.** Verify magic bytes (`%PDF-`) before parsing; cap page count and extracted-text size pre-truncation; keep pymupdf current via the new scan gate (M-4); run the backend sandboxed/without ambient credentials. Effort: small.

### M-3 — Uploader-controlled filename interpolated outside prompt markers (Verified)

**Affected files:** `backend/app/services/analyzer.py:52-65` (`build_user_prompt`).

**Evidence.** `f"Analyze the following threat report ({filename})."` places the sanitized-but-attacker-controlled filename outside the `--- BEGIN/END REPORT ---` quarantine, while rule 6 of the system prompt only disavows instructions "in the report". Filename is length-capped (100) and the model still faces temp-0, schema validation, and verbatim IOC/CVE re-verification, which bound practical impact — a filename cannot smuggle IOCs/CVEs past verification, but could nudge free-text fields (summary, recommendations).

**Impact.** Low-probability prompt-influence on narrative fields only.

**Recommended fix.** Move the filename inside the marked block or strip it to the sanitized stem and quote it; add a regression test with an instruction-bearing filename. Effort: trivial.

### M-4 — Python dependencies use floating ranges with no lockfile; no vulnerability scanning (Potential)

**Affected files:** `backend/requirements.txt`; `frontend/package.json` + `frontend/package-lock.json` (tracked — good).

**Evidence.** Installed versions inventoried locally (e.g. fastapi 0.116.2, starlette 0.48.0, uvicorn 0.34.3, openai 1.109.1, pymupdf 1.28.2, reportlab 4.5.1, pymisp 2.5.34.4, python-multipart 0.0.33, React 19.3.1, vite 8.3.5). No `pip-audit`/`safety`/`npm audit` tooling is installed and network policy forbids installing new tools, so **no CVE verdict is verifiable from here — no known-vulnerable dependency is asserted.** The structural risk is verified: `requirements.txt` pins ranges (`>=,<`), so two installs resolve different code (supply-chain drift); only npm has a lockfile.

**Impact.** Builds are not reproducible; a compromised or vulnerable release inside a range could be picked up silently.

**Recommended fix.** Commit `pip freeze` output (or pip-tools/uv lock) and hashes; add `pip-audit` and `npm audit` (or OSV-Scanner) as CI gates with fail-on-high; re-run this section once scanners are available. Effort: small.

### M-5 — Unbounded local state growth; no retention/rotation policy (Verified)

**Affected files:** `backend/app/services/audit.py` (`audit/audit.log`), `backend/app/services/history_store.py` (`data/history.db`), `backend/app/services/misp_store.py` (`data/misp_exports.json`).

**Evidence.** All three grow forever; nothing rotates, compacts, or expires. Combined with H-2 (unauthenticated append-capable endpoints), disk exhaustion is reachable remotely; combined with long-lived analyst/org identifiers, retention is a privacy loose end.

**Recommended fix.** Add size/age rotation for the JSONL log (or ship to syslog), retention windows + purge for history/exports, and disk-usage monitoring. Effort: small–medium.

### M-6 — Interactive API docs exposed by default (Verified)

**Affected files:** `backend/app/main.py:49-54` (default `FastAPI(...)` leaves `/docs`, `/redoc`, `/openapi.json` enabled).

**Evidence.** Default-on; combined with C-1 it hands unauthenticated callers a clickable attack surface map, including "try it out" execution.

**Recommended fix.** Disable docs in production (`docs_url=None, redoc_url=None, openapi_url=None` unless `ENVIRONMENT=development`). Effort: trivial.

### M-7 — CORS allows credentials with wildcard methods/headers (Verified, hardening)

**Affected files:** `backend/app/main.py:56-62`, `backend/app/config.py:22`.

**Evidence.** `allow_credentials=True` with `allow_methods=["*"]`, `allow_headers=["*"]`; origins default to the two localhost dev URLs. Current default is acceptable (explicit origins; browsers refuse `*` + credentials), but any operator who widens `CORS_ORIGINS` carelessly (e.g. adding `https://*` patterns or reflecting origins in a proxy) combined with future cookie auth would create CSRF-grade exposure.

**Recommended fix.** Enumerate methods/headers explicitly, keep origins tight in production, and re-check this block when cookie/session auth lands. Effort: trivial.

---

## Low

### L-1 — `backend/.env.example` ignored and untracked; README references it (Verified)

`.gitignore:24` (`backend/.env.*`) also matches the template, so `git ls-files` contains only the root `.env.example`. Fresh clones lack backend configuration guidance, inviting misconfiguration. Fix: add a `!backend/.env.example` negation (one line).

### L-2 — History search wildcards (Verified, no injection)

`history_store.py` builds `LIKE %...%` from user input with bound parameters — no SQL injection (verified: all values passed as parameters) — but literal `%`/`_` in input act as wildcards (over-matching). Fix: escape LIKE metacharacters. Effort: trivial.

### L-3 — `AnalyzeResponse.filename`/`model` unbounded in JSON bodies (Verified)

`schemas.py:115,119` lack `max_length` (unlike nearly every other string field). Values are reflected in responses and pass through `_safe_download_stem` (sanitized to `[A-Za-z0-9._-]`, stix_export.py:159-161) before any filename/header use, and `share_pdf` uses the hex package ID in `Content-Disposition` — so impact is limited to oversized JSON. Fix: add `max_length` (e.g. 200/100). Effort: trivial.

### L-4 — `/api/health` discloses configuration booleans (Verified)

`main.py:89-96` reports `model_api_configured`/`misp_configured` — minor recon (tells attackers which paid/external paths are live). Acceptable for a status endpoint; consider gating details or rate-limiting. No secret values leak (booleans only — verified).

### L-5 — README runs uvicorn with `--reload` (Verified, dev-only)

`README.md:63`. Harmless as documented (default binds loopback) but must not be cargo-culted into production (watcher overhead, debug surface). Fix: add an explicit production run command (no reload, explicit `--host 127.0.0.1`, workers, proxy TLS).

### L-6 — SDK exception strings written to backend logs (Verified)

`analyzer.py:288` logs `str(exc)` from the OpenAI SDK. Assessed low: SDK error strings carry status/message/IDs, not request bodies, and field-path-only logging is used for validation failures (`analyzer.py:229-232`). Keep an eye on it when swapping providers.

---

## Verified strengths (keep these)

- **Secrets:** no hardcoded values in tracked files, built bundles, or any Git commit (full-history scan, values redacted); `backend/.env` (which holds a real local key) is gitignored; keys are server-side only with `misp_configured` booleans to the UI; tests assert keys never appear in responses, logs, or audits.
- **No SSRF:** no user-controlled URL is ever fetched (Model/MISP URLs are server config).
- **No XSS sinks:** no `dangerouslySetInnerHTML`/`innerHTML`; React-escaped rendering; the only dynamic link is a server-built MISP URL with `rel="noreferrer"`.
- **Injection resistance:** parameterized SQLite; JSON-encoded audit lines; sanitized download stems; hex package IDs in headers; extension + size validation on uploads with in-memory-only parsing.
- **AI safety depth:** injection-resistant system prompt + report markers + temp-0 + strict JSON-schema validation with local Pydantic re-check + verbatim IOC/CVE source re-verification with warnings + evidence/inference distinction + field-path-only failure logging.
- **MISP caution:** unpublished drafts, no auto-publish/sync (verified: no schedulers; sole publish call site is the explicit route), no TLP→distribution inference, TLP:RED→org-only, live sharing-group verification, MISP-side permission checks, TLS-verify-by-default, idempotent creates, fully mocked tests.
- **Audit design:** append-only via API (PUT/PATCH/DELETE → 405, tested), metadata-only entries, Phase 4 deny-first authorization with secret-free denial audits.

## Dependency report (inventory; scanner unavailable offline)

| Package | Installed | Notes |
|---|---|---|
| fastapi / starlette / uvicorn | 0.116.2 / 0.48.0 / 0.34.3 | Current ranges; run pip-audit in CI |
| pydantic / pydantic-settings | 2.14.2 / 2.16.2 | — |
| openai / httpx / requests / urllib3 / certifi | 1.109.1 / 0.28.1 / 2.34.2 / 2.8.0 / 2026.10.23 | — |
| pymupdf | 1.28.2 | Native parser — priority for M-2/M-4 |
| stix2 / reportlab / pymisp / python-multipart / pytest | 3.0.2 / 4.5.1 / 2.5.34.4 / 0.0.33 / 8.4.2 | — |
| react / react-dom / vite / vitest / jsdom | 19.3.1 / 19.3.1 / 8.3.5 / 5.0.5 / 30.1.3 | Lockfile tracked; run npm audit in CI |

No `pip-audit`, `safety`, or offline `npm audit` capability exists in this environment, and installing new tools was out of scope — so **no dependency is asserted vulnerable or clean here** (see M-4). No typosquatting, private-registry, or unexpected packages were observed in either manifest.

## GitHub readiness checklist

- [x] No secret values in tracked files or any commit (scanned; values redacted, none printed).
- [x] `.env`, `*.pem/*.key`, `*.db/*.sqlite*`, logs, `backend/audit/`, `backend/data/` ignored; local `backend/.env` confirmed ignored.
- [ ] `backend/.env.example` is unintentionally ignored — untrack-gap, see L-1.
- [x] Only TEST-NET (`192.0.2.x`, `198.51.100.x`), RFC1918 test IPs, `127.0.0.1`, and one invalid `999.x` test value in tracked files; no internal hostnames, absolute paths, or proprietary content found. Test fixture and mocks are synthetic.
- [x] `package-lock.json` tracked; no private registry URLs.
- [ ] No push, visibility change, or release performed (per instructions — none will be without explicit direction).
- Manual review still advised for: the local `backend/.env` contents hygiene (rotation if the key was ever pasted anywhere), and MISP/test-instance credentials in operator notes outside the repo.

## Test summary (this session)

- Backend: `pytest tests/ -q` → **153 passed** (includes auth-denial, TLP, audit-integrity, and mocked-MISP suites; no test performs network I/O).
- Frontend: `tsc -b` clean; `vitest run` → **42 passed** (4 files); `vite build` clean; `oxlint` 0 errors, 1 pre-existing warning in `App.tsx`.
- Security-relevant coverage already present: approval-required paths, unsafe-TLP rejection, secret-leak scans over responses/audits/stores, append-only (405) checks, client-identity rejection. Gaps tests do not cover: authentication (doesn't exist), rate limiting (doesn't exist), and dependency CVEs (no scanner gate).

## No production code changed

Per instructions, this audit made zero source changes. The only new file is this report. Recommended first patches: wire `authz.require_role()` into all effective routes, add rate limits + docs toggle + filename prompt fix, and ship the upload disclosure — details above.

## Remediation log

- **2026-10-31 — C-1 remediated.** Operator session authentication added
  (`OPERATOR_API_KEY`/`ADMIN_API_KEY` in backend env, HttpOnly SameSite
  cookie + synchronizer CSRF, login throttle, fail-closed 503 without
  secrets). All effective routes require analyst role or above; MISP
  publishing requires administrator; audit attribution uses the
  server-derived session actor; analyst labels are untrusted workflow text.
  Health endpoint stripped to liveness-only. Verified by
  `backend/tests/test_auth.py` (15 tests) plus updated suites.
  Remaining from this audit: H-2 (general rate limiting), H-3 (upload
  disclosure), M-series and L-series hardening — still open.

- **2026-11-01 — H-2 remediated.** Sliding-window rate limiter added
  (`backend/app/services/ratelimit.py`, in-memory single-process):
  per-session buckets `analyze` 10/h, `misp_write` 20/h, `misp_read`
  60/h, `share` 60/h, wired as route dependencies AFTER auth so
  anonymous floods still get 401 while abuse gets 429 with `Retry-After`
  and a safe message; login keeps its per-IP throttle (10/min,
  `login_throttled`). ASGI middleware caps request bodies (2 MB JSON,
  12 MB multipart `/api/analyze`) with 413 `body_too_large` before any
  handling. Verified by `backend/tests/test_limits.py` (rate + 413
  cases) and frontend 429 surfacing tests. Residual: limits reset on
  restart and don't span workers (documented; use a reverse proxy for
  multi-worker); bucket sizes are MVP guesses awaiting product review.
- **2026-11-01 — H-3 remediated.** Upload panel shows a prominent
  external-AI notice (report text goes to Meta Model API
  `muse-spark-1.3`; no retention/training claims; NDA/confidential
  warning) with an explicit checkbox + per-session acknowledgment
  button; Analyze stays disabled until acked. The backend enforces a
  per-session `ai_consent` flag (`POST /api/auth/consent`, analyst +
  CSRF, 403 `consent_required` on `/api/analyze` without it) and audits
  one `ai_consent` event with actor only — no report content or
  credentials. Verified by `backend/tests/test_limits.py` (consent
  cases) and `frontend/src/App.test.tsx` (notice/ack/403/429 flows).
  Remaining from this audit: H-1 (MISP authorization — partially
  addressed by C-1 role gating, destination allowlist still open),
  M-series and L-series hardening — still open.

- **2026-11-02 — H-1 remediated (destination authorization).** The
  authentication half was already closed by C-1 (analyst role for
  drafts, administrator + CSRF + explicit confirmation for publish);
  this change closes the destination half. `MISP_ALLOWED_DISTRIBUTIONS`
  / `MISP_ALLOWED_SHARING_GROUPS` in backend env form the only
  authority for where events may go (defaults: org-only, no groups;
  malformed/empty fails closed). Frontend destinations are validated
  against the allowlist in preview (flagged unsafe), create (403
  `destination_not_allowed` before any MISP traffic or idempotent
  re-confirmation), and publish (re-checked, so revocation blocks
  pending drafts). Publish additionally verifies the live event's
  distribution/sharing-group still matches the approved destination
  (403 `destination_changed`, with string coercion for real MISP
  responses) and re-verifies sharing-group recipients. TLP:RED stays
  pinned to distribution 0 — the allowlist cannot broaden TLP.
  `MISP_URL` must be http(s) from backend env only (503
  `misp_invalid_url`); client-supplied URLs are never accepted
  (schema has no URL field; extras are dropped). Approvals audit
  `destination_allowed: true`; denials/failures audit the rejecting
  code — no secrets. Verified by 24 new `backend/tests/test_misp.py`
  cases (bypass, revocation, group mismatch/deactivation, TLP, SSRF,
  network failures; sockets blocked, PyMISP faked) and 3 new
  `frontend/src/MispPanel.test.tsx` cases (denial surfacing).
  Residual: group membership is point-in-time (could change between
  the re-check and publish); `MISP_VERIFY_SSL=false` is still
  permitted outside development (open hardening item from H-1's
  recommended fix, unchanged by this work). Remaining from this
  audit: M-series and L-series hardening — still open.
