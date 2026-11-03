import type {
  AnalyzeResponse,
  AuditListResponse,
  AuthStatusResponse,
  ConsentResponse,
  HistoryFilters,
  HistoryListResponse,
  LoginResponse,
  MispApproval,
  MispCreateResponse,
  MispDestinationChoice,
  MispPreviewResponse,
  MispPublishResponse,
  MispTestResponse,
  SharePrepareRequest,
  SharePrepareResponse,
  StixExportResponse,
} from "./types";

export interface HealthResponse {
  status: "ok";
  service: string;
  version: string;
  timestamp: string;
}

/**
 * CSRF token for state-changing requests. In-memory only — never persisted
 * to localStorage, URLs, or env files. Set at login, cleared at logout.
 */
let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

function csrfHeaders(): Record<string, string> {
  return csrfToken ? { "X-CSRF-Token": csrfToken } : {};
}

/** Query the FastAPI health endpoint (proxied to :8000 in dev). */
export async function fetchHealth(signal?: AbortSignal): Promise<HealthResponse> {
  const res = await fetch("/api/health", { signal, credentials: "include" });
  if (!res.ok) {
    throw new Error(`Health check failed with status ${res.status}`);
  }
  return (await res.json()) as HealthResponse;
}

/** Structured error from the backend: { detail: { code, message } }. */
export class ApiError extends Error {
  status: number;
  code: string;
  retryAfter: string | null;

  constructor(status: number, code: string, message: string, retryAfter: string | null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

interface ErrorBody {
  detail?: { code?: string; message?: string } | string | { msg?: string }[];
}

function parseError(status: number, body: ErrorBody | null, res: Response): ApiError {
  const detail = body?.detail;
  if (Array.isArray(detail)) {
    const first = detail[0];
    return new ApiError(
      status,
      "invalid_request",
      first?.msg ?? `Request invalid (HTTP ${status}).`,
      res.headers.get("retry-after"),
    );
  }
  if (typeof detail === "object" && detail !== null) {
    return new ApiError(
      status,
      detail.code ?? "unknown_error",
      detail.message ?? "Analysis failed.",
      res.headers.get("retry-after"),
    );
  }
  return new ApiError(
    status,
    "unknown_error",
    typeof detail === "string" ? detail : `Analysis failed (HTTP ${status}).`,
    res.headers.get("retry-after"),
  );
}

/** Upload a report for AI analysis. The API key stays on the backend. */
export async function analyzeReport(
  file: File,
  signal?: AbortSignal,
): Promise<AnalyzeResponse> {
  const form = new FormData();
  form.append("file", file, file.name);
  let res: Response;
  try {
    res = await fetch("/api/analyze", {
      method: "POST",
      body: form,
      signal,
      credentials: "include",
      headers: csrfHeaders(),
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError(
      0,
      "backend_unreachable",
      "Cannot reach the backend. Is it running on port 8000?",
      null,
    );
  }
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as ErrorBody | null;
    throw parseError(res.status, body, res);
  }
  return (await res.json()) as AnalyzeResponse;
}

/** Convert an analysis result to a validated STIX 2.1 bundle. */
export async function exportStix(
  result: AnalyzeResponse,
  signal?: AbortSignal,
): Promise<StixExportResponse> {
  let res: Response;
  try {
    res = await fetch("/api/export/stix", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...csrfHeaders() },
      credentials: "include",
      body: JSON.stringify(result),
      signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError(
      0,
      "backend_unreachable",
      "Cannot reach the backend. Is it running on port 8000?",
      null,
    );
  }
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as ErrorBody | null;
    throw parseError(res.status, body, res);
  }
  return (await res.json()) as StixExportResponse;
}

/** Prepare a classified sharing package (Phase 1: no publishing). */
export async function prepareShare(
  req: SharePrepareRequest,
  signal?: AbortSignal,
): Promise<SharePrepareResponse> {
  let res: Response;
  try {
    res = await fetch("/api/share/prepare", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...csrfHeaders() },
      credentials: "include",
      body: JSON.stringify(req),
      signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError(
      0,
      "backend_unreachable",
      "Cannot reach the backend. Is it running on port 8000?",
      null,
    );
  }
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as ErrorBody | null;
    throw parseError(res.status, body, res);
  }
  return (await res.json()) as SharePrepareResponse;
}

/** Render a prepared package as a classified PDF report. */
export async function downloadSharePdf(
  pkg: SharePrepareResponse,
  analyst: string,
  signal?: AbortSignal,
): Promise<{ filename: string; blob: Blob }> {
  let res: Response;
  try {
    res = await fetch("/api/share/pdf", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...csrfHeaders() },
      credentials: "include",
      body: JSON.stringify({ package: pkg, analyst }),
      signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError(
      0,
      "backend_unreachable",
      "Cannot reach the backend. Is it running on port 8000?",
      null,
    );
  }
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as ErrorBody | null;
    throw parseError(res.status, body, res);
  }
  return {
    filename: `threatlens-share-${pkg.package_id.slice(0, 8)}.pdf`,
    blob: await res.blob(),
  };
}

/** Shared POST helper for the MISP endpoints (same error shape as above). */
async function postJson<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...csrfHeaders() },
      credentials: "include",
      body: JSON.stringify(body),
      signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError(
      0,
      "backend_unreachable",
      "Cannot reach the backend. Is it running on port 8000?",
      null,
    );
  }
  if (!res.ok) {
    const errBody = (await res.json().catch(() => null)) as ErrorBody | null;
    throw parseError(res.status, errBody, res);
  }
  return (await res.json()) as T;
}

/** Explicit MISP connection check. Reach out only when the analyst clicks. */
export function mispTest(signal?: AbortSignal): Promise<MispTestResponse> {
  return postJson<MispTestResponse>("/api/misp/test", {}, signal);
}

/** Build a MISP event preview locally (no MISP traffic). */
export function mispPreview(
  pkg: SharePrepareResponse,
  destination: MispDestinationChoice,
  signal?: AbortSignal,
): Promise<MispPreviewResponse> {
  return postJson<MispPreviewResponse>(
    "/api/misp/preview",
    { package: pkg, destination },
    signal,
  );
}

/** Create an unpublished MISP draft (approval + confirmation required). */
export function mispCreate(
  pkg: SharePrepareResponse,
  analyst: string,
  destination: MispDestinationChoice,
  approval: MispApproval,
  signal?: AbortSignal,
): Promise<MispCreateResponse> {
  return postJson<MispCreateResponse>(
    "/api/misp/create",
    { package: pkg, analyst, destination, approval },
    signal,
  );
}

/** Publish a ThreatLens-created event (separate explicit action). */
export function mispPublish(
  eventUuid: string,
  analyst: string,
  approval: MispApproval,
  signal?: AbortSignal,
): Promise<MispPublishResponse> {
  return postJson<MispPublishResponse>(
    "/api/misp/publish",
    { event_uuid: eventUuid, analyst, approval },
    signal,
  );
}

/** Shared GET helper (same error shape as postJson). */
async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, { signal, credentials: "include" });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError(
      0,
      "backend_unreachable",
      "Cannot reach the backend. Is it running on port 8000?",
      null,
    );
  }
  if (!res.ok) {
    const errBody = (await res.json().catch(() => null)) as ErrorBody | null;
    throw parseError(res.status, errBody, res);
  }
  return (await res.json()) as T;
}

/** Caller role and whether distribution is enabled. */
export function fetchAuthStatus(signal?: AbortSignal): Promise<AuthStatusResponse> {
  return getJson<AuthStatusResponse>("/api/auth/status", signal);
}

/** Exchange an operator key for a session cookie + CSRF token. */
export async function login(
  key: string,
  signal?: AbortSignal,
): Promise<LoginResponse> {
  const res = await postJson<LoginResponse>("/api/auth/login", { key }, signal);
  setCsrfToken(res.csrf_token);
  return res;
}

/** Acknowledge external AI processing for this session (H-3 gate for /api/analyze). */
export function grantAiConsent(signal?: AbortSignal): Promise<ConsentResponse> {
  return postJson<ConsentResponse>("/api/auth/consent", { acknowledged: true }, signal);
}

/** Destroy the current session. */
export async function logout(signal?: AbortSignal): Promise<void> {
  try {
    await postJson<{ logged_out: boolean }>("/api/auth/logout", {}, signal);
  } finally {
    setCsrfToken(null);
  }
}

/** List distribution history records (demonstration data while unauthenticated). */
export function fetchHistory(
  filters: HistoryFilters = {},
  signal?: AbortSignal,
): Promise<HistoryListResponse> {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value) params.set(key, value);
  }
  const query = params.toString();
  return getJson<HistoryListResponse>(
    query ? `/api/history/records?${query}` : "/api/history/records",
    signal,
  );
}

/** Read the append-only audit log, newest first. */
export function fetchAuditEvents(
  filters: { event?: string; since?: string; until?: string; limit?: number } = {},
  signal?: AbortSignal,
): Promise<AuditListResponse> {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== "") params.set(key, String(value));
  }
  const query = params.toString();
  return getJson<AuditListResponse>(
    query ? `/api/audit/events?${query}` : "/api/audit/events",
    signal,
  );
}

/** Render a prepared package as a TLP-marked STIX 2.1 bundle. */
export async function exportPackageStix(
  pkg: SharePrepareResponse,
  analyst: string,
  signal?: AbortSignal,
): Promise<StixExportResponse> {
  let res: Response;
  try {
    res = await fetch("/api/share/stix", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...csrfHeaders() },
      credentials: "include",
      body: JSON.stringify({ package: pkg, analyst }),
      signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError(
      0,
      "backend_unreachable",
      "Cannot reach the backend. Is it running on port 8000?",
      null,
    );
  }
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as ErrorBody | null;
    throw parseError(res.status, body, res);
  }
  return (await res.json()) as StixExportResponse;
}
