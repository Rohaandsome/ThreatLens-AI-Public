"""ThreatLens AI FastAPI application.

Threat intelligence analysis platform focused on critical infrastructure
(especially the energy sector).
"""

from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, File, Query, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import settings
from .errors import AnalysisError, analysis_error_handler
from .schemas import (
    AnalyzeResponse,
    AuditListResponse,
    AuthStatusResponse,
    DistributionResult,
    ConsentRequest,
    ConsentResponse,
    HealthResponse,
    HistoryListResponse,
    HistoryRecord,
    LoginRequest,
    LoginResponse,
    MispCreateRequest,
    MispCreateResponse,
    MispPreviewRequest,
    MispPreviewResponse,
    MispPublishRequest,
    MispPublishResponse,
    MispTestResponse,
    ShareExportRequest,
    SharePrepareRequest,
    SharePrepareResponse,
    StixExportResponse,
)
from .services import (
    analyzer,
    audit,
    authz,
    distribution,
    extraction,
    history_store,
    misp_flow,
    pdf_report,
    ratelimit,
    sharing,
    stix_export,
    tlp,
)

app = FastAPI(
    title="ThreatLens AI API",
    version=settings.api_version,
    description="Cybersecurity threat intelligence analysis for critical infrastructure.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_exception_handler(AnalysisError, analysis_error_handler)

# Request body caps: uploads allow the 10 MB file cap plus multipart overhead;
# JSON endpoints stay small (normal payloads are <1 MB).
MAX_JSON_BODY_BYTES = 2 * 1024 * 1024
MAX_UPLOAD_BODY_BYTES = 12 * 1024 * 1024


class BodySizeLimitMiddleware:
    """Reject oversized request bodies (declared or streamed) with 413."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in (
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ):
            await self.app(scope, receive, send)
            return
        limit = (
            MAX_UPLOAD_BODY_BYTES
            if scope["path"] == "/api/analyze"
            else MAX_JSON_BODY_BYTES
        )
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope["headers"]
        }
        declared = headers.get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            await self._too_large(scope, receive, send, limit)
            return
        body = b""
        trailing: Message | None = None
        while True:
            message = await receive()
            if message["type"] != "http.request":
                trailing = message
                break
            body += message.get("body", b"")
            if len(body) > limit:
                await self._too_large(scope, receive, send, limit)
                return
            if not message.get("more_body", False):
                break

        # Replay the buffered body downstream, then any trailing message.
        queue: list[Message] = [
            {"type": "http.request", "body": body, "more_body": False}
        ]
        if trailing is not None:
            queue.append(trailing)

        async def replay() -> Message:
            if queue:
                return queue.pop(0)
            return {"type": "http.disconnect"}

        await self.app(scope, replay, send)

    async def _too_large(
        self, scope: Scope, receive: Receive, send: Send, limit: int
    ) -> None:
        response = JSONResponse(
            status_code=413,
            content={
                "detail": {
                    "code": "body_too_large",
                    "message": (
                        f"Request body exceeds the {limit // 1024 // 1024} MB limit."
                    ),
                }
            },
        )
        await response(scope, receive, send)


app.add_middleware(BodySizeLimitMiddleware)

_READ_CHUNK = 1024 * 1024  # 1 MB


def _safe_filename(filename: str | None) -> str:
    """Strip directories and cap length; used for display only, never for I/O."""
    return Path(filename or "upload").name[:100] or "upload"


async def _read_bounded(file: UploadFile, limit: int) -> bytes:
    """Read at most limit+1 bytes so oversize uploads fail fast."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(_READ_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise AnalysisError(413, "file_too_large", "File exceeds the 10 MB limit.")
        chunks.append(chunk)
    return b"".join(chunks)


@app.get("/api/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    """Public liveness check. Configuration details need a session."""
    return HealthResponse(version=settings.api_version)


@app.post("/api/analyze", response_model=AnalyzeResponse, tags=["analysis"])
async def analyze(
    file: UploadFile = File(...),
    _actor: str = Depends(
        authz.authorized(settings, authz.Role.analyst, "analyze", csrf=True)
    ),
    _consent: None = Depends(authz.require_ai_consent),
    _limited: None = Depends(ratelimit.limited("analyze")),
) -> AnalyzeResponse:
    """Analyze an uploaded PDF/TXT threat report with the Model API."""
    raw = await _read_bounded(file, settings.max_upload_bytes)
    filename = _safe_filename(file.filename)
    file_type = extraction.validate_upload(filename, len(raw))
    extracted = extraction.extract_text(
        raw, file_type, max_chars=settings.max_report_chars
    )
    result, model, warnings = await run_in_threadpool(
        analyzer.analyze_report_text,
        extracted.text,
        filename,
        settings,
        extracted.truncated,
    )
    return AnalyzeResponse(
        filename=filename,
        file_type=file_type,
        char_count=extracted.char_count,
        truncated=extracted.truncated,
        model=model,
        analyzed_at=datetime.now(timezone.utc),
        warnings=warnings,
        analysis=result,
    )


@app.post("/api/export/stix", response_model=StixExportResponse, tags=["export"])
def export_stix(
    payload: AnalyzeResponse,
    _actor: str = Depends(
        authz.authorized(settings, authz.Role.analyst, "export", csrf=True)
    ),
    _limited: None = Depends(ratelimit.limited("share")),
) -> StixExportResponse:
    """Convert an analysis result to a validated STIX 2.1 bundle."""
    bundle, warnings, counts = stix_export.build_bundle(payload)
    return StixExportResponse(
        filename=stix_export.download_filename(payload.filename),
        bundle=bundle,
        warnings=warnings,
        object_counts=counts,
    )


@app.post("/api/share/prepare", response_model=SharePrepareResponse, tags=["sharing"])
def share_prepare(
    payload: SharePrepareRequest,
    actor: str = Depends(
        authz.authorized(settings, authz.Role.analyst, "prepare", csrf=True)
    ),
    _limited: None = Depends(ratelimit.limited("share")),
) -> SharePrepareResponse:
    """Prepare a classified sharing package (Phase 1: no publishing)."""
    return sharing.build_package(payload, actor)


@app.post("/api/share/pdf", tags=["sharing"])
def share_pdf(
    payload: ShareExportRequest,
    actor: str = Depends(
        authz.authorized(settings, authz.Role.analyst, "export", csrf=True)
    ),
    _limited: None = Depends(ratelimit.limited("share")),
) -> Response:
    """Render a prepared package as a classified PDF report."""
    data = pdf_report.build_pdf(payload.package, analyst=actor)
    audit.record(
        "exported",
        {
            "analyst": actor,
            "format": "pdf",
            "package_id": payload.package.package_id,
            "classification": payload.package.classification.proposed,
        },
    )
    filename = f"threatlens-share-{payload.package.package_id[:8]}.pdf"
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/share/stix", response_model=StixExportResponse, tags=["sharing"])
def share_stix(
    payload: ShareExportRequest,
    actor: str = Depends(
        authz.authorized(settings, authz.Role.analyst, "export", csrf=True)
    ),
    _limited: None = Depends(ratelimit.limited("share")),
) -> StixExportResponse:
    """Render a prepared package as a TLP-marked STIX 2.1 bundle."""
    bundle, warnings, counts = stix_export.build_package_bundle(payload.package)
    audit.record(
        "exported",
        {
            "analyst": actor,
            "format": "stix",
            "package_id": payload.package.package_id,
            "classification": payload.package.classification.proposed,
        },
    )
    return StixExportResponse(
        filename=stix_export.download_filename(
            payload.package.source_filename or "shared-report"
        ),
        bundle=bundle,
        warnings=warnings,
        object_counts=counts,
    )


@app.post("/api/misp/test", response_model=MispTestResponse, tags=["misp"])
def misp_test(
    _actor: str = Depends(
        authz.authorized(settings, authz.Role.analyst, "misp_test", csrf=True)
    ),
    _limited: None = Depends(ratelimit.limited("misp_read")),
) -> MispTestResponse:
    """Explicit connection check. Authenticated operators only."""
    return misp_flow.test_connection(settings)


@app.post(
    "/api/misp/preview", response_model=MispPreviewResponse, tags=["misp"]
)
def misp_preview(
    request: MispPreviewRequest,
    _actor: str = Depends(
        authz.authorized(settings, authz.Role.analyst, "misp_preview", csrf=True)
    ),
    _limited: None = Depends(ratelimit.limited("misp_read")),
) -> MispPreviewResponse:
    """Build a full event preview locally. No MISP network traffic."""
    return misp_flow.prepare_preview(settings, request)


@app.post(
    "/api/misp/create", response_model=MispCreateResponse, tags=["misp"]
)
def misp_create(
    request: MispCreateRequest,
    actor: str = Depends(
        authz.authorized(settings, authz.Role.analyst, "misp_create", csrf=True)
    ),
    _limited: None = Depends(ratelimit.limited("misp_write")),
) -> MispCreateResponse:
    """Create an unpublished draft event after approval + confirmation."""
    return misp_flow.create_draft(settings, request, actor)


@app.post(
    "/api/misp/publish", response_model=MispPublishResponse, tags=["misp"]
)
def misp_publish(
    request: MispPublishRequest,
    actor: str = Depends(
        authz.authorized(
            settings, authz.Role.administrator, "misp_publish", csrf=True
        )
    ),
    _limited: None = Depends(ratelimit.limited("misp_write")),
) -> MispPublishResponse:
    """Publish a ThreatLens-created event. Administrators only."""
    return misp_flow.publish_draft(settings, request, actor)


@app.post("/api/auth/login", response_model=LoginResponse, tags=["system"])
def auth_login(
    payload: LoginRequest, request: Request, response: Response
) -> LoginResponse:
    """Exchange an operator key for a session cookie + CSRF token."""
    token, role, csrf_token = authz.login(settings, payload.key, request)
    authz.set_session_cookie(response, token, settings)
    return LoginResponse(
        role=role.name,
        csrf_token=csrf_token,
        expires_in_seconds=settings.session_timeout_seconds,
    )


@app.post("/api/auth/logout", tags=["system"])
def auth_logout(request: Request, response: Response) -> dict[str, bool]:
    """Destroy the current session (CSRF-protected when logged in)."""
    if authz.resolve_role(request) != authz.Role.anonymous:
        authz.require_csrf(request)
    authz.destroy_session(request)
    authz.clear_session_cookie(response)
    return {"logged_out": True}


@app.get("/api/auth/status", response_model=AuthStatusResponse, tags=["system"])
def auth_status(request: Request) -> AuthStatusResponse:
    """Session status. Config details and CSRF tokens need a live session."""
    role = authz.resolve_role(request)
    operator_ok, _ = authz.auth_configured(settings)
    if role == authz.Role.anonymous:
        return AuthStatusResponse(
            authenticated=False,
            role=role.name,
            distribution_enabled=False,
            auth_configured=operator_ok,
            ai_consent=False,
        )
    return AuthStatusResponse(
        authenticated=True,
        role=role.name,
        distribution_enabled=authz.distribution_enabled(role),
        auth_configured=True,
        csrf_token=authz.csrf_token_for(request),
        model_api_configured=bool(settings.model_api_key),
        misp_configured=bool(settings.misp_url and settings.misp_api_key),
        ai_consent=authz.ai_consented(request),
    )


@app.post("/api/auth/consent", response_model=ConsentResponse, tags=["system"])
def auth_consent(
    payload: ConsentRequest,
    request: Request,
    actor: str = Depends(
        authz.authorized(settings, authz.Role.analyst, "consent", csrf=True)
    ),
) -> ConsentResponse:
    """Record AI-processing acknowledgment for this session (audited once)."""
    if not payload.acknowledged:
        raise AnalysisError(
            400,
            "invalid_acknowledgment",
            "Acknowledgment is required before AI analysis.",
        )
    if authz.grant_ai_consent(request):
        audit.record(
            "ai_consent",
            {"analyst": actor, "role": authz.resolve_role(request).name},
        )
    return ConsentResponse(acknowledged=True)


@app.get(
    "/api/history/records", response_model=HistoryListResponse, tags=["history"]
)
def history_records(
    request: Request,
    _actor: str = Depends(
        authz.authorized(settings, authz.Role.analyst, "history", csrf=False)
    ),
    status: str | None = Query(default=None),
    classification: str | None = Query(default=None),
    report: str | None = Query(default=None, max_length=200),
    recipient: str | None = Query(default=None, max_length=200),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> HistoryListResponse:
    """List distribution records newest-first (demonstration data for now)."""
    if status is not None and status not in history_store.STATUSES:
        raise AnalysisError(400, "invalid_status", f"Unknown status '{status}'.")
    if classification is not None:
        try:
            classification = tlp.parse_marking(classification)
        except tlp.InvalidMarkingError:
            raise AnalysisError(
                400, "invalid_tlp", f"Unknown TLP marking '{classification}'."
            ) from None
    role = authz.resolve_role(request)
    records, total = history_store.list_records(
        status=status,
        classification=classification,
        report=report,
        recipient=recipient,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )
    return HistoryListResponse(
        records=[HistoryRecord.model_validate(r) for r in records],
        total=total,
        demo=all(r["demo"] for r in records),
        distribution_enabled=authz.distribution_enabled(role),
    )


@app.get(
    "/api/history/records/{record_id}",
    response_model=HistoryRecord,
    tags=["history"],
)
def history_record(
    record_id: str,
    _actor: str = Depends(
        authz.authorized(settings, authz.Role.analyst, "history", csrf=False)
    ),
) -> HistoryRecord:
    """Fetch one distribution record by ID."""
    record = history_store.get_record(record_id)
    if record is None:
        raise AnalysisError(404, "unknown_record", "Distribution record not found.")
    return HistoryRecord.model_validate(record)


@app.get("/api/audit/events", response_model=AuditListResponse, tags=["history"])
def audit_events(
    _actor: str = Depends(
        authz.authorized(settings, authz.Role.analyst, "audit", csrf=False)
    ),
    event: str | None = Query(default=None, max_length=100),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AuditListResponse:
    """Read the append-only audit log newest-first (metadata only)."""
    events, total = audit.read_events(
        event=event, since=since, until=until, limit=limit, offset=offset
    )
    return AuditListResponse(events=events, total=total)


def _distribution_action(request: Request, record_id: str, action: str) -> DistributionResult:
    """Authenticated distribution gate: role + CSRF, then the state machine.

    Denied attempts are audit-logged with metadata only (action, record ID,
    role, reason) — never credentials or report bodies.
    """
    try:
        role = authz.require_role(request, settings, authz.Role.analyst, action)
        authz.require_csrf(request)
    except AnalysisError as exc:
        audit.record(
            "distribution_denied",
            {
                "action": action,
                "record_id": record_id,
                "role": authz.resolve_role(request).name,
                "reason": exc.message,
            },
        )
        raise
    record = history_store.get_record(record_id)
    if record is None:
        raise AnalysisError(404, "unknown_record", "Distribution record not found.")
    if action == "send":
        target = distribution.send_target(record)
    elif action == "approve":
        target = "approved"
    else:  # cancel
        target = "cancelled"
    actor = "administrator" if role == authz.Role.administrator else "operator"
    updated = distribution.transition(record, target, role)
    audit.record(
        "distribution_transition",
        {
            "action": action,
            "record_id": record_id,
            "from_status": record["status"],
            "to_status": updated["status"],
            "role": role.name,
            "analyst": actor,
        },
    )
    return DistributionResult(
        record=HistoryRecord.model_validate(updated), action=action
    )


@app.post(
    "/api/distribution/{record_id}/approve",
    response_model=DistributionResult,
    tags=["history"],
)
def distribution_approve(request: Request, record_id: str) -> DistributionResult:
    """Approve a pending record for distribution."""
    return _distribution_action(request, record_id, "approve")


@app.post(
    "/api/distribution/{record_id}/send",
    response_model=DistributionResult,
    tags=["history"],
)
def distribution_send(request: Request, record_id: str) -> DistributionResult:
    """Send an approved record to its destination."""
    return _distribution_action(request, record_id, "send")


@app.post(
    "/api/distribution/{record_id}/cancel",
    response_model=DistributionResult,
    tags=["history"],
)
def distribution_cancel(request: Request, record_id: str) -> DistributionResult:
    """Cancel a record."""
    return _distribution_action(request, record_id, "cancel")


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    return {"message": "ThreatLens AI API. See /docs for the interactive API docs."}
