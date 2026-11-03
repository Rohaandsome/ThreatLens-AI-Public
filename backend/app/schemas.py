"""Shared Pydantic schemas for ThreatLens AI."""

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]


class HealthResponse(BaseModel):
    """Public health check. Configuration details stay behind authentication."""

    status: Literal["ok"] = "ok"
    service: str = "threatlens-api"
    version: str = Field(default="0.1.0", description="API version")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatSummary(BaseModel):
    """Lightweight threat summary used by mock endpoints and the dashboard."""

    id: str
    title: str
    severity: Severity
    sector: str
    source: str
    detected_at: datetime
    summary: str


class EvidenceItem(BaseModel):
    """A verbatim excerpt from the report plus why it matters."""

    quote: str = Field(max_length=2000)
    relevance: str = Field(max_length=1000)


class AttackTechnique(BaseModel):
    name: str = Field(max_length=300)
    mitre_id: str | None = Field(default=None, max_length=20)
    description: str = Field(max_length=2000)
    evidence_quote: str = Field(
        default="",
        max_length=2000,
        description="Verbatim supporting excerpt; empty when inferred.",
    )
    inferred: bool = Field(
        default=False,
        description="True when the model inferred this rather than reading it.",
    )


class IOC(BaseModel):
    """Indicator of compromise. Must appear verbatim in the report."""

    value: str = Field(max_length=500)
    type: Literal["ip", "domain", "url", "hash", "email", "filename", "mutex", "other"]
    context: str = Field(default="", max_length=1000)
    evidence_quote: str = Field(default="", max_length=2000)
    verified_in_source: bool = Field(
        default=False,
        description="Set by the backend source check, not the model.",
    )


class CVERef(BaseModel):
    """CVE reference. Must appear verbatim in the report."""

    id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$", max_length=30)
    description: str = Field(default="", max_length=2000)
    evidence_quote: str = Field(default="", max_length=2000)
    verified_in_source: bool = Field(
        default=False,
        description="Set by the backend source check, not the model.",
    )


class AffectedSystem(BaseModel):
    system: str = Field(max_length=300)
    detail: str = Field(default="", max_length=2000)
    evidence_quote: str = Field(default="", max_length=2000)
    inferred: bool = False


class Recommendation(BaseModel):
    recommendation: str = Field(max_length=2000)
    priority: Literal["critical", "high", "medium", "low"] = "medium"
    rationale: str = Field(default="", max_length=2000)


class AnalysisResult(BaseModel):
    """Structured threat-report analysis produced by the model."""

    executive_summary: str = Field(max_length=8000)
    attack_techniques: list[AttackTechnique] = Field(default_factory=list, max_length=50)
    indicators_of_compromise: list[IOC] = Field(default_factory=list, max_length=200)
    cves: list[CVERef] = Field(default_factory=list, max_length=100)
    affected_systems: list[AffectedSystem] = Field(default_factory=list, max_length=100)
    recommendations: list[Recommendation] = Field(default_factory=list, max_length=50)
    supporting_evidence: list[EvidenceItem] = Field(default_factory=list, max_length=50)


class AnalyzeResponse(BaseModel):
    """Full response for POST /api/analyze."""

    filename: str
    file_type: Literal["pdf", "txt"]
    char_count: int
    truncated: bool
    model: str
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    warnings: list[str] = Field(default_factory=list)
    analysis: AnalysisResult


class ShareSource(BaseModel):
    """One source of the shared material with its observed TLP marking."""

    name: str = Field(min_length=1, max_length=100)
    marking: str | None = Field(
        default=None, description="Observed TLP marking; null when unmarked."
    )


class ShareSelection(BaseModel):
    """Analyst-chosen subset of findings to include in the package."""

    include_summary: bool = True
    techniques: list[int] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    systems: list[str] = Field(default_factory=list)
    recommendations: list[int] = Field(default_factory=list)
    evidence: list[int] = Field(default_factory=list)


class ShareRedaction(BaseModel):
    """Literal find/replace applied to included free-text fields only."""

    match: str = Field(min_length=1, max_length=200)
    replacement: str = Field(default="[REDACTED]", max_length=200)


class ShareApproval(BaseModel):
    """Explicit analyst approval. Required for every prepared package."""

    approved: bool = False
    # Free-text workflow label. Ignored for identity: audit attribution always
    # uses the server-derived session actor (see authz.current_actor).
    analyst: str = Field(default="", max_length=100)
    justification: str = Field(default="", max_length=2000)
    downgrade_accepted: bool = False


class SharePrepareRequest(BaseModel):
    """Request to prepare a classified sharing package (no publishing)."""

    analysis: AnalyzeResponse
    sources: list[ShareSource] = Field(min_length=1, max_length=20)
    analyst_source_marking: str | None = Field(
        default=None,
        description="Analyst's explicit classification of the source material.",
    )
    proposed_marking: str
    selection: ShareSelection = Field(default_factory=ShareSelection)
    redactions: list[ShareRedaction] = Field(default_factory=list, max_length=50)
    approval: ShareApproval | None = None
    audience_note: str = Field(default="", max_length=500)
    analyst_notes: str = Field(
        default="", max_length=5000, description="Free-text analyst notes for exports."
    )


class ShareClassification(BaseModel):
    source_markings: list[str | None]
    effective_source: str
    proposed: str
    downgrade: bool
    analyst_asserted: bool


class SharePrepareResponse(BaseModel):
    """Prepared (not published) sharing package with preview data."""

    package_id: str
    prepared_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    analyzed_at: datetime | None = None
    source_filename: str = ""
    model: str = ""
    classification: ShareClassification
    audience: str
    audience_note: str = ""
    analyst_notes: str = ""
    content: AnalysisResult
    content_counts: dict[str, int]
    warnings: list[str] = Field(default_factory=list)
    redactions_applied: int = 0
    audit_id: str


class ShareExportRequest(BaseModel):
    """Request to render a prepared package as a downloadable export."""

    package: SharePrepareResponse
    analyst: str = Field(default="unknown", max_length=100)


class MispDestination(BaseModel):
    """Explicit analyst-chosen destination. Never derived from TLP."""

    distribution: int = Field(description="MISP distribution level 0-4.")
    sharing_group_id: int | None = Field(
        default=None, description="Required when distribution is 4."
    )


class MispApproval(BaseModel):
    """Two-step explicit approval for MISP actions."""

    approved: bool = False
    confirmed: bool = False


class MispPreviewRequest(BaseModel):
    package: SharePrepareResponse
    destination: MispDestination | None = None


class MispDestinationCheck(BaseModel):
    safe: bool
    reason: str
    verified: bool = Field(
        description="Whether recipient policy was verified live (never in preview)."
    )


class MispPreviewResponse(BaseModel):
    event: dict[str, Any]
    warnings: list[str] = Field(default_factory=list)
    attribute_count: int
    tlp_tag: str
    destination_check: MispDestinationCheck | None = None


class MispCreateRequest(BaseModel):
    package: SharePrepareResponse
    # Workflow label only; audit identity uses the session actor.
    analyst: str = Field(default="", max_length=100)
    destination: MispDestination
    approval: MispApproval | None = None


class MispCreateResponse(BaseModel):
    event_id: Any
    event_uuid: str
    url: str
    duplicate: bool = False
    warnings: list[str] = Field(default_factory=list)


class MispPublishRequest(BaseModel):
    event_uuid: str = Field(min_length=1, max_length=100)
    # Workflow label only; audit identity uses the session actor.
    analyst: str = Field(default="", max_length=100)
    approval: MispApproval | None = None


class MispPublishResponse(BaseModel):
    event_uuid: str
    published: bool


class MispTestResponse(BaseModel):
    ok: bool
    url: str
    org: str = ""
    role: str = ""
    can_add: bool = False
    can_publish: bool = False
    error: dict[str, str] | None = None


class HistoryRecord(BaseModel):
    """One distribution record: metadata only, never report bodies."""

    id: str
    report_id: str
    package_id: str
    classification: str
    destination_kind: str
    destination_label: str
    destination_detail: dict[str, Any]
    findings: dict[str, int]
    analyst: str
    approved_at: str | None
    status: str
    misp_event_uuid: str | None
    error: str | None
    demo: bool
    created_at: str
    updated_at: str


class HistoryListResponse(BaseModel):
    records: list[HistoryRecord]
    total: int
    demo: bool = Field(description="True while records are demonstration data.")
    distribution_enabled: bool


class AuditListResponse(BaseModel):
    events: list[dict[str, Any]]
    total: int


class AuthStatusResponse(BaseModel):
    authenticated: bool
    role: str
    distribution_enabled: bool
    auth_configured: bool = Field(
        description="Whether operator secrets exist (guides the login screen)."
    )
    csrf_token: str | None = Field(
        default=None,
        description="CSRF token for state-changing requests (sessions only).",
    )
    model_api_configured: bool = Field(
        default=False,
        description="Meta Model API key present (authenticated sessions only).",
    )
    misp_configured: bool = Field(
        default=False,
        description="MISP_URL and MISP_API_KEY present (sessions only).",
    )
    ai_consent: bool = Field(
        default=False,
        description="Session acknowledged AI processing of uploads.",
    )


class LoginRequest(BaseModel):
    key: str = Field(min_length=1, max_length=200)


class LoginResponse(BaseModel):
    role: str
    csrf_token: str
    expires_in_seconds: int


class ConsentRequest(BaseModel):
    acknowledged: bool = Field(
        description="Must be true: the operator accepts AI processing terms."
    )


class ConsentResponse(BaseModel):
    acknowledged: bool


class DistributionResult(BaseModel):
    """Success shape for distribution actions (denied while unauthenticated)."""

    record: HistoryRecord
    action: str


class StixExportResponse(BaseModel):
    """Response for POST /api/export/stix."""

    filename: str = Field(description="Suggested download filename.")
    media_type: Literal["application/json"] = "application/json"
    bundle: dict[str, Any] = Field(description="Validated STIX 2.1 bundle.")
    warnings: list[str] = Field(
        default_factory=list,
        description="Items skipped or downgraded during conversion.",
    )
    object_counts: dict[str, int] = Field(
        default_factory=dict, description="Bundle objects by STIX type."
    )
