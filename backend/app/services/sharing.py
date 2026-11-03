"""Secure sharing preparation (Phase 1: classification, no publishing).

Builds a classified sharing package from an analysis: validates TLP 2.0
markings, enforces no-downgrade-without-approval, applies analyst selection
and redactions, and records every attempt in the audit log. All rules are
enforced here in the backend; the React UI only mirrors them for display.
"""

from typing import Any
from uuid import uuid4

from ..errors import AnalysisError
from ..schemas import (
    AnalysisResult,
    SharePrepareRequest,
    SharePrepareResponse,
    ShareClassification,
)
from . import audit, tlp


def _parse_or_400(raw: str, where: str) -> str:
    try:
        return tlp.parse_marking(raw)
    except (tlp.InvalidMarkingError, ValueError, AttributeError, TypeError) as exc:
        raise AnalysisError(
            400, "invalid_tlp", f"Invalid TLP marking in {where}: {raw!r}."
        ) from exc


def resolve_sources(
    request: SharePrepareRequest,
) -> tuple[list[str | None], str, bool]:
    """Resolve source markings conservatively.

    Returns (canonical markings with None for unmarked, effective source,
    analyst_asserted). Raises classification_required when undetermined and
    downgrade_attempt when the analyst asserts below a known marking.
    """
    canonical: list[str | None] = []
    for src in request.sources:
        if src.marking is None:
            canonical.append(None)
        else:
            canonical.append(_parse_or_400(src.marking, f"source '{src.name}'"))
    known = [m for m in canonical if m is not None]
    asserted = request.analyst_source_marking
    if asserted is not None:
        asserted = _parse_or_400(asserted, "analyst_source_marking")
        if known and tlp.level(asserted) < max(tlp.level(m) for m in known):
            raise AnalysisError(
                422,
                "downgrade_attempt",
                "Analyst classification is less restrictive than an observed "
                "source marking. Only the originator may downgrade a marking.",
            )
    if any(m is None for m in canonical) and asserted is None:
        raise AnalysisError(
            422,
            "classification_required",
            "Source material is unmarked or cannot be determined. The analyst "
            "must explicitly classify it before sharing.",
        )
    effective = tlp.most_restrictive([*(known or []), *( [asserted] if asserted else [])])
    return canonical, effective, asserted is not None


def check_approval(request: SharePrepareRequest, downgrade: bool) -> None:
    approval = request.approval
    if approval is None or not approval.approved:
        raise AnalysisError(
            422,
            "approval_required",
            "Explicit analyst approval is required before preparing a package.",
        )
    if downgrade and (
        not approval.downgrade_accepted or len(approval.justification.strip()) < 10
    ):
        raise AnalysisError(
            422,
            "downgrade_attempt",
            "Downgrade requires explicit acceptance and a justification "
            "(at least 10 characters).",
        )


def _pick_indexes(items: list[Any], indexes: list[int], label: str) -> list[Any]:
    picked = []
    for i in indexes:
        if not isinstance(i, int) or i < 0 or i >= len(items):
            raise AnalysisError(
                422, "invalid_selection", f"Invalid {label} index: {i!r}."
            )
        picked.append(items[i])
    return picked


def apply_selection(request: SharePrepareRequest) -> AnalysisResult:
    """Filter the analysis to the analyst-selected subset (deep copy)."""
    analysis = request.analysis.analysis
    sel = request.selection
    ioc_values = {i.value for i in analysis.indicators_of_compromise}
    for value in sel.iocs:
        if value not in ioc_values:
            raise AnalysisError(
                422, "invalid_selection", f"Unknown IOC in selection: {value!r}."
            )
    cve_ids = {c.id for c in analysis.cves}
    for cid in sel.cves:
        if cid not in cve_ids:
            raise AnalysisError(
                422, "invalid_selection", f"Unknown CVE in selection: {cid!r}."
            )
    system_names = {s.system for s in analysis.affected_systems}
    for name in sel.systems:
        if name not in system_names:
            raise AnalysisError(
                422, "invalid_selection", f"Unknown system in selection: {name!r}."
            )
    filtered = AnalysisResult(
        executive_summary=analysis.executive_summary if sel.include_summary else "",
        attack_techniques=_pick_indexes(
            analysis.attack_techniques, sel.techniques, "technique"
        ),
        indicators_of_compromise=[
            i for i in analysis.indicators_of_compromise if i.value in set(sel.iocs)
        ],
        cves=[c for c in analysis.cves if c.id in set(sel.cves)],
        affected_systems=[
            s for s in analysis.affected_systems if s.system in set(sel.systems)
        ],
        recommendations=_pick_indexes(
            analysis.recommendations, sel.recommendations, "recommendation"
        ),
        supporting_evidence=_pick_indexes(
            analysis.supporting_evidence, sel.evidence, "evidence"
        ),
    )
    item_count = (
        len(filtered.attack_techniques)
        + len(filtered.indicators_of_compromise)
        + len(filtered.cves)
        + len(filtered.affected_systems)
        + len(filtered.recommendations)
        + len(filtered.supporting_evidence)
    )
    if item_count == 0 and not sel.include_summary:
        raise AnalysisError(
            422, "empty_selection", "Select at least one finding to share."
        )
    return filtered.model_copy(deep=True)


def _redactable_fields(result: AnalysisResult) -> list[tuple[Any, str]]:
    """Free-text fields only — identifiers (values, IDs, names) stay intact."""
    fields: list[tuple[Any, str]] = [(result, "executive_summary")]
    for t in result.attack_techniques:
        fields += [(t, "description"), (t, "evidence_quote")]
    for i in result.indicators_of_compromise:
        fields += [(i, "context"), (i, "evidence_quote")]
    for c in result.cves:
        fields += [(c, "description"), (c, "evidence_quote")]
    for s in result.affected_systems:
        fields += [(s, "detail"), (s, "evidence_quote")]
    for r in result.recommendations:
        fields += [(r, "recommendation"), (r, "rationale")]
    for e in result.supporting_evidence:
        fields += [(e, "quote"), (e, "relevance")]
    return fields


def apply_redactions(
    result: AnalysisResult, request: SharePrepareRequest
) -> tuple[int, list[str]]:
    """Apply literal replacements; returns (total applied, unmatched)."""
    applied = 0
    unmatched: list[str] = []
    fields = _redactable_fields(result)
    for red in request.redactions:
        hits = 0
        for obj, attr in fields:
            text = getattr(obj, attr) or ""
            if red.match in text:
                hits += text.count(red.match)
                setattr(obj, attr, text.replace(red.match, red.replacement))
        if hits == 0:
            unmatched.append(red.match)
        applied += hits
    return applied, unmatched


def _content_counts(result: AnalysisResult) -> dict[str, int]:
    return {
        "summary": 1 if result.executive_summary else 0,
        "techniques": len(result.attack_techniques),
        "iocs": len(result.indicators_of_compromise),
        "cves": len(result.cves),
        "systems": len(result.affected_systems),
        "recommendations": len(result.recommendations),
        "evidence": len(result.supporting_evidence),
    }


def build_package(request: SharePrepareRequest, actor: str) -> SharePrepareResponse:
    """Validate, filter, redact, audit, and return the prepared package.

    `actor` is the server-derived session identity used for audit attribution.
    The client-supplied approval label is workflow evidence only and is never
    trusted for identity.
    """
    analyst = actor
    try:
        proposed = _parse_or_400(request.proposed_marking, "proposed_marking")
        canonical, effective, asserted = resolve_sources(request)
        downgrade = tlp.is_downgrade(effective, proposed)
        check_approval(request, downgrade)
        if asserted and request.analyst_source_marking is not None:
            audit.record(
                "classification",
                {
                    "analyst": analyst,
                    "sources": [
                        {"name": s.name, "marking": m}
                        for s, m in zip(request.sources, canonical)
                    ],
                    "asserted": _parse_or_400(
                        request.analyst_source_marking, "analyst_source_marking"
                    ),
                    "effective_source": effective,
                },
            )
        content = apply_selection(request)
        redactions_applied, unmatched = apply_redactions(content, request)

        warnings: list[str] = []
        if downgrade:
            warnings.append(
                f"Downgrade: {effective} source material prepared as {proposed} "
                "with analyst approval. Verify recipients are authorized."
            )
        unverified_iocs = sorted(
            {i.value for i in content.indicators_of_compromise if not i.verified_in_source}
        )
        for value in unverified_iocs:
            warnings.append(f"Included IOC '{value}' is unverified against the source.")
        unverified_cves = sorted(
            {c.id for c in content.cves if not c.verified_in_source}
        )
        for cid in unverified_cves:
            warnings.append(f"Included CVE '{cid}' is unverified against the source.")
        inferred = [
            t.name for t in content.attack_techniques if t.inferred
        ] + [s.system for s in content.affected_systems if s.inferred]
        if inferred:
            warnings.append(
                "Included AI-inferred items (not direct report evidence): "
                + ", ".join(sorted(set(inferred)))
                + "."
            )
        if request.analysis.truncated:
            warnings.append("Source report exceeded the analysis window; partial data.")
        for match in unmatched:
            warnings.append(f"Redaction '{match}' matched no included text.")

        package_id = uuid4().hex
        counts = _content_counts(content)
        audit_entry = audit.record(
            "prepared",
            {
                "analyst": analyst,
                "package_id": package_id,
                "effective_source": effective,
                "proposed": proposed,
                "downgrade": downgrade,
                "analyst_asserted": asserted,
                "content_counts": counts,
                "redactions_applied": redactions_applied,
                "warning_count": len(warnings),
            },
        )
        return SharePrepareResponse(
            package_id=package_id,
            analyzed_at=request.analysis.analyzed_at,
            source_filename=request.analysis.filename,
            model=request.analysis.model,
            classification=ShareClassification(
                source_markings=canonical,
                effective_source=effective,
                proposed=proposed,
                downgrade=downgrade,
                analyst_asserted=asserted,
            ),
            audience=tlp.audience(proposed),
            audience_note=request.audience_note,
            analyst_notes=request.analyst_notes.strip(),
            content=content,
            content_counts=counts,
            warnings=warnings,
            redactions_applied=redactions_applied,
            audit_id=audit_entry["id"],
        )
    except AnalysisError as exc:
        audit.record(
            "rejected",
            {
                "analyst": analyst,
                "code": exc.code,
                "reason": exc.message,
                "proposed": request.proposed_marking,
            },
        )
        raise
