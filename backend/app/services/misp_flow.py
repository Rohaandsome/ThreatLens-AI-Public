"""MISP orchestration: preview, draft creation, and publishing.

Policy rules enforced here (server-side, never in the browser alone):
- TLP:RED may only go to distribution 0 (creating org); any other
  destination — or an unverifiable recipient set — is rejected.
- Numeric distribution always comes from the analyst's explicit destination
  choice; it is never inferred from a TLP marking.
- Every destination must also be explicitly allowlisted in backend env
  (MISP_ALLOWED_DISTRIBUTIONS / MISP_ALLOWED_SHARING_GROUPS); anything
  else fails closed, including on publish after a revocation.
- Draft creation and publishing each need explicit approval + confirmation.
- Publishing needs the MISP `publish` permission, re-checks the event's
  live distribution/sharing-group against the approved destination, and
  re-verifies sharing-group recipients before releasing alerts.

All failures and outcomes are written to the local audit log. The MISP API
key never appears in responses, audits, or logs.
"""

from typing import Any

from ..config import Settings
from ..errors import AnalysisError
from ..schemas import (
    MispApproval,
    MispCreateRequest,
    MispCreateResponse,
    MispDestinationCheck,
    MispPreviewRequest,
    MispPreviewResponse,
    MispPublishRequest,
    MispPublishResponse,
    MispTestResponse,
    SharePrepareResponse,
)
from . import audit, misp_client, misp_store
from . import tlp as tlp_rules
from .misp_export import (
    DISTRIBUTION_LABELS,
    TLP_TAGS,
    build_misp_event,
    event_preview_dict,
    validate_destination,
)


def _approval_error(action: str) -> AnalysisError:
    return AnalysisError(
        422,
        "approval_required",
        f"MISP {action} needs explicit analyst approval and confirmation.",
    )


def _check_approval(approval: MispApproval | None, action: str) -> None:
    if approval is None or not approval.approved or not approval.confirmed:
        raise _approval_error(action)


def _package_tlp(package: SharePrepareResponse) -> str:
    try:
        return tlp_rules.parse_marking(package.classification.proposed)
    except (tlp_rules.InvalidMarkingError, ValueError, AttributeError, TypeError):
        raise AnalysisError(
            400, "invalid_tlp", "Package carries an invalid TLP marking."
        ) from None


def _allowlist_reason(
    settings: Settings, distribution: int, sharing_group_id: int | None
) -> str | None:
    """H-1: client destinations are valid only if explicitly allowlisted.

    Returns a human-readable denial reason, or None when authorized.
    """
    if distribution not in settings.misp_distribution_allowlist:
        return (
            f"Distribution '{DISTRIBUTION_LABELS.get(distribution, distribution)}' "
            "is not in the MISP destination allowlist. Ask your administrator "
            "to authorize it via MISP_ALLOWED_DISTRIBUTIONS."
        )
    if (
        distribution == 4
        and sharing_group_id not in settings.misp_sharing_group_allowlist
    ):
        return (
            f"Sharing group {sharing_group_id} is not in the MISP destination "
            "allowlist. Ask your administrator to authorize it via "
            "MISP_ALLOWED_SHARING_GROUPS."
        )
    return None


def _require_allowlisted(
    settings: Settings, distribution: int, sharing_group_id: int | None
) -> None:
    reason = _allowlist_reason(settings, distribution, sharing_group_id)
    if reason is not None:
        raise AnalysisError(403, "destination_not_allowed", reason)


def _as_int(value: Any) -> int | None:
    """Coerce a MISP numeric field (often a string). None fails closed."""
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def prepare_preview(
    settings: Settings, request: MispPreviewRequest
) -> MispPreviewResponse:
    """Build a full event preview. Pure local computation — no network."""
    designation = _package_tlp(request.package)
    distribution, sharing_group_id = 0, None
    check: MispDestinationCheck | None = None
    if request.destination is not None:
        distribution, sharing_group_id = validate_destination(
            request.destination.distribution, request.destination.sharing_group_id
        )
        if designation == "TLP:RED" and distribution != 0:
            check = MispDestinationCheck(
                safe=False,
                reason=(
                    "TLP:RED is limited to the creating organisation. "
                    "Choose 'Your organisation only'."
                ),
                verified=False,
            )
        elif (
            reason := _allowlist_reason(settings, distribution, sharing_group_id)
        ) is not None:
            check = MispDestinationCheck(safe=False, reason=reason, verified=False)
        else:
            check = MispDestinationCheck(
                safe=True,
                reason=(
                    f"Destination: {DISTRIBUTION_LABELS[distribution]}"
                    + (
                        f" (sharing group {sharing_group_id})"
                        if sharing_group_id is not None
                        else ""
                    )
                    + ". Recipients are verified live when the draft is created."
                ),
                verified=False,
            )
    event, warnings = build_misp_event(request.package, distribution, sharing_group_id)
    node = event_preview_dict(event)
    return MispPreviewResponse(
        event=node,
        warnings=warnings,
        attribute_count=len(node["attributes"]),
        tlp_tag=TLP_TAGS[designation],
        destination_check=check,
    )


def test_connection(settings: Settings) -> MispTestResponse:
    """Explicit connection check. Only network call allowed before approval."""
    try:
        client = misp_client.build_client(settings)
        user = misp_client.current_user(client)
    except AnalysisError as exc:
        audit.record(
            "misp_tested",
            {"ok": False, "code": exc.code, "reason": exc.message,
             "url": settings.misp_url},
        )
        return MispTestResponse(
            ok=False, url=settings.misp_url,
            error={"code": exc.code, "message": exc.message},
        )
    audit.record(
        "misp_tested",
        {"ok": True, "org": user["org_name"], "role": user["role"],
         "url": settings.misp_url},
    )
    return MispTestResponse(
        ok=True,
        url=settings.misp_url,
        org=user["org_name"],
        role=user["role"],
        can_add=user["perm_add"],
        can_publish=user["perm_publish"],
    )


def create_draft(
    settings: Settings, request: MispCreateRequest, actor: str
) -> MispCreateResponse:
    """Create an unpublished draft event (or return the existing duplicate).

    `actor` is the server-derived session identity; the client label is ignored.
    """
    designation = _package_tlp(request.package)
    distribution, sharing_group_id = validate_destination(
        request.destination.distribution, request.destination.sharing_group_id
    )
    base_audit: dict[str, Any] = {
        "analyst": actor,
        "package_id": request.package.package_id,
        "tlp": designation,
        "distribution": distribution,
        "sharing_group_id": sharing_group_id,
        "url": settings.misp_url,
    }
    try:
        _check_approval(request.approval, "event creation")
        misp_client.require_configured(settings)

        # TLP:RED never leaves the creating organisation.
        if designation == "TLP:RED" and distribution != 0:
            raise AnalysisError(
                403,
                "unsafe_destination",
                "TLP:RED may only use 'Your organisation only'.",
            )

        # H-1: the destination must be explicitly allowlisted in backend
        # env. Checked before the idempotency lookup so a revoked
        # destination cannot be re-confirmed through an old draft.
        _require_allowlisted(settings, distribution, sharing_group_id)

        # Idempotency: same package + destination returns the stored record.
        existing = misp_store.find_export(
            request.package.package_id, settings.misp_url, distribution,
            sharing_group_id,
        )
        if existing is not None:
            audit.record("misp_duplicate", {**base_audit,
                                            "event_uuid": existing["event_uuid"]})
            return MispCreateResponse(
                event_id=existing["event_id"],
                event_uuid=existing["event_uuid"],
                url=existing["event_url"],
                duplicate=True,
                warnings=[],
            )

        client = misp_client.build_client(settings)
        user = misp_client.current_user(client)
        if not user["perm_add"]:
            raise AnalysisError(
                403, "permission_denied",
                "The MISP API user lacks permission to add events.",
            )

        # Verify sharing-group recipients server-side when one is chosen.
        if distribution == 4 and sharing_group_id is not None:
            group = misp_client.sharing_group_orgs(client, sharing_group_id)
            if not group["active"] or user["org_id"] not in group["org_ids"]:
                raise AnalysisError(
                    403, "recipient_unverifiable",
                    "Sharing-group recipients could not be verified.",
                )

        event, warnings = build_misp_event(
            request.package, distribution, sharing_group_id
        )
        created = misp_client.create_event(client, event)
        url = f"{settings.misp_url.rstrip('/')}/events/view/{created['id']}"
        misp_store.record_export({
            **base_audit, "event_id": created["id"],
            "event_uuid": created["uuid"], "event_url": url,
        })
        audit.record(
            "misp_created",
            {**base_audit, "event_uuid": created["uuid"],
             "attribute_count": len(event.attributes),
             "destination_allowed": True},
        )
        return MispCreateResponse(
            event_id=created["id"], event_uuid=created["uuid"], url=url,
            duplicate=False, warnings=warnings,
        )
    except AnalysisError as exc:
        audit.record(
            "misp_rejected",
            {**base_audit, "code": exc.code, "reason": exc.message},
        )
        raise


def publish_draft(
    settings: Settings, request: MispPublishRequest, actor: str
) -> MispPublishResponse:
    """Publish a ThreatLens-created event. Separate explicit action.

    `actor` is the server-derived session identity; the client label is ignored.
    """
    base_audit: dict[str, Any] = {
        "analyst": actor, "event_uuid": request.event_uuid,
        "url": settings.misp_url,
    }
    try:
        _check_approval(request.approval, "publishing")
        record = misp_store.find_by_uuid(request.event_uuid)
        if record is None:
            raise AnalysisError(
                404, "unknown_event",
                "Only events created through ThreatLens can be published here.",
            )
        if record.get("status") == "published":
            audit.record("misp_publish_duplicate", base_audit)
            return MispPublishResponse(event_uuid=request.event_uuid, published=True)
        stored_distribution = record.get("distribution")
        stored_group = record.get("sharing_group_id")
        base_audit["distribution"] = stored_distribution
        base_audit["sharing_group_id"] = stored_group
        misp_client.require_configured(settings)

        # H-1: the approved destination must still be allowlisted — an
        # administrator may have revoked it after the draft was created.
        _require_allowlisted(settings, stored_distribution, stored_group)

        client = misp_client.build_client(settings)
        user = misp_client.current_user(client)
        if not user["perm_publish"]:
            raise AnalysisError(
                403, "permission_denied",
                "The MISP API user lacks permission to publish events.",
            )

        # Re-verify the live event before releasing alerts. MISP may
        # serialize these fields as strings; anything unparseable or
        # different from the approved destination fails closed.
        node = misp_client.fetch_event(client, request.event_uuid)
        live_distribution = _as_int(node.get("distribution"))
        live_group = _as_int(node.get("sharing_group_id"))
        if record.get("tlp") == "TLP:RED" and live_distribution != 0:
            raise AnalysisError(
                403, "unsafe_destination",
                "TLP:RED event left 'Your organisation only'; refusing to publish.",
            )
        if (
            live_distribution is None
            or live_distribution != stored_distribution
            or (stored_distribution == 4 and live_group != stored_group)
        ):
            raise AnalysisError(
                403, "destination_changed",
                "The live event no longer matches its approved destination; "
                "refusing to publish.",
            )

        # Re-verify sharing-group recipients: membership may have changed
        # since the draft was created.
        if stored_distribution == 4 and stored_group is not None:
            group = misp_client.sharing_group_orgs(client, stored_group)
            if not group["active"] or user["org_id"] not in group["org_ids"]:
                raise AnalysisError(
                    403, "recipient_unverifiable",
                    "Sharing-group recipients could not be re-verified.",
                )

        misp_client.publish_event(client, record["event_id"])
        misp_store.mark_published(request.event_uuid, actor)
        audit.record("misp_published", {**base_audit, "destination_allowed": True})
        return MispPublishResponse(event_uuid=request.event_uuid, published=True)
    except AnalysisError as exc:
        audit.record(
            "misp_publish_rejected",
            {**base_audit, "code": exc.code, "reason": exc.message},
        )
        raise

