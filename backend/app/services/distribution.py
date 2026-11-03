"""Distribution state machine (status transitions + who may perform them).

States flow pending_review -> approved -> exported/draft -> published, with
failed/denied/cancelled as terminal or requeue states. transition() takes an
explicit, already-resolved Role (see authz.resolve_role) so the machine itself
is pure and unit-testable; the HTTP layer always resolves anonymous today, so
live transitions deny before mutating anything. No external distribution
request is ever made from this module.
"""

from datetime import datetime, timezone
from typing import Any

from ..errors import AnalysisError
from . import authz, history_store

# current status -> {target status: minimum role}
TRANSITIONS: dict[str, dict[str, authz.Role]] = {
    "pending_review": {
        "approved": authz.Role.analyst,
        "denied": authz.Role.analyst,
        "cancelled": authz.Role.analyst,
    },
    "approved": {
        "exported": authz.Role.analyst,
        "draft": authz.Role.analyst,
        "cancelled": authz.Role.analyst,
    },
    "exported": {},
    "draft": {
        "published": authz.Role.administrator,
        "failed": authz.Role.analyst,
        "cancelled": authz.Role.analyst,
    },
    "published": {},
    "failed": {
        "approved": authz.Role.analyst,
        "cancelled": authz.Role.analyst,
    },
    "denied": {},
    "cancelled": {},
}

TERMINAL = ("exported", "published", "denied", "cancelled")


def allowed_targets(status: str, role: authz.Role) -> list[str]:
    """Targets reachable from a status with at least the given role."""
    return [
        target
        for target, minimum in TRANSITIONS.get(status, {}).items()
        if role >= minimum
    ]


def transition(
    record: dict[str, Any],
    target: str,
    role: authz.Role,
    *,
    now: str | None = None,
    misp_event_uuid: str | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """Validate role + edge, persist, and return the updated record."""
    if target not in history_store.STATUSES:
        raise AnalysisError(422, "invalid_status", f"Unknown status '{target}'.")
    current = record["status"]
    minimum = TRANSITIONS.get(current, {}).get(target)
    if minimum is None:
        raise AnalysisError(
            422,
            "illegal_transition",
            f"Cannot move a '{current}' record to '{target}'.",
        )
    authz.require_role_for(role, minimum, f"transition to '{target}'")
    stamp = now or datetime.now(timezone.utc).isoformat()
    updated = history_store.set_status(
        record["id"],
        target,
        approved_at=stamp if target == "approved" else None,
        misp_event_uuid=misp_event_uuid,
        error=error if target in ("failed", "denied") else None,
        updated_at=stamp,
    )
    if updated is None:  # pragma: no cover - record existed moments ago
        raise AnalysisError(404, "unknown_record", "Distribution record not found.")
    return updated


def send_target(record: dict[str, Any]) -> str:
    """Where 'send' moves an approved record, by destination kind."""
    if record["status"] != "approved":
        raise AnalysisError(
            422, "illegal_transition",
            f"Cannot send a '{record['status']}' record; approve it first.",
        )
    if record["destination_kind"] == "misp":
        return "draft"  # unpublished draft; publishing stays a separate action
    return "exported"
