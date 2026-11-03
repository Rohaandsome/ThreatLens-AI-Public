"""Thin PyMISP adapter: connection, API calls, and error mapping.

All MISP network I/O flows through these functions so tests can mock one
seam. The API key never appears in return values, logs, or error messages.
"""

import logging
from typing import Any
from urllib.parse import urlsplit

import requests
from pymisp import MISPEvent, PyMISP
from pymisp.exceptions import PyMISPError

from ..config import Settings
from ..errors import AnalysisError

logger = logging.getLogger("threatlens.misp")


def require_configured(settings: Settings) -> None:
    """Fail fast when MISP is not configured (before destination checks)."""
    if not settings.misp_url or not settings.misp_api_key:
        raise AnalysisError(
            503,
            "misp_not_configured",
            "MISP is not configured. Set MISP_URL and MISP_API_KEY in backend/.env.",
        )
    # SSRF guard: the MISP base URL comes only from backend env, and must
    # be http(s). No client-supplied URL is ever accepted (see schemas).
    scheme = urlsplit(settings.misp_url.strip()).scheme.lower()
    if scheme not in ("http", "https"):
        raise AnalysisError(
            503,
            "misp_invalid_url",
            "MISP_URL must be an http(s) URL. Check backend/.env.",
        )


def build_client(settings: Settings) -> PyMISP:
    """Construct the PyMISP client. Raises 503 when unconfigured."""
    require_configured(settings)
    return PyMISP(
        settings.misp_url,
        settings.misp_api_key,
        ssl=settings.misp_verify_ssl,
        timeout=settings.misp_timeout_seconds,
        tool="ThreatLensAI",
    )


def map_error(exc: Exception, action: str) -> AnalysisError:
    """Map transport/SDK failures to structured API errors (no secrets)."""
    text = f"{type(exc).__name__}: {exc}"
    status = getattr(getattr(exc, "response", None), "status_code", None)
    blob = f"{status} {text}".lower()
    if isinstance(exc, requests.Timeout):
        return AnalysisError(504, "misp_timeout", f"MISP request timed out ({action}).")
    if isinstance(exc, requests.ConnectionError):
        return AnalysisError(
            502, "misp_unreachable", f"Could not reach the MISP server ({action})."
        )
    if status == 401 or "401" in blob or "unauthorized" in blob:
        return AnalysisError(
            503,
            "misp_auth_failed",
            "MISP authentication failed. Check MISP_URL and MISP_API_KEY.",
        )
    if status == 403 or "403" in blob or "forbidden" in blob:
        return AnalysisError(
            403, "permission_denied", f"MISP refused the request ({action})."
        )
    if status == 404 or "404" in blob:
        return AnalysisError(
            502, "misp_api_error", f"MISP object not found ({action})."
        )
    logger.warning("misp %s failed: %s", action, type(exc).__name__)
    return AnalysisError(502, "misp_api_error", f"MISP request failed ({action}).")


def _truthy(value: Any) -> bool:
    return value is True or value == 1 or value == "1"


def current_user(client: PyMISP) -> dict[str, Any]:
    """Fetch the API user's org/role/permissions. Raises mapped errors."""
    try:
        data = client.get_user("me")
    except Exception as exc:  # noqa: BLE001 - mapped below
        raise map_error(exc, "read current user") from exc
    if not isinstance(data, dict) or "User" not in data:
        raise AnalysisError(
            502, "misp_api_error", "Unexpected MISP user response."
        )
    user = data.get("User") or {}
    role = data.get("Role") or {}
    org = data.get("Organisation") or {}
    org_id = str(user.get("org_id", "") or org.get("id", ""))
    if not org_id:
        raise AnalysisError(
            502, "misp_api_error", "MISP user has no organisation; cannot verify recipients."
        )
    return {
        "org_id": org_id,
        "org_name": str(org.get("name", "") or user.get("org_id", "")),
        "role": str(role.get("name", "")),
        "perm_add": _truthy(role.get("perm_add")),
        "perm_publish": _truthy(role.get("perm_publish")),
    }


def sharing_group_orgs(client: PyMISP, group_id: int) -> dict[str, Any]:
    """Fetch a sharing group and its member org IDs. Raises mapped errors."""
    try:
        data = client.get_sharing_group(group_id)
    except Exception as exc:  # noqa: BLE001 - mapped below
        raise map_error(exc, "read sharing group") from exc
    group = (data.get("SharingGroup") or {}) if isinstance(data, dict) else {}
    if not group:
        raise AnalysisError(
            502, "misp_api_error", "Unexpected MISP sharing-group response."
        )
    org_ids: set[str] = set()
    for entry in data.get("Organisation") or []:
        if isinstance(entry, dict) and entry.get("id") is not None:
            org_ids.add(str(entry["id"]))
    for entry in data.get("SharingGroupOrg") or []:
        if isinstance(entry, dict) and entry.get("org_id") is not None:
            org_ids.add(str(entry["org_id"]))
    return {
        "id": group.get("id", group_id),
        "name": str(group.get("name", "")),
        "active": _truthy(group.get("active", True)),
        "org_ids": sorted(org_ids),
    }


def create_event(client: PyMISP, event: MISPEvent) -> dict[str, Any]:
    """Create the event (caller must set published=False). Returns id/uuid."""
    try:
        created = client.add_event(event)
    except Exception as exc:  # noqa: BLE001 - mapped below
        raise map_error(exc, "create event") from exc
    node = (created.get("Event") or {}) if isinstance(created, dict) else {}
    if not node.get("id") or not node.get("uuid"):
        raise AnalysisError(
            502, "misp_api_error", "MISP did not return the created event."
        )
    return {"id": node["id"], "uuid": node["uuid"]}


def fetch_event(client: PyMISP, uuid: str) -> dict[str, Any]:
    """Fetch an event by UUID. Returns the raw Event node."""
    try:
        data = client.get_event(uuid)
    except Exception as exc:  # noqa: BLE001 - mapped below
        raise map_error(exc, "read event") from exc
    node = (data.get("Event") or {}) if isinstance(data, dict) else {}
    if not node:
        raise AnalysisError(502, "misp_api_error", "MISP event not found.")
    return node


def publish_event(client: PyMISP, event_id: Any) -> None:
    """Publish an event (alerts off). Raises mapped errors."""
    try:
        client.publish(event_id, alert=False)
    except Exception as exc:  # noqa: BLE001 - mapped below
        raise map_error(exc, "publish event") from exc
