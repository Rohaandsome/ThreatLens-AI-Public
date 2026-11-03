"""Persistent record of MISP exports for idempotency (local JSON file).

Before creating a MISP event, callers check find_export(): a repeated request
for the same package + destination returns the stored record instead of
creating a duplicate event. Override the path in tests with
THREATLENS_MISP_STORE.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent


def store_path() -> Path:
    override = os.environ.get("THREATLENS_MISP_STORE")
    if override:
        return Path(override)
    return BACKEND_DIR / "data" / "misp_exports.json"


def _read() -> dict[str, Any]:
    path = store_path()
    if not path.exists():
        return {"exports": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("exports"), list):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"exports": []}


def _write(data: dict[str, Any]) -> None:
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")


def find_export(
    package_id: str, misp_url: str, distribution: int, sharing_group_id: int | None
) -> dict[str, Any] | None:
    for entry in _read()["exports"]:
        if (
            entry.get("package_id") == package_id
            and entry.get("url") == misp_url
            and entry.get("distribution") == distribution
            and entry.get("sharing_group_id") == sharing_group_id
        ):
            return entry
    return None


def find_by_uuid(event_uuid: str) -> dict[str, Any] | None:
    for entry in _read()["exports"]:
        if entry.get("event_uuid") == event_uuid:
            return entry
    return None


def record_export(entry: dict[str, Any]) -> dict[str, Any]:
    data = _read()
    stored = {
        **entry,
        "status": "draft",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    data["exports"].append(stored)
    _write(data)
    return stored


def mark_published(event_uuid: str, analyst: str) -> dict[str, Any] | None:
    data = _read()
    for entry in data["exports"]:
        if entry.get("event_uuid") == event_uuid:
            entry["status"] = "published"
            entry["published_at"] = datetime.now(timezone.utc).isoformat()
            entry["published_by"] = analyst
            _write(data)
            return entry
    return None
