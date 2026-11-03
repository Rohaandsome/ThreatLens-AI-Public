"""Append-only JSONL audit log for the sharing workflow.

Records classification assertions, prepared packages, and rejected attempts.
Entries carry metadata only (analyst, markings, counts, reasons) — never
report content or secrets. Override the path in tests with THREATLENS_AUDIT_LOG.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent


def log_path() -> Path:
    override = os.environ.get("THREATLENS_AUDIT_LOG")
    if override:
        return Path(override)
    return BACKEND_DIR / "audit" / "audit.log"


def record(event: str, details: dict[str, Any]) -> dict[str, Any]:
    """Append one audit record; returns the record (with id and timestamp)."""
    path = log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "id": uuid4().hex,
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **details,
    }
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def read_events(
    *,
    event: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Read audit events newest-first. Malformed lines are skipped, never fixed.

    There is intentionally no update or delete API: the log is append-only and
    ordinary users cannot edit it through the application.
    """
    path = log_path()
    if not path.exists():
        return [], 0
    events: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict) or "event" not in entry:
                continue
            if event and entry.get("event") != event:
                continue
            ts = str(entry.get("ts", ""))
            if since and ts < since:
                continue
            if until and ts > until:
                continue
            events.append(entry)
    events.reverse()
    total = len(events)
    start = max(offset, 0)
    return events[start : start + max(limit, 0)], total
