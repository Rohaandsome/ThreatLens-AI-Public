"""SQLite-backed distribution history (MVP persistence).

Each record tracks one reviewed package's path toward its recipients: report
ID, TLP classification, destination, approved-finding counts (never bodies),
approval timestamp, delivery status, and MISP event UUID when applicable.

No authentication exists yet, so this store currently holds clearly-labelled
DEMONSTRATION seeds (is_demo=1) only; live recording unlocks with login (see
authz.py). Override the path in tests with THREATLENS_HISTORY_DB.
"""

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent

STATUSES = (
    "pending_review",
    "approved",
    "exported",
    "draft",
    "published",
    "failed",
    "denied",
    "cancelled",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS distribution_records (
    id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL,
    package_id TEXT NOT NULL,
    classification TEXT NOT NULL,
    destination_kind TEXT NOT NULL,
    destination_label TEXT NOT NULL,
    destination_detail TEXT NOT NULL,
    findings TEXT NOT NULL,
    analyst TEXT NOT NULL,
    approved_at TEXT,
    status TEXT NOT NULL,
    misp_event_uuid TEXT,
    error TEXT,
    is_demo INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)
"""

# Synthetic demonstration rows. Every value is fictional (TEST-NET IPs live
# only in the audit-free findings COUNTS here — no report bodies, no secrets).
_DEMO_SEEDS: list[dict[str, Any]] = [
    {
        "id": "demo-001", "report_id": "synthetic_ics_report.txt",
        "package_id": "demo-pkg-0001", "classification": "TLP:AMBER",
        "destination_kind": "misp", "destination_label": "Energy ISAC sharing group",
        "destination_detail": {"distribution": 4, "sharing_group_id": 7},
        "findings": {"iocs": 2, "cves": 1, "techniques": 2, "systems": 2},
        "analyst": "demo-operator-1", "approved_at": "2026-10-28T14:02:00+00:00",
        "status": "published", "misp_event_uuid": "11111111-1111-4111-8111-111111111111",
        "error": None, "created_at": "2026-10-28T13:55:00+00:00",
    },
    {
        "id": "demo-002", "report_id": "synthetic_substation_probe.txt",
        "package_id": "demo-pkg-0002", "classification": "TLP:GREEN",
        "destination_kind": "misp", "destination_label": "This community",
        "destination_detail": {"distribution": 1, "sharing_group_id": None},
        "findings": {"iocs": 3, "cves": 0, "techniques": 1, "systems": 1},
        "analyst": "demo-operator-2", "approved_at": "2026-10-29T09:20:00+00:00",
        "status": "draft", "misp_event_uuid": "22222222-2222-4222-8222-222222222222",
        "error": None, "created_at": "2026-10-29T09:12:00+00:00",
    },
    {
        "id": "demo-003", "report_id": "synthetic_turbine_maintenance.txt",
        "package_id": "demo-pkg-0003", "classification": "TLP:CLEAR",
        "destination_kind": "pdf", "destination_label": "Public advisory subscribers",
        "destination_detail": {"format": "pdf"},
        "findings": {"iocs": 1, "cves": 1, "techniques": 1, "systems": 3},
        "analyst": "demo-operator-1", "approved_at": "2026-10-27T16:40:00+00:00",
        "status": "exported", "misp_event_uuid": None,
        "error": None, "created_at": "2026-10-27T16:30:00+00:00",
    },
    {
        "id": "demo-004", "report_id": "synthetic_vpn_telemetry.txt",
        "package_id": "demo-pkg-0004", "classification": "TLP:AMBER",
        "destination_kind": "stix", "destination_label": "Partner SOC feed",
        "destination_detail": {"format": "stix"},
        "findings": {"iocs": 5, "cves": 2, "techniques": 3, "systems": 2},
        "analyst": "demo-operator-2", "approved_at": "2026-10-30T11:05:00+00:00",
        "status": "exported", "misp_event_uuid": None,
        "error": None, "created_at": "2026-10-30T10:58:00+00:00",
    },
    {
        "id": "demo-005", "report_id": "synthetic_historian_access.txt",
        "package_id": "demo-pkg-0005", "classification": "TLP:RED",
        "destination_kind": "misp", "destination_label": "Your organisation only",
        "destination_detail": {"distribution": 0, "sharing_group_id": None},
        "findings": {"iocs": 2, "cves": 0, "techniques": 2, "systems": 1},
        "analyst": "demo-operator-1", "approved_at": "2026-10-30T15:44:00+00:00",
        "status": "approved", "misp_event_uuid": None,
        "error": None, "created_at": "2026-10-30T15:30:00+00:00",
    },
    {
        "id": "demo-006", "report_id": "synthetic_relay_firmware.txt",
        "package_id": "demo-pkg-0006", "classification": "TLP:AMBER+STRICT",
        "destination_kind": "misp", "destination_label": "Your organisation only",
        "destination_detail": {"distribution": 0, "sharing_group_id": None},
        "findings": {"iocs": 1, "cves": 1, "techniques": 1, "systems": 4},
        "analyst": "demo-operator-3", "approved_at": None,
        "status": "pending_review", "misp_event_uuid": None,
        "error": None, "created_at": "2026-10-31T08:02:00+00:00",
    },
    {
        "id": "demo-007", "report_id": "synthetic_scada_incident.txt",
        "package_id": "demo-pkg-0007", "classification": "TLP:AMBER",
        "destination_kind": "pdf", "destination_label": "Internal review board",
        "destination_detail": {"format": "pdf"},
        "findings": {"iocs": 0, "cves": 1, "techniques": 2, "systems": 2},
        "analyst": "demo-operator-3", "approved_at": None,
        "status": "pending_review", "misp_event_uuid": None,
        "error": None, "created_at": "2026-10-31T09:15:00+00:00",
    },
    {
        "id": "demo-008", "report_id": "synthetic_ics_report.txt",
        "package_id": "demo-pkg-0008", "classification": "TLP:GREEN",
        "destination_kind": "misp", "destination_label": "Connected communities",
        "destination_detail": {"distribution": 2, "sharing_group_id": None},
        "findings": {"iocs": 4, "cves": 1, "techniques": 2, "systems": 1},
        "analyst": "demo-operator-2", "approved_at": "2026-10-26T10:00:00+00:00",
        "status": "failed", "misp_event_uuid": None,
        "error": "MISP request timed out (create event).",
        "created_at": "2026-10-26T09:50:00+00:00",
    },
    {
        "id": "demo-009", "report_id": "synthetic_vendor_advisory.txt",
        "package_id": "demo-pkg-0009", "classification": "TLP:RED",
        "destination_kind": "misp", "destination_label": "All communities",
        "destination_detail": {"distribution": 3, "sharing_group_id": None},
        "findings": {"iocs": 2, "cves": 0, "techniques": 1, "systems": 1},
        "analyst": "demo-operator-1", "approved_at": None,
        "status": "denied", "misp_event_uuid": None,
        "error": "TLP:RED may only use 'Your organisation only'.",
        "created_at": "2026-10-25T12:00:00+00:00",
    },
    {
        "id": "demo-010", "report_id": "synthetic_grid_sensor.txt",
        "package_id": "demo-pkg-0010", "classification": "TLP:GREEN",
        "destination_kind": "stix", "destination_label": "Partner SOC feed",
        "destination_detail": {"format": "stix"},
        "findings": {"iocs": 2, "cves": 0, "techniques": 1, "systems": 2},
        "analyst": "demo-operator-2", "approved_at": "2026-10-24T09:30:00+00:00",
        "status": "approved", "misp_event_uuid": None,
        "error": None, "created_at": "2026-10-24T09:20:00+00:00",
    },
]


def db_path() -> Path:
    override = os.environ.get("THREATLENS_HISTORY_DB")
    if override:
        return Path(override)
    return BACKEND_DIR / "data" / "history.db"


def _connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create schema and idempotently seed demonstration records."""
    conn = _connect()
    try:
        conn.execute(_SCHEMA)
        for seed in _DEMO_SEEDS:
            conn.execute(
                """
                INSERT OR IGNORE INTO distribution_records
                (id, report_id, package_id, classification, destination_kind,
                 destination_label, destination_detail, findings, analyst,
                 approved_at, status, misp_event_uuid, error, is_demo,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    seed["id"], seed["report_id"], seed["package_id"],
                    seed["classification"], seed["destination_kind"],
                    seed["destination_label"],
                    json.dumps(seed["destination_detail"], sort_keys=True),
                    json.dumps(seed["findings"], sort_keys=True),
                    seed["analyst"], seed["approved_at"], seed["status"],
                    seed["misp_event_uuid"], seed["error"],
                    seed["created_at"], seed["created_at"],
                ),
            )
        conn.commit()
    finally:
        conn.close()


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "report_id": row["report_id"],
        "package_id": row["package_id"],
        "classification": row["classification"],
        "destination_kind": row["destination_kind"],
        "destination_label": row["destination_label"],
        "destination_detail": json.loads(row["destination_detail"]),
        "findings": json.loads(row["findings"]),
        "analyst": row["analyst"],
        "approved_at": row["approved_at"],
        "status": row["status"],
        "misp_event_uuid": row["misp_event_uuid"],
        "error": row["error"],
        "demo": bool(row["is_demo"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_records(
    *,
    status: str | None = None,
    classification: str | None = None,
    report: str | None = None,
    recipient: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Filter records; returns (rows newest-first, total count)."""
    init_db()
    clauses = ["1 = 1"]
    params: list[Any] = []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if classification:
        clauses.append("classification = ?")
        params.append(classification.upper())
    if report:
        clauses.append("report_id LIKE ?")
        params.append(f"%{report}%")
    if recipient:
        clauses.append("destination_label LIKE ?")
        params.append(f"%{recipient}%")
    if since:
        clauses.append("created_at >= ?")
        params.append(since)
    if until:
        clauses.append("created_at <= ?")
        params.append(until)
    where = " AND ".join(clauses)
    conn = _connect()
    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM distribution_records WHERE {where}", params
        ).fetchone()[0]
        rows = conn.execute(
            f"""SELECT * FROM distribution_records WHERE {where}
                ORDER BY created_at DESC LIMIT ? OFFSET ?""",
            [*params, max(limit, 0), max(offset, 0)],
        ).fetchall()
        return [_row_to_dict(r) for r in rows], total
    finally:
        conn.close()


def get_record(record_id: str) -> dict[str, Any] | None:
    init_db()
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM distribution_records WHERE id = ?", (record_id,)
        ).fetchone()
        return _row_to_dict(row) if row else None
    finally:
        conn.close()


def set_status(
    record_id: str,
    status: str,
    *,
    approved_at: str | None = None,
    misp_event_uuid: str | None = None,
    error: str | None = None,
    updated_at: str,
) -> dict[str, Any] | None:
    """Server-side-only status update (no direct API route; see distribution)."""
    if status not in STATUSES:
        raise ValueError(f"unknown status: {status}")
    init_db()
    conn = _connect()
    try:
        conn.execute(
            """UPDATE distribution_records
               SET status = ?, approved_at = COALESCE(?, approved_at),
                   misp_event_uuid = COALESCE(?, misp_event_uuid),
                   error = ?, updated_at = ?
               WHERE id = ?""",
            (status, approved_at, misp_event_uuid, error, updated_at, record_id),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM distribution_records WHERE id = ?", (record_id,)
        ).fetchone()
        return _row_to_dict(row) if row else None
    finally:
        conn.close()
