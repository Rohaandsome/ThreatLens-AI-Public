"""STIX 2.1 export for evidence-backed analysis results.

Converts an AnalyzeResponse into a STIX 2.1 Bundle using the stix2 library.
Principles:
- Only grounded content is exported. Unverifiable or malformed items are
  skipped with a conversion warning — never fabricated into STIX objects.
- MITRE ATT&CK IDs are validated against the vendored official dataset
  (backend/app/data/mitre_attack.json) before creating Attack Patterns.
- No object asserts more than the evidence supports: unverified IOCs become
  low-confidence Indicators (leads, not confirmed malicious), and
  technique-to-system links are report-level associations with an explicit
  caveat, not asserted pairings.
"""

import ipaddress
import json
import re
import urllib.parse
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

import stix2

from ..errors import AnalysisError
from ..schemas import (
    AffectedSystem,
    AnalyzeResponse,
    IOC,
    SharePrepareResponse,
)
from . import tlp as tlp_rules

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre_attack.json"

SystemClass = Literal["confirmed", "potentially-affected", "unaffected"]

_UNAFFECTED_PATTERNS = [
    r"\bno (evidence of |indication of )?compromise\b",
    r"\bnot (affected|compromised)\b",
    r"\bno malicious activity (found|detected|observed)\b",
    r"\bruled out\b",
]
_UNAFFECTED_RE = re.compile("|".join(_UNAFFECTED_PATTERNS), re.IGNORECASE)

_MITRE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

_HASH_ALGOS = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}

_CONFIDENCE_VERIFIED = 85
_CONFIDENCE_UNVERIFIED = 20
_CONFIDENCE_CONFIRMED_SYSTEM = 90
_CONFIDENCE_POTENTIAL_SYSTEM = 40
_CONFIDENCE_ASSOCIATION = 50


@lru_cache(maxsize=1)
def load_attack_data() -> dict[str, Any]:
    """Load the vendored MITRE ATT&CK reference (cached)."""
    try:
        data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalysisError(
            500, "stix_reference_missing", "MITRE reference dataset unavailable."
        ) from exc
    meta = data.get("metadata", {})
    if not meta.get("collection_version") or "techniques" not in data:
        raise AnalysisError(
            500, "stix_reference_missing", "MITRE reference dataset is invalid."
        )
    return data


def classify_mitre_id(
    mitre_id: str | None, dataset: dict[str, Any] | None = None
) -> tuple[str, dict[str, Any] | None]:
    """Validate a MITRE ID. Returns (status, technique-entry-or-None).

    Status is one of: valid, malformed, unknown, revoked.
    """
    normalized = (mitre_id or "").strip().upper()
    if not normalized or not _MITRE_ID_RE.match(normalized):
        return "malformed", None
    techniques = (dataset or load_attack_data())["techniques"]
    entry = techniques.get(normalized)
    if entry is None:
        return "unknown", None
    if entry.get("revoked"):
        return "revoked", entry
    return "valid", entry


def classify_system(entry: AffectedSystem) -> SystemClass:
    """Confirmed / potentially-affected / unaffected from model output only."""
    text = f"{entry.detail}\n{entry.evidence_quote}"
    if entry.inferred:
        return "potentially-affected"
    if _UNAFFECTED_RE.search(text):
        return "unaffected"
    if entry.evidence_quote.strip():
        return "confirmed"
    return "potentially-affected"


def _escape_pattern_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def ioc_to_pattern(ioc: IOC) -> tuple[str | None, str | None]:
    """Build a STIX pattern for an IOC. Returns (pattern, problem).

    problem is None on success, else "malformed" or "unsupported".
    """
    value = ioc.value.strip()
    if not value or re.search(r"[\x00-\x1f\x7f]", value):
        return None, "malformed"
    v = _escape_pattern_value(value)
    kind = ioc.type
    if kind == "ip":
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return None, "malformed"
        family = "ipv6-addr" if addr.version == 6 else "ipv4-addr"
        return f"[{family}:value = '{v}']", None
    if kind == "domain":
        if " " in value or "." not in value or len(value) > 253:
            return None, "malformed"
        return f"[domain-name:value = '{v}']", None
    if kind == "url":
        try:
            parts = urllib.parse.urlsplit(value)
        except ValueError:
            return None, "malformed"
        if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
            return None, "malformed"
        return f"[url:value = '{v}']", None
    if kind == "hash":
        algo = _HASH_ALGOS.get(len(value)) if re.fullmatch(r"[0-9a-fA-F]+", value) else None
        if algo is None:
            return None, "malformed"
        return f"[file:hashes.'{algo}' = '{v}']", None
    if kind == "email":
        if " " in value or value.count("@") != 1 or value.startswith("@") or value.endswith("@"):
            return None, "malformed"
        return f"[email-addr:value = '{v}']", None
    if kind == "filename":
        return f"[file:name = '{v}']", None
    return None, "unsupported"  # mutex, other: no STIX 2.1 artifact mapping


def _evidence_block(quote: str) -> str:
    quote = quote.strip()
    return f"\n\nEvidence (report excerpt): {quote}" if quote else ""


def _safe_download_stem(filename: str) -> str:
    stem = Path(filename).stem[:60].strip() or "report"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", stem)


def tlp_marking(designation: str) -> tuple[Any, str | None]:
    """STIX marking object for a TLP 2.0 designation. Returns (object, note).

    RED/GREEN/AMBER reuse the STIX predefined marking definitions. CLEAR maps
    to predefined WHITE (equivalent handling per FIRST TLP 2.0). AMBER+STRICT
    has no STIX predefined equivalent, so it becomes a statement marking that
    preserves the exact handling caveat.
    """
    if designation == "TLP:RED":
        return stix2.TLP_RED, None
    if designation == "TLP:GREEN":
        return stix2.TLP_GREEN, None
    if designation == "TLP:AMBER":
        return stix2.TLP_AMBER, None
    if designation == "TLP:CLEAR":
        return stix2.TLP_WHITE, (
            "TLP:CLEAR exported with the predefined STIX TLP:WHITE marking "
            "(equivalent handling: distribute without restriction)."
        )
    if designation == "TLP:AMBER+STRICT":
        marking = stix2.MarkingDefinition(
            definition_type="statement",
            definition=stix2.StatementMarking(
                statement=(
                    "TLP:AMBER+STRICT: restricted to the recipient's "
                    "organization only, on a need-to-know basis. No sharing "
                    "with clients or outside parties."
                )
            ),
        )
        return marking, (
            "TLP:AMBER+STRICT has no predefined STIX marking; exported as a "
            "statement marking preserving the exact handling caveat."
        )
    raise AnalysisError(400, "invalid_tlp", f"Invalid TLP marking: {designation!r}.")


def build_bundle(response: AnalyzeResponse) -> tuple[dict[str, Any], list[str], dict[str, int]]:
    """Build a validated STIX 2.1 bundle dict. Returns (bundle, warnings, counts)."""
    return _build(
        analysis=response.analysis,
        filename=response.filename,
        truncated=response.truncated,
        char_count=response.char_count,
        base_warnings=[f"analysis: {w}" for w in response.warnings],
        tlp_designation=None,
        analyst_notes="",
    )


def build_package_bundle(
    package: SharePrepareResponse,
) -> tuple[dict[str, Any], list[str], dict[str, int]]:
    """Build a bundle from an approved share package (already filtered/redacted)."""
    try:
        designation = tlp_rules.parse_marking(package.classification.proposed)
    except (tlp_rules.InvalidMarkingError, ValueError, AttributeError, TypeError) as exc:
        raise AnalysisError(
            400, "invalid_tlp", "Package carries an invalid TLP marking."
        ) from exc
    return _build(
        analysis=package.content,
        filename=package.source_filename or "shared-report",
        truncated=False,
        char_count=0,
        base_warnings=list(package.warnings),
        tlp_designation=designation,
        analyst_notes=package.analyst_notes,
    )


def _build(
    analysis: Any,
    filename: str,
    truncated: bool,
    char_count: int,
    base_warnings: list[str],
    tlp_designation: str | None,
    analyst_notes: str,
) -> tuple[dict[str, Any], list[str], dict[str, int]]:
    now = datetime.now(timezone.utc)
    warnings: list[str] = list(base_warnings)

    identity = stix2.Identity(
        name="ThreatLens AI",
        identity_class="system",
        description=(
            "AI threat-intelligence analysis platform for critical "
            "infrastructure. Objects below were derived from an AI analysis "
            "of a single uploaded report; verification status is recorded "
            "per object."
        ),
    )
    creator = identity.id
    objects: list[Any] = [identity]

    # TLP marking (package path only): referenced by every content object.
    markkw: dict[str, Any] = {}
    if tlp_designation is not None:
        marking, mapping_note = tlp_marking(tlp_designation)
        if mapping_note:
            warnings.append(mapping_note)
        objects.append(marking)
        markkw = {"object_marking_refs": [marking.id]}

    # Indicators (verified = confident; unverified = low-confidence lead).
    for item in analysis.indicators_of_compromise:
        pattern, problem = ioc_to_pattern(item)
        if pattern is None:
            warnings.append(
                f"IOC '{item.value}' skipped ({problem}): "
                + (
                    "value is not a well-formed indicator"
                    if problem == "malformed"
                    else f"artifact type '{item.type}' has no STIX 2.1 mapping"
                )
                + "."
            )
            continue
        verified = item.verified_in_source
        context = f" Context: {item.context.strip()}" if item.context.strip() else ""
        objects.append(
            stix2.Indicator(
                name=f"ThreatLens IOC ({item.type}): {item.value[:80]}",
                description=(
                    (
                        "Indicator extracted from the analyzed report and "
                        "verified verbatim against its text."
                        if verified
                        else "UNVERIFIED lead: this value was NOT found in the "
                        "report text and may be unreliable. Treat as a lead, "
                        "not a confirmed malicious indicator."
                    )
                    + context
                    + _evidence_block(item.evidence_quote)
                ),
                pattern=pattern,
                pattern_type="stix",
                valid_from=now,
                labels=["malicious-activity"] if verified else ["malicious-activity", "unverified"],
                confidence=_CONFIDENCE_VERIFIED if verified else _CONFIDENCE_UNVERIFIED,
                created_by_ref=creator,
                **markkw,
            )
        )

    # Vulnerabilities (verified only: an unverified CVE ID may be misinformation).
    for cve in analysis.cves:
        if not cve.verified_in_source:
            warnings.append(
                f"CVE '{cve.id}' skipped: not found in the report text."
            )
            continue
        objects.append(
            stix2.Vulnerability(
                name=cve.id,
                description=(cve.description.strip() + _evidence_block(cve.evidence_quote)).strip(),
                external_references=[{"source_name": "cve", "external_id": cve.id}],
                confidence=_CONFIDENCE_VERIFIED,
                created_by_ref=creator,
                **markkw,
            )
        )

    # Attack patterns (MITRE-validated only).
    attack_patterns: list[Any] = []
    for tech in analysis.attack_techniques:
        status, entry = classify_mitre_id(tech.mitre_id)
        if status != "valid" or entry is None:
            warnings.append(
                f"Technique '{tech.name}' skipped: MITRE ID "
                f"'{tech.mitre_id}' is {status} per the vendored ATT&CK dataset."
            )
            continue
        tactics = entry.get("tactics", [])
        objects.append(
            stix2.AttackPattern(
                name=entry["name"],
                description=(
                    tech.description.strip() + _evidence_block(tech.evidence_quote)
                ).strip(),
                external_references=[
                    {
                        "source_name": "mitre-attack",
                        "external_id": (tech.mitre_id or "").strip().upper(),
                        "url": entry.get("url"),
                    }
                ],
                kill_chain_phases=[
                    {"kill_chain_name": "mitre-attack", "phase_name": t} for t in tactics
                ],
                created_by_ref=creator,
                **markkw,
            )
        )
        attack_patterns.append(objects[-1])

    # Affected systems as Infrastructure with explicit classification.
    infrastructures: list[tuple[Any, SystemClass]] = []
    for entry in analysis.affected_systems:
        cls = classify_system(entry)
        label = {"confirmed": "compromised", "potentially-affected": "potentially-affected", "unaffected": "unaffected"}[cls]
        confidence = (
            _CONFIDENCE_CONFIRMED_SYSTEM
            if cls in ("confirmed", "unaffected")
            else _CONFIDENCE_POTENTIAL_SYSTEM
        )
        status_note = {
            "confirmed": "Status: confirmed affected (evidence-backed).",
            "potentially-affected": "Status: potentially affected (inferred or weakly evidenced).",
            "unaffected": "Status: unaffected per the report (explicitly cleared).",
        }[cls]
        objects.append(
            stix2.Infrastructure(
                name=entry.system[:200],
                description=(f"{status_note}\n\n{entry.detail.strip()}".strip() + _evidence_block(entry.evidence_quote)).strip(),
                labels=[label],
                confidence=confidence,
                created_by_ref=creator,
                **markkw,
            )
        )
        infrastructures.append((objects[-1], cls))

    # Report-level associations only: technique -> affected infrastructure,
    # with an explicit caveat. Unaffected systems get no relationships.
    for ap in attack_patterns:
        for infra, cls in infrastructures:
            if cls == "unaffected":
                continue
            objects.append(
                stix2.Relationship(
                    source_ref=ap.id,
                    target_ref=infra.id,
                    relationship_type="targets",
                    description=(
                        f"Report-level association from '{filename}': "
                        "technique and system co-occur in the same intrusion "
                        "report; a specific pairing is NOT asserted."
                    ),
                    confidence=_CONFIDENCE_ASSOCIATION,
                    created_by_ref=creator,
                **markkw,
                )
            )

    description = analysis.executive_summary.strip()
    if truncated:
        description += (
            f"\n\nNote: the source report ({char_count:,} chars) "
            "exceeded the analysis window; only the first portion was analyzed."
        )
    report = stix2.Report(
        name=f"Threat analysis: {filename[:150]}",
        description=description,
        published=now,
        # Marking definitions ride along in the bundle but must not be
        # report refs (STIX allows only SDO/SRO/SCO there).
        object_refs=[o.id for o in objects if o.type != "marking-definition"],
        labels=["threat-report"] + ([tlp_designation] if tlp_designation else []),
        external_references=[
            {
                "source_name": "threatlens-report",
                "description": f"Source file: {filename}",
            }
        ],
        created_by_ref=creator,
        **markkw,
    )
    objects.append(report)

    if analyst_notes.strip():
        analyst_note = stix2.Note(
            content=analyst_notes.strip()[:4000],
            object_refs=[report.id],
            created_by_ref=creator,
            **markkw,
        )
        objects.append(analyst_note)
        objects[-2] = report.new_version(
            object_refs=[*report.object_refs, analyst_note.id]
        )

    bundle = stix2.Bundle(objects=objects)
    serialized = bundle.serialize()
    try:
        stix2.parse(serialized)  # strict by default: no custom content
    except Exception as exc:
        raise AnalysisError(
            500, "stix_build_failed", "Built STIX bundle failed validation."
        ) from exc

    counts: dict[str, int] = {}
    for o in objects:
        counts[o.type] = counts.get(o.type, 0) + 1
    # De-duplicate warnings while preserving order.
    seen: set[str] = set()
    unique_warnings = [w for w in warnings if not (w in seen or seen.add(w))]
    return json.loads(serialized), unique_warnings, counts


def download_filename(source_filename: str) -> str:
    return f"threatlens-{_safe_download_stem(source_filename)}-{uuid4().hex[:8]}.stix.json"
