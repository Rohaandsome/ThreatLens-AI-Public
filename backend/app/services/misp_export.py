"""Map approved share packages to MISP events (no network I/O here).

Only package content (already selected and redacted) is mapped — never the
raw analysis. Attribute distribution is deliberately never set, so every
attribute inherits the event distribution. TLP is expressed as event tags;
numeric distribution always comes from the analyst's explicit destination
choice, never from the TLP marking.
"""

import json
import re
from typing import Any

from pymisp import MISPEvent

from ..errors import AnalysisError
from ..schemas import SharePrepareResponse
from . import tlp as tlp_rules
from .stix_export import (
    classify_mitre_id,
    classify_system,
    ioc_to_pattern,
    load_attack_data,
)

TLP_TAGS = {
    "TLP:RED": "tlp:red",
    "TLP:AMBER+STRICT": "tlp:amber+strict",
    "TLP:AMBER": "tlp:amber",
    "TLP:GREEN": "tlp:green",
    "TLP:CLEAR": "tlp:clear",
}

DISTRIBUTION_LABELS = {
    0: "Your organisation only",
    1: "This community only",
    2: "Connected communities",
    3: "All communities",
    4: "Sharing group",
}

_MISP_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
_MISP_IOC_TYPES = {
    "ip": "ip-dst",
    "domain": "domain",
    "url": "url",
    "email": "email-src",
    "filename": "filename",
}
_MISP_IOC_CATEGORIES = {
    "ip": "Network activity",
    "domain": "Network activity",
    "url": "Network activity",
    "hash": "Payload delivery",
    "email": "Payload delivery",
    "filename": "Payload delivery",
}


def validate_destination(distribution: Any, sharing_group_id: Any) -> tuple[int, int | None]:
    """Validate an explicit destination choice. Returns (distribution, group)."""
    if not isinstance(distribution, int) or isinstance(distribution, bool):
        raise AnalysisError(400, "invalid_destination", "Distribution must be 0-4.")
    if distribution not in DISTRIBUTION_LABELS:
        raise AnalysisError(400, "invalid_destination", "Distribution must be 0-4.")
    if distribution == 4:
        if not isinstance(sharing_group_id, int) or isinstance(sharing_group_id, bool):
            raise AnalysisError(
                400, "invalid_destination", "Sharing-group distribution needs a group ID."
            )
        if sharing_group_id <= 0:
            raise AnalysisError(
                400, "invalid_destination", "Sharing-group ID must be positive."
            )
        return distribution, sharing_group_id
    return distribution, None


def _misp_hash_type(value: str) -> str | None:
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        return _MISP_HASH_TYPES.get(len(value))
    return None


def _evidence_comment(*parts: str) -> str:
    return " — ".join(p.strip() for p in parts if p and p.strip())


def build_misp_event(
    package: SharePrepareResponse,
    distribution: int,
    sharing_group_id: int | None,
) -> tuple[MISPEvent, list[str]]:
    """Build an unpublished MISP event from a package. Returns (event, warnings)."""
    try:
        designation = tlp_rules.parse_marking(package.classification.proposed)
    except (tlp_rules.InvalidMarkingError, ValueError, AttributeError, TypeError) as exc:
        raise AnalysisError(
            400, "invalid_tlp", "Package carries an invalid TLP marking."
        ) from exc
    content = package.content
    warnings: list[str] = []
    event = MISPEvent()
    filename = (package.source_filename or "shared-report")[:120]
    event.info = f"[ThreatLens] {filename} [{designation}]"[:240]
    event.distribution = distribution
    if distribution == 4 and sharing_group_id is not None:
        event.sharing_group_id = sharing_group_id
    event.threat_level_id = 4  # Undefined: no overall severity asserted
    event.analysis = 2  # Completed analysis
    event.published = False  # Drafts only; publishing is a separate action

    event.add_tag(TLP_TAGS[designation])

    # MITRE techniques as galaxy tags (validated IDs only).
    for tech in content.attack_techniques:
        status, entry = classify_mitre_id(tech.mitre_id)
        if status != "valid" or entry is None:
            warnings.append(
                f"Technique '{tech.name}' skipped: MITRE ID "
                f"'{tech.mitre_id}' is {status} per the vendored ATT&CK dataset."
            )
            continue
        event.add_tag(
            f"misp-galaxy:mitre-attack-pattern=\"{entry['name']} - "
            f"{(tech.mitre_id or '').strip().upper()}\""
        )

    # IOCs.
    for item in content.indicators_of_compromise:
        _, problem = ioc_to_pattern(item)
        if problem is not None:
            warnings.append(
                f"IOC '{item.value}' skipped ({problem}): "
                + (
                    "value is not a well-formed indicator"
                    if problem == "malformed"
                    else f"artifact type '{item.type}' has no MISP mapping"
                )
                + "."
            )
            continue
        if item.type == "hash":
            misp_type = _misp_hash_type(item.value.strip())
        else:
            misp_type = _MISP_IOC_TYPES.get(item.type)
        if misp_type is None:  # pragma: no cover - guarded by ioc_to_pattern
            warnings.append(f"IOC '{item.value}' skipped (unsupported).")
            continue
        caveat = ""
        if item.type == "ip":
            caveat = "direction not specified by source"
        elif item.type == "email":
            caveat = "role not specified by source"
        if not item.verified_in_source:
            caveat = f"UNVERIFIED lead{(('; ' + caveat) if caveat else '')}"
        event.add_attribute(
            type=misp_type,
            value=item.value.strip(),
            category=_MISP_IOC_CATEGORIES[item.type],
            to_ids=bool(item.verified_in_source),
            comment=_evidence_comment(item.context, item.evidence_quote, caveat),
        )

    # CVEs (verified only).
    for cve in content.cves:
        if not cve.verified_in_source:
            warnings.append(f"CVE '{cve.id}' skipped: not found in the report text.")
            continue
        event.add_attribute(
            type="vulnerability",
            value=cve.id,
            category="External analysis",
            to_ids=False,
            comment=_evidence_comment(cve.description, cve.evidence_quote),
        )

    # Affected systems (asset tags, not asserted hostnames).
    for system in content.affected_systems:
        status = classify_system(system)
        event.add_attribute(
            type="text",
            value=system.system,
            category="Other",
            to_ids=False,
            comment=_evidence_comment(
                f"affected system ({status})", system.detail, system.evidence_quote
            ),
        )

    # Free-text findings.
    if content.executive_summary:
        event.add_attribute(
            type="text",
            value=content.executive_summary,
            category="Other",
            to_ids=False,
            comment="ThreatLens executive summary",
        )
    for e in content.supporting_evidence:
        event.add_attribute(
            type="text",
            value=e.quote,
            category="Other",
            to_ids=False,
            comment=_evidence_comment("supporting evidence", e.relevance),
        )
    for r in content.recommendations:
        event.add_attribute(
            type="text",
            value=r.recommendation,
            category="Other",
            to_ids=False,
            comment=_evidence_comment(f"priority: {r.priority}", r.rationale),
        )
    if package.analyst_notes.strip():
        event.add_attribute(
            type="text",
            value=package.analyst_notes.strip(),
            category="Other",
            to_ids=False,
            comment="Analyst notes",
        )
    event.add_attribute(
        type="text",
        value=f"Source file: {package.source_filename or 'unknown'} "
        f"(ThreatLens AI, model {package.model or 'unknown'}; "
        f"package {package.package_id[:12]})",
        category="Other",
        to_ids=False,
        comment="Source attribution and sharing reference",
    )
    return event, warnings


def event_preview_dict(event: MISPEvent) -> dict[str, Any]:
    """Normalize a MISPEvent to a plain dict for API responses."""
    # to_json() fully serializes nested attributes/tags; to_dict() does not.
    raw = json.loads(event.to_json())
    node = raw.get("Event", raw) if isinstance(raw, dict) else {}
    attributes = node.get("Attribute", []) or []
    tags = []
    for tag in node.get("Tag", []) or []:
        if isinstance(tag, dict) and tag.get("name"):
            tags.append(tag["name"])
        elif isinstance(tag, str):
            tags.append(tag)
    def _as_int(value: Any) -> Any:
        try:
            return int(value)
        except (TypeError, ValueError):
            return value

    return {
        "info": node.get("info", ""),
        "distribution": _as_int(node.get("distribution", 0)),
        "sharing_group_id": _as_int(node.get("sharing_group_id")),
        "threat_level_id": _as_int(node.get("threat_level_id")),
        "analysis": _as_int(node.get("analysis")),
        "published": node.get("published", False),
        "tags": tags,
        "attributes": [
            {
                "type": a.get("type"),
                "value": a.get("value"),
                "category": a.get("category"),
                "to_ids": a.get("to_ids"),
                "comment": a.get("comment", ""),
            }
            for a in attributes
            if isinstance(a, dict)
        ],
    }


def load_attack_names() -> dict[str, str]:
    """Official technique names (for preview display)."""
    return {
        tid: entry["name"] for tid, entry in load_attack_data()["techniques"].items()
    }
