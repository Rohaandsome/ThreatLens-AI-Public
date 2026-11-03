"""FIRST TLP 2.0 traffic-light markings: parsing, ordering, audience rules.

Public standard only. Designations from most to least restrictive:
TLP:RED > TLP:AMBER+STRICT > TLP:AMBER > TLP:GREEN > TLP:CLEAR.
"""

CANONICAL_MARKINGS: tuple[str, ...] = (
    "TLP:RED",
    "TLP:AMBER+STRICT",
    "TLP:AMBER",
    "TLP:GREEN",
    "TLP:CLEAR",
)

_LEVELS: dict[str, int] = {
    "TLP:RED": 4,
    "TLP:AMBER+STRICT": 3,
    "TLP:AMBER": 2,
    "TLP:GREEN": 1,
    "TLP:CLEAR": 0,
}

_AUDIENCE: dict[str, str] = {
    "TLP:RED": (
        "Restricted to named recipients present. Recipients must not share "
        "TLP:RED information with any other parties."
    ),
    "TLP:AMBER+STRICT": (
        "Restricted to the recipient's organization only, on a need-to-know "
        "basis. No sharing with clients or outside parties."
    ),
    "TLP:AMBER": (
        "Limited disclosure: the recipient's organization and its clients, "
        "on a need-to-know basis."
    ),
    "TLP:GREEN": (
        "Limited disclosure: the trusted community (for example peer CSIRTs "
        "and ISACs). Do not publish publicly."
    ),
    "TLP:CLEAR": "May be distributed without restriction (subject to copyright).",
}


class InvalidMarkingError(ValueError):
    """Raised when a string is not a valid TLP 2.0 designation."""


def parse_marking(raw: str) -> str:
    """Normalize user input to a canonical marking (e.g. "amber" -> "TLP:AMBER").

    Raises InvalidMarkingError for anything outside the five designations.
    """
    normalized = "".join((raw or "").split()).upper()
    if normalized.startswith("TLP:"):
        normalized = normalized[len("TLP:") :]
    candidate = f"TLP:{normalized}"
    if candidate not in _LEVELS:
        raise InvalidMarkingError(f"Not a TLP 2.0 designation: {raw!r}")
    return candidate


def level(marking: str) -> int:
    """Restrictiveness level (higher = more restrictive)."""
    return _LEVELS[parse_marking(marking)]


def most_restrictive(markings: list[str]) -> str:
    """Conservative combination: the single most restrictive marking."""
    if not markings:
        raise ValueError("most_restrictive requires at least one marking")
    return max((parse_marking(m) for m in markings), key=_LEVELS.__getitem__)


def is_downgrade(source: str, proposed: str) -> bool:
    """True when the proposed marking is less restrictive than the source."""
    return level(proposed) < level(source)


def audience(marking: str) -> str:
    """Permitted-audience description for a canonical marking."""
    return _AUDIENCE[parse_marking(marking)]
