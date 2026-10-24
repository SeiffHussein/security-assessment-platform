"""
schemas.py - THE shared data format for the whole project.

Every scanner, the ML classifier, remediation and reporting exchange findings
as plain dictionaries produced by ``Finding.to_dict()`` (or ``new_finding()``).
Do NOT invent per-module finding formats. Do NOT change this file without
agreeing with the whole team first (see README > Collaboration rules).

Finding fields (all values are strings):

    Field           Type  Required  Default        Meaning
    --------------  ----  --------  -------------  ---------------------------------------------
    id              str   no        8-char hex     Unique identifier (auto-generated)
    target          str   yes       -              Hostname / IP / host the finding is about
    source          str   yes       -              Tool or module, e.g. "nmap", "nuclei",
                                                   "nikto", "lynis". Sample data MUST use
                                                   sample_source("nmap") -> "nmap (sample)"
    title           str   yes       -              Short name of the finding
    severity        str   no        "Info"         One of SEVERITIES (exact capitalisation)
    description     str   no        ""             Plain-language explanation
    evidence        str   no        ""             Supporting detail (port, URL, raw line...)
    ml_priority     str   no        ""             "" = not classified yet, otherwise one of
                                                   ML_PRIORITIES (set only by ml_classifier)
    recommendation  str   no        ""             Corrective action (set by remediation)

Rules:
* Modules ADD information (ml_priority, recommendation); they never remove or
  overwrite the original title, severity, description or evidence.
* Lists of findings are ``list[dict]``; an empty list means "nothing found".
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field, fields

# Allowed severities, ordered from most to least serious.
SEVERITIES: tuple[str, ...] = ("Critical", "High", "Medium", "Low", "Info")

# Numeric score per severity (used for sorting and as an ML feature).
SEVERITY_SCORES: dict[str, int] = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

# ML priority labels written into Finding.ml_priority by modules/ml_classifier.py.
#   P1 = fix immediately, P2 = fix soon, P3 = monitor / fix when convenient
ML_PRIORITIES: tuple[str, ...] = ("P1", "P2", "P3")

# Suffix that marks data that did NOT come from a real scan.
SAMPLE_SUFFIX = " (sample)"

# Common tool wording -> our severity. Used by normalize_severity().
_SEVERITY_ALIASES: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "warning": "Medium",      # Lynis warnings
    "low": "Low",
    "suggestion": "Low",      # Lynis suggestions
    "info": "Info",
    "informational": "Info",
    "information": "Info",
    "unknown": "Info",
    "none": "Info",
    "": "Info",
}


def normalize_severity(value: object) -> str:
    """Map any tool's severity wording to one of SEVERITIES.

    Args:
        value: e.g. "high", "HIGH", "informational", "warning", None.

    Returns:
        One of SEVERITIES. Unrecognised values become "Info" (never raises).
    """
    text = str(value or "").strip().lower()
    return _SEVERITY_ALIASES.get(text, "Info")


def sample_source(tool: str) -> str:
    """Return the source label for sample/mock data, e.g. "nmap" -> "nmap (sample)"."""
    return f"{tool}{SAMPLE_SUFFIX}"


def is_sample(finding: dict) -> bool:
    """True if the finding is sample/mock data rather than a real scan result."""
    return str(finding.get("source", "")).endswith(SAMPLE_SUFFIX)


def _new_id() -> str:
    return uuid.uuid4().hex[:8]


@dataclass
class Finding:
    """One security finding in the shared project format. See module docstring."""

    target: str
    source: str
    title: str
    severity: str = "Info"
    description: str = ""
    evidence: str = ""
    ml_priority: str = ""
    recommendation: str = ""
    id: str = field(default_factory=_new_id)

    def __post_init__(self) -> None:
        # Accept "high"/"HIGH" etc. but reject anything that is not a real severity.
        matched = next((s for s in SEVERITIES if s.lower() == str(self.severity).strip().lower()), None)
        if matched is None:
            raise ValueError(
                f"Invalid severity {self.severity!r}; use one of {SEVERITIES} "
                "(tip: schemas.normalize_severity() converts tool wording)."
            )
        self.severity = matched
        if self.ml_priority not in ("",) + ML_PRIORITIES:
            raise ValueError(f"Invalid ml_priority {self.ml_priority!r}; use '' or one of {ML_PRIORITIES}.")
        for name in ("target", "source", "title"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"Finding.{name} must not be empty.")
        # Everything is stored as text so CSV/HTML/pandas behave predictably.
        for f in fields(self):
            setattr(self, f.name, str(getattr(self, f.name)))

    def to_dict(self) -> dict:
        """Return the finding as a plain dict with exactly FINDING_FIELDS as keys."""
        return asdict(self)


# Canonical field order (use this for CSV columns and tables).
FINDING_FIELDS: tuple[str, ...] = (
    "id", "target", "source", "title", "severity",
    "description", "evidence", "ml_priority", "recommendation",
)


def new_finding(target: str, source: str, title: str, **optional: str) -> dict:
    """Convenience helper: build a validated finding dict in one call.

    Example:
        new_finding("10.0.0.5", "nmap", "Open port 22/tcp (ssh)",
                    severity="Info", evidence="22/tcp open ssh OpenSSH 8.9")

    Raises:
        ValueError: if severity/ml_priority is invalid or a required field is empty.
        TypeError: if an unknown field name is passed.
    """
    return Finding(target=target, source=source, title=title, **optional).to_dict()


def validate_finding(finding: dict) -> dict:
    """Check that a dict follows the shared format and return a cleaned copy.

    Missing optional fields get their defaults; unknown keys are rejected.

    Raises:
        ValueError / TypeError: if the dict does not fit the format.
    """
    unknown = set(finding) - set(FINDING_FIELDS)
    if unknown:
        raise TypeError(f"Unknown finding field(s): {sorted(unknown)}")
    return Finding(**finding).to_dict()


def sort_by_severity(findings: list[dict]) -> list[dict]:
    """Return findings sorted Critical -> Info (stable; does not modify the input)."""
    return sorted(findings, key=lambda f: -SEVERITY_SCORES.get(f.get("severity", "Info"), 0))
