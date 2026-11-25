"""Plain data types shared across the package."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from log_analyzer.errors import InputValidationError

LEVEL_RANK: dict[str, int] = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}

_ALIASES: dict[str, str] = {
    "DEBUG": "DEBUG",
    "TRACE": "DEBUG",
    "INFO": "INFO",
    "NOTICE": "INFO",
    "WARN": "WARNING",
    "WARNING": "WARNING",
    "ERR": "ERROR",
    "ERROR": "ERROR",
    "SEVERE": "ERROR",
    "CRIT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "FATAL": "CRITICAL",
    "ALERT": "CRITICAL",
    "EMERG": "CRITICAL",
}


def normalize_level(text: str) -> str | None:
    """Map a level word such as ``warn`` or ``FATAL`` to one of the five standard levels."""
    return _ALIASES.get(text.strip().upper())


def levels_at_least(level: str) -> list[str]:
    """Every standard level at or above ``level``. Unparsed ("UNKNOWN") entries are never included."""
    normalized = normalize_level(level)
    if normalized is None:
        raise InputValidationError(f"unknown level {level!r}; use one of {', '.join(LEVEL_RANK)}")
    floor = LEVEL_RANK[normalized]
    return [name for name, rank in LEVEL_RANK.items() if rank >= floor]


@dataclass(frozen=True)
class LogEntry:
    """One logical log record. A multi-line record (such as a stack trace) is one entry."""

    line_no: int
    timestamp: datetime | None  # naive, normalised to UTC
    level: str
    source: str
    message: str
    raw: str


@dataclass(frozen=True)
class AnalyzedEntry:
    entry: LogEntry
    fingerprint: str
    category: str
    template: str


@dataclass(frozen=True)
class StoredEntry:
    id: int
    line_no: int
    timestamp: str | None
    level: str
    source: str
    message: str
    category: str
    fingerprint: str

    @property
    def ts_text(self) -> str:
        return self.timestamp.replace("T", " ") if self.timestamp else "(no timestamp)"

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "line_no": self.line_no,
            "timestamp": self.timestamp,
            "level": self.level,
            "source": self.source,
            "message": self.message,
            "category": self.category,
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True)
class ErrorGroup:
    fingerprint: str
    count: int
    level: str  # the highest level seen in the group
    category: str
    template: str
    first_seen: str | None
    last_seen: str | None
    sample: str

    def to_dict(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "count": self.count,
            "level": self.level,
            "category": self.category,
            "template": self.template,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "sample": self.sample,
        }


@dataclass(frozen=True)
class Filters:
    """Search criteria. ``since`` is inclusive and ``until`` is exclusive."""

    min_level: str | None = None
    source: str | None = None
    category: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    text: str | None = None
    fingerprint: str | None = None


@dataclass(frozen=True)
class IngestResult:
    name: str
    sha256: str
    skipped: bool
    entries: int
    lines: int
    continuation_lines: int
