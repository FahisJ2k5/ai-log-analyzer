"""Turning raw log lines into structured entries.

Four formats are recognised: JSON lines, Python/``logging``-style text,
syslog, and web-server access logs (common and combined). A line that matches
none of them is treated as a *continuation* of the previous entry. This is what
keeps stack traces together as one record.

The parsers never raise on odd input; a test feeds them random text to prove it.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from log_analyzer.models import LogEntry, normalize_level
from log_analyzer.timeparse import build_datetime, parse_timestamp

MAX_MESSAGE_CHARS = 10_000

_MONTHS = {
    name: number
    for number, name in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1
    )
}


@dataclass(frozen=True)
class ParsedLine:
    timestamp: datetime | None
    level: str
    source: str
    message: str


ParseFn = Callable[[str, int], ParsedLine | None]


# --------------------------------------------------------------------- JSON

_MESSAGE_KEYS = ("message", "msg", "event", "text")
_LEVEL_KEYS = ("level", "severity", "levelname")
_SOURCE_KEYS = ("logger", "source", "service", "component", "module", "name")
_TIME_KEYS = ("timestamp", "time", "ts", "@timestamp", "asctime", "datetime")
_CAUSE_KEYS = ("error", "err")
_TRACE_KEYS = ("exception", "stack", "stacktrace", "traceback")


def _first_text(data: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _from_epoch(value: float) -> datetime | None:
    if value > 1e11:  # milliseconds
        value = value / 1000
    try:
        return datetime.fromtimestamp(value, timezone.utc).replace(tzinfo=None)
    except (OverflowError, OSError, ValueError):
        return None


def parse_json(line: str, year: int) -> ParsedLine | None:
    if not line.startswith("{"):
        return None
    try:
        data = json.loads(line)
    except (ValueError, RecursionError):
        return None
    if not isinstance(data, dict):
        return None

    message = _first_text(data, _MESSAGE_KEYS)
    if message is None:
        return None
    cause = _first_text(data, _CAUSE_KEYS)
    if cause is not None:
        message = f"{message}: {cause}"  # the cause belongs in the headline, so it affects grouping
    for key in _TRACE_KEYS:
        trace = data.get(key)
        if isinstance(trace, str) and trace.strip():
            message = f"{message}\n{trace.rstrip()}"
            break

    level_text = _first_text(data, _LEVEL_KEYS)
    level = (normalize_level(level_text) if level_text else None) or "UNKNOWN"

    timestamp: datetime | None = None
    for key in _TIME_KEYS:
        value = data.get(key)
        if isinstance(value, str):
            timestamp = parse_timestamp(value)
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            timestamp = _from_epoch(value)
        if timestamp is not None:
            break

    return ParsedLine(timestamp, level, _first_text(data, _SOURCE_KEYS) or "", message)


# ---------------------------------------------------------- Python / logging

_PYTHON = re.compile(
    r"^(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})[T ](?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
    r"(?:[.,]\d+)?(?P<tz>Z|[+-]\d{2}:?\d{2})?\s+"
    r"\[?(?P<level>[A-Za-z]+)\]?(?:\s+|$)"
    r"(?:(?P<source>[\w.\-/]+):(?:\s+|$))?(?P<message>.*)$"
)


def parse_python(line: str, year: int) -> ParsedLine | None:
    match = _PYTHON.match(line)
    if match is None:
        return None
    level = normalize_level(match.group("level"))
    if level is None:
        return None
    moment = build_datetime(
        int(match.group("y")),
        int(match.group("mo")),
        int(match.group("d")),
        int(match.group("h")),
        int(match.group("mi")),
        int(match.group("s")),
        match.group("tz"),
    )
    return ParsedLine(moment, level, match.group("source") or "", match.group("message"))


# ----------------------------------------------------------------- access log

_ACCESS = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<d>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<y>\d{4}):"
    r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2}) (?P<tz>[+-]\d{4})\] "
    r'"(?P<req>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
)


def parse_access(line: str, year: int) -> ParsedLine | None:
    match = _ACCESS.match(line)
    if match is None:
        return None
    month = _MONTHS.get(match.group("mon").capitalize())
    moment = (
        None
        if month is None
        else build_datetime(
            int(match.group("y")),
            month,
            int(match.group("d")),
            int(match.group("h")),
            int(match.group("mi")),
            int(match.group("s")),
            match.group("tz"),
        )
    )
    status = int(match.group("status"))
    level = "ERROR" if status >= 500 else "WARNING" if status >= 400 else "INFO"
    # The client address is left out of the message so identical failures from different clients group together.
    return ParsedLine(moment, level, "access", f"{match.group('req')} -> {status}")


# --------------------------------------------------------------------- syslog

_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:(?:\s+|$)(?P<message>.*)$"
)
_SYSLOG_ERROR = re.compile(
    r"\b(error|errors|failed|failure|fatal|panic|critical|denied|refused|segfault|unable to|cannot|can't"
    r"|out of memory|oom-kill|killed process|no space left|timed out|abort|aborted|exception|traceback)\b",
    re.IGNORECASE,
)
_SYSLOG_WARNING = re.compile(r"\b(warn|warning|deprecated|retry|retrying)\b", re.IGNORECASE)


def parse_syslog(line: str, year: int) -> ParsedLine | None:
    match = _SYSLOG.match(line)
    if match is None:
        return None
    month = _MONTHS.get(match.group("mon"))
    if month is None:
        return None
    # Classic syslog has no year and no severity, so the year is supplied by the caller
    # and the level is a keyword guess (documented as a limitation).
    moment = build_datetime(
        year, month, int(match.group("day")), int(match.group("h")), int(match.group("mi")), int(match.group("s"))
    )
    message = match.group("message")
    level = "ERROR" if _SYSLOG_ERROR.search(message) else "WARNING" if _SYSLOG_WARNING.search(message) else "INFO"
    return ParsedLine(moment, level, match.group("proc"), message)


PARSERS: tuple[ParseFn, ...] = (parse_json, parse_python, parse_access, parse_syslog)


# --------------------------------------------------------------- the stateful part


@dataclass
class ParseStats:
    lines: int = 0  # non-blank lines seen
    entries: int = 0
    continuation_lines: int = 0
    leading_unparsed: int = 0  # unparseable lines that appeared before any entry


@dataclass
class _Pending:
    line_no: int
    timestamp: datetime | None
    level: str
    source: str
    parts: list[str]
    raw_parts: list[str]
    size: int = 0

    @classmethod
    def start(cls, line_no: int, parsed: ParsedLine | None, line: str) -> _Pending:
        pending = cls(
            line_no,
            None if parsed is None else parsed.timestamp,
            "UNKNOWN" if parsed is None else parsed.level,
            "" if parsed is None else parsed.source,
            [],
            [],
        )
        pending.add(line if parsed is None else parsed.message, line)
        return pending

    def add(self, text: str, raw: str) -> None:
        # Bounded, so one enormous file with no recognisable lines cannot exhaust memory.
        if self.size >= MAX_MESSAGE_CHARS:
            return
        room = MAX_MESSAGE_CHARS - self.size
        self.parts.append(text[:room])
        self.raw_parts.append(raw[:room])
        self.size += min(len(text), room) + 1

    def finish(self) -> LogEntry:
        message = "\n".join(self.parts)
        return LogEntry(self.line_no, self.timestamp, self.level, self.source, message, "\n".join(self.raw_parts))


@dataclass
class LogParser:
    """Feed lines in order. Each call returns the entries that the new line just completed."""

    year: int
    stats: ParseStats = field(default_factory=ParseStats)
    _pending: _Pending | None = None
    _line_no: int = 0

    def feed(self, line: str) -> list[LogEntry]:
        self._line_no += 1
        line = line.rstrip("\r\n")
        if not line.strip():
            return []
        self.stats.lines += 1

        parsed = self._parse(line)
        if parsed is None:
            if self._pending is None:
                self.stats.leading_unparsed += 1
                self._pending = _Pending.start(self._line_no, None, line)
            else:
                self.stats.continuation_lines += 1
                self._pending.add(line, line)
            return []

        finished = self.finish()
        self._pending = _Pending.start(self._line_no, parsed, line)
        return finished

    def finish(self) -> list[LogEntry]:
        """Complete and return the entry in progress, if there is one."""
        if self._pending is None:
            return []
        entry = self._pending.finish()
        self._pending = None
        self.stats.entries += 1
        return [entry]

    def _parse(self, line: str) -> ParsedLine | None:
        for parse in PARSERS:
            result = parse(line, self.year)
            if result is not None:
                return result
        return None


def parse_text(text: str, year: int) -> tuple[list[LogEntry], ParseStats]:
    """Parse a whole log held in memory. Convenient for tests and small inputs."""
    parser = LogParser(year)
    entries: list[LogEntry] = []
    for line in text.split("\n"):
        entries.extend(parser.feed(line))
    entries.extend(parser.finish())
    return entries, parser.stats
