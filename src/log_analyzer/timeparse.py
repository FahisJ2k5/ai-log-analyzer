"""Timestamp handling.

Python 3.10 and 3.11+ accept different ISO-8601 variants in ``fromisoformat``.
To behave identically on every version, timestamps are parsed here with one
explicit pattern. Everything is normalised to naive UTC. A timestamp that has
no offset is assumed to already be UTC; that is documented in the README.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from log_analyzer.errors import InputValidationError

_ISO = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})"
    r"(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2})?)?$"
)
_RELATIVE = re.compile(r"^(\d+)([smhdw])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
_OFFSET = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


def build_datetime(
    year: int,
    month: int,
    day: int,
    hour: int = 0,
    minute: int = 0,
    second: int = 0,
    tz_text: str | None = None,
) -> datetime | None:
    """Build a naive-UTC datetime, or return None if any part is impossible."""
    try:
        moment = datetime(year, month, day, hour, minute, second)
        if tz_text:
            if tz_text == "Z":
                offset = timedelta(0)
            else:
                match = _OFFSET.match(tz_text)
                if match is None:
                    return None
                sign = -1 if match.group(1) == "-" else 1
                offset = sign * timedelta(hours=int(match.group(2)), minutes=int(match.group(3)))
            # Validates the range (a UTC offset must be under 24 hours).
            zone = timezone(offset)
            moment = moment.replace(tzinfo=zone).astimezone(timezone.utc).replace(tzinfo=None)
    except (ValueError, OverflowError):
        return None
    return moment


def parse_timestamp(text: str) -> datetime | None:
    """Parse ``2026-01-05``, ``2026-01-05 10:30``, ``2026-01-05T10:30:15.123Z`` and similar."""
    match = _ISO.match(text.strip())
    if match is None:
        return None
    year, month, day, hour, minute, second, tz_text = match.groups()
    return build_datetime(int(year), int(month), int(day), int(hour or 0), int(minute or 0), int(second or 0), tz_text)


def parse_when(text: str, now: datetime) -> datetime:
    """Read a command-line time: an absolute timestamp, or a relative one such as ``2h`` or ``7d``."""
    cleaned = text.strip()
    relative = _RELATIVE.match(cleaned)
    if relative is not None:
        try:
            return now - timedelta(**{_UNITS[relative.group(2)]: int(relative.group(1))})
        except OverflowError:
            raise InputValidationError(f"time {text!r} is too far in the past") from None
    parsed = parse_timestamp(cleaned)
    if parsed is None:
        raise InputValidationError(
            f"cannot understand time {text!r}; use for example 2026-01-05, '2026-01-05 10:30' or 2h"
        )
    return parsed


def to_iso(moment: datetime) -> str:
    """The text form stored in the database. It sorts correctly as plain text."""
    return moment.isoformat(timespec="seconds")
