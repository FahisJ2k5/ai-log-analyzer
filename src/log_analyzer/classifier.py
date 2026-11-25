"""Rule-based error classification.

Each category is a list of keyword patterns. The first category (in the order
below) with any match wins, so more specific categories come first.

Which text is searched matters:
  1. The first line (the headline) is checked against every category.
  2. Only if that matches nothing, the *whole* entry is checked, and only for
     ``crash``. A stack trace is full of incidental words (a KeyError inside a
     crash would otherwise be labelled "validation"), so the details can make
     an entry a crash but cannot give it any other label.

A message that matches nothing is ``unclassified``; one below WARNING is ``info``.

This is deterministic and explainable: the same line always gets the same
category, and you can see which rule fired. It is a keyword heuristic, not a
trained model, and the README says so.
"""

from __future__ import annotations

import re

from log_analyzer.models import LEVEL_RANK

# (category, patterns). Order matters.
_CATEGORIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "out_of_memory",
        (
            r"out of memory",
            r"\boom\b",
            r"oom-kill",
            r"memoryerror",
            r"cannot allocate memory",
            r"java\.lang\.outofmemory",
        ),
    ),
    ("disk", (r"no space left", r"disk full", r"disk quota", r"disk usage", r"read-only file system", r"i/o error")),
    (
        "authentication",
        (
            r"authentication fail",
            r"failed password",
            r"invalid user",
            r"invalid credentials",
            r"login failed",
            r"unauthori[sz]ed",
            r"access denied",
            r"permission denied",
            r"forbidden",
            r"invalid token",
            r"token expired",
            r"\b401\b",
            r"\b403\b",
        ),
    ),
    ("timeout", (r"timed out", r"time out", r"timeout", r"deadline exceeded")),
    (
        "database",
        (
            r"database",
            r"\bsql\b",
            r"deadlock",
            r"too many connections",
            r"connection pool",
            r"psycopg",
            r"sqlite",
            r"mysql",
            r"postgres",
            r"integrityerror",
            r"operationalerror",
        ),
    ),
    (
        "network",
        (
            r"connection refused",
            r"connection reset",
            r"broken pipe",
            r"unreachable",
            r"\bdns\b",
            r"name or service not known",
            r"socket",
            r"\bssl\b",
            r"certificate",
            r"\b502\b",
            r"\b503\b",
            r"\b504\b",
            r"bad gateway",
            r"service unavailable",
        ),
    ),
    ("server_error", (r"->\s*5\d\d\b", r"internal server error")),
    (
        "not_found",
        (r"not found", r"no such file", r"does not exist", r"\b404\b", r"filenotfounderror", r"modulenotfounderror"),
    ),
    (
        "configuration",
        (
            r"invalid config",
            r"missing config",
            r"configuration error",
            r"environment variable",
            r"misconfigur",
            r"invalid setting",
        ),
    ),
    (
        "validation",
        (
            r"validation",
            r"invalid input",
            r"invalid value",
            r"malformed",
            r"bad request",
            r"\b400\b",
            r"valueerror",
            r"typeerror",
            r"keyerror",
        ),
    ),
    ("performance", (r"\bslow\b", r"latency", r"high load")),
    (
        "crash",
        (
            r"traceback",
            r"unhandled exception",
            r"\bpanic\b",
            r"segfault",
            r"segmentation fault",
            r"core dumped",
            r"fatal",
            r"\bcrash(?:ed|es)?\b",
            r"exception",
        ),
    ),
)


def _compile(patterns: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


_COMPILED = tuple((name, _compile(patterns)) for name, patterns in _CATEGORIES)
_CRASH = next(patterns for name, patterns in _COMPILED if name == "crash")

CATEGORIES: tuple[str, ...] = tuple(name for name, _ in _CATEGORIES) + ("unclassified", "info")


def _first_match(text: str) -> str | None:
    for name, patterns in _COMPILED:
        if any(pattern.search(text) for pattern in patterns):
            return name
    return None


def classify(level: str, message: str) -> str:
    """Return the category for one entry. ``message`` may span several lines."""
    if LEVEL_RANK.get(level, 0) < LEVEL_RANK["WARNING"] and level != "UNKNOWN":
        return "info"
    head = message.split("\n", 1)[0]
    found = _first_match(head)
    if found is not None:
        return found
    if "\n" in message and any(pattern.search(message) for pattern in _CRASH):
        return "crash"
    return "unclassified"
