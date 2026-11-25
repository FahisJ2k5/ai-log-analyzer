"""Grouping similar log messages.

Two messages that differ only in an id, a number, an address or a path are the
same *kind* of problem. ``make_template`` replaces those variable parts with
placeholders, and the fingerprint is a short hash of the result.

    "Connection to 10.0.0.5:5432 timed out after 30s"
    "Connection to 10.0.0.9:5432 timed out after 12s"
        -> "Connection to <ip>:<num> timed out after <num>s"   (same fingerprint)

The order of the substitutions matters: the most specific patterns run first,
so a UUID is not chewed up by the generic number rule.
"""

from __future__ import annotations

import hashlib
import re

_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"), "<time>"),
    # Paths run before addresses and hex so a whole path becomes one placeholder.
    (re.compile(r"(?<![\w<])(?:/[\w.\-@+%~]+){2,}"), "<path>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<ip>"),
    (re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"), "<mac>"),
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "<email>"),
    (re.compile(r"\b0[xX][0-9a-fA-F]+\b"), "<hex>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<hex>"),
    # Shorter hex-looking identifiers (commit hashes, request ids). They must contain a digit,
    # so ordinary words such as "defaced" or "decade" are left alone.
    (re.compile(r"\b(?=[0-9a-fA-F]*\d)[0-9a-fA-F]{8,}\b"), "<hex>"),
    # An HTTP status after "->" is part of what kind of failure this is (500 is not 502): keep it.
    (re.compile(r"->\s*(\d{3})\b"), r"-> http\1"),
    # A number that is not glued to a preceding letter. "30s" and "2300ms" count; "ssh2" does not.
    (re.compile(r"(?<![A-Za-z0-9_<])\d+(?:\.\d+)?"), "<num>"),
)
_WHITESPACE = re.compile(r"\s+")


def headline(message: str) -> str:
    """The first line of a message. A stack trace's later lines would make every trace look unique."""
    return message.split("\n", 1)[0].strip()


def make_template(message: str) -> str:
    """Replace the variable parts of the first line with placeholders."""
    text = headline(message)
    for pattern, placeholder in _RULES:
        text = pattern.sub(placeholder, text)
    return _WHITESPACE.sub(" ", text).strip().lower()


def fingerprint(template: str) -> str:
    """Twelve hex characters: enough to tell groups apart, short enough to type."""
    return hashlib.sha256(template.encode("utf-8")).hexdigest()[:12]
