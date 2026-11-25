"""Removing sensitive values before text leaves the machine.

Anything sent to a language model goes through ``redact`` first. It masks the
kinds of secrets that commonly appear in logs: credentials in ``key=value``
pairs, Authorization headers, well-known token shapes, JWTs, private keys,
email addresses, IP addresses, and passwords inside URLs.

Honest limits: this is pattern matching. It will miss a secret that has an
unusual shape, and it can mask harmless text that happens to look like one.
It reduces the risk; it does not remove it. Do not send logs that must never
leave your environment.
"""

from __future__ import annotations

import re

MAX_PROMPT_CHARS = 4_000

_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), "<private-key>"),
    (
        re.compile(
            r"(?i)\b(authorization|proxy-authorization)\b\s*[:=]\s*(?:bearer|basic|token)?\s*[^\s,;\"']+(?:\s+[A-Za-z0-9._~+/=-]{8,})?"
        ),
        r"\1: <redacted>",
    ),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 <redacted>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), "<jwt>"),
    (re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b"), "<api-key>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "<api-key>"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<aws-access-key>"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "<api-key>"),
    # scheme://user:password@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+):[^\s@/]+@"), r"\1:<redacted>@"),
    # password=..., api_key: ..., "secret": "..."
    (
        re.compile(
            r"(?i)([\"']?\b(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key)\b[\"']?\s*[:=]\s*)"
            r"(?:\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)"
        ),
        r"\1<redacted>",
    ),
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "<email>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<ip>"),
)


def redact(text: str) -> str:
    """Mask sensitive values in ``text``."""
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text


def prepare_for_model(text: str, limit: int = MAX_PROMPT_CHARS) -> str:
    """Redact first, then cut to a bounded size. The order matters: truncating first could split a secret."""
    cleaned = redact(text)
    if len(cleaned) > limit:
        return cleaned[:limit] + "\n[truncated]"
    return cleaned
