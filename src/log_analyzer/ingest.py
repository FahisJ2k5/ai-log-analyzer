"""Reading log files and storing the analysed entries."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path

from log_analyzer.classifier import classify
from log_analyzer.errors import InputFileError
from log_analyzer.fingerprint import fingerprint, make_template
from log_analyzer.models import AnalyzedEntry, IngestResult, LogEntry
from log_analyzer.parsers import LogParser
from log_analyzer.storage import Store

MAX_FILE_BYTES = 200 * 1024 * 1024
MAX_LINE_CHARS = 20_000
_CHUNK = 1024 * 1024


def analyze(entry: LogEntry) -> AnalyzedEntry:
    """Add the grouping fingerprint and the category to a parsed entry."""
    template = make_template(entry.message)
    return AnalyzedEntry(entry, fingerprint(template), classify(entry.level, entry.message), template)


def hash_file(path: Path) -> str:
    """SHA-256 of the file's bytes. Also rejects directories, oversized files and binary files."""
    try:
        if not path.is_file():
            raise InputFileError(f"{path} is not a file")
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise InputFileError(f"{path} is {size} bytes; the limit is {MAX_FILE_BYTES}")
        digest = hashlib.sha256()
        first = True
        with path.open("rb") as handle:
            while chunk := handle.read(_CHUNK):
                if first and b"\x00" in chunk:
                    raise InputFileError(f"{path} looks like a binary file, not a text log")
                first = False
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        raise InputFileError(f"cannot read {path}: {exc.strerror or exc}") from exc


def read_lines(path: Path) -> Iterator[str]:
    """Yield lines, cutting any single line at MAX_LINE_CHARS so memory use stays bounded."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            while True:
                line = handle.readline(MAX_LINE_CHARS)
                if not line:
                    return
                if len(line) == MAX_LINE_CHARS and not line.endswith("\n"):
                    while True:  # discard the rest of this over-long physical line
                        rest = handle.readline(MAX_LINE_CHARS)
                        if not rest or rest.endswith("\n"):
                            break
                    line += " [line truncated]"
                yield line
    except OSError as exc:
        raise InputFileError(f"cannot read {path}: {exc.strerror or exc}") from exc


def ingest_file(store: Store, path: Path, year: int, now: datetime) -> IngestResult:
    """Store one log file. Ingesting identical content twice is a no-op."""
    sha = hash_file(path)
    parser = LogParser(year)

    def analysed() -> Iterator[AnalyzedEntry]:
        for line in read_lines(path):
            for entry in parser.feed(line):
                yield analyze(entry)
        for entry in parser.finish():
            yield analyze(entry)

    count = store.add_file(path.name, sha, analysed(), now)
    if count is None:
        return IngestResult(path.name, sha, True, 0, 0, 0)
    return IngestResult(path.name, sha, False, count, parser.stats.lines, parser.stats.continuation_lines)


def ingest_text(store: Store, name: str, text: str, year: int, now: datetime) -> IngestResult:
    """Store log text that is already in memory (for example read from standard input)."""
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    parser = LogParser(year)

    def analysed(lines: Iterable[str]) -> Iterator[AnalyzedEntry]:
        for line in lines:
            for entry in parser.feed(line):
                yield analyze(entry)
        for entry in parser.finish():
            yield analyze(entry)

    count = store.add_file(name, sha, analysed(text.split("\n")), now)
    if count is None:
        return IngestResult(name, sha, True, 0, 0, 0)
    return IngestResult(name, sha, False, count, parser.stats.lines, parser.stats.continuation_lines)
