"""SQLite storage with full-text search.

Why SQLite: a log analyser used by one person needs no server. A single file,
transactions, indexes and FTS5 full-text search all ship with Python.

Every value that comes from a user (filters, search text, identifiers) reaches
SQL only as a bound parameter. The few strings built into SQL text are
constants defined in this file. Search text is additionally turned into a
quoted FTS5 query, so characters such as ``"``, ``*`` and ``AND`` are treated
as ordinary words rather than as query syntax.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Any

from log_analyzer.errors import InputValidationError, StorageError
from log_analyzer.fingerprint import headline
from log_analyzer.models import (
    LEVEL_RANK,
    AnalyzedEntry,
    ErrorGroup,
    Filters,
    StoredEntry,
    levels_at_least,
)
from log_analyzer.timeparse import to_iso

MAX_LIMIT = 1_000
MAX_SEARCH_TOKENS = 20
MAX_SEARCH_TOKEN_CHARS = 200
_BATCH = 1_000

_RANK_BY_VALUE = {rank: name for name, rank in LEVEL_RANK.items()}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    sha256      TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    entries     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    file_sha    TEXT NOT NULL REFERENCES files(sha256),
    line_no     INTEGER NOT NULL,
    ts          TEXT,
    level       TEXT NOT NULL,
    source      TEXT NOT NULL,
    message     TEXT NOT NULL,
    category    TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    template    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_ts          ON entries(ts);
CREATE INDEX IF NOT EXISTS idx_entries_level       ON entries(level);
CREATE INDEX IF NOT EXISTS idx_entries_category    ON entries(category);
CREATE INDEX IF NOT EXISTS idx_entries_source      ON entries(source);
CREATE INDEX IF NOT EXISTS idx_entries_fingerprint ON entries(fingerprint);
CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(message, source);
"""


def _rank_sql(alias: str) -> str:
    """SQL expression turning a level name into its numeric rank (built from constants only)."""
    cases = " ".join(f"WHEN '{name}' THEN {rank}" for name, rank in LEVEL_RANK.items())
    return f"CASE {alias}.level {cases} ELSE 0 END"


def fts_query(text: str) -> str:
    """Quote every word so FTS5 treats user input as plain terms, never as operators."""
    tokens = text.split()
    if not tokens:
        raise InputValidationError("search text is empty")
    if len(tokens) > MAX_SEARCH_TOKENS:
        raise InputValidationError(f"search text has more than {MAX_SEARCH_TOKENS} words")
    for token in tokens:
        if len(token) > MAX_SEARCH_TOKEN_CHARS:
            raise InputValidationError(f"a search word is longer than {MAX_SEARCH_TOKEN_CHARS} characters")
    return " ".join('"' + token.replace('"', '""') + '"' for token in tokens)


def _where(filters: Filters) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if filters.min_level is not None:
        levels = levels_at_least(filters.min_level)
        clauses.append(f"e.level IN ({','.join('?' * len(levels))})")
        params.extend(levels)
    if filters.source is not None:
        clauses.append("e.source = ? COLLATE NOCASE")
        params.append(filters.source)
    if filters.category is not None:
        clauses.append("e.category = ?")
        params.append(filters.category)
    if filters.fingerprint is not None:
        clauses.append("e.fingerprint = ?")
        params.append(filters.fingerprint)
    if filters.since is not None:
        clauses.append("e.ts >= ?")  # entries without a timestamp never match a time filter
        params.append(to_iso(filters.since))
    if filters.until is not None:
        clauses.append("e.ts < ?")
        params.append(to_iso(filters.until))
    if filters.text is not None:
        clauses.append("e.id IN (SELECT rowid FROM entries_fts WHERE entries_fts MATCH ?)")
        params.append(fts_query(filters.text))
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def _check_page(limit: int, offset: int = 0) -> None:
    if not 1 <= limit <= MAX_LIMIT:
        raise InputValidationError(f"limit must be between 1 and {MAX_LIMIT}")
    if offset < 0:
        raise InputValidationError("offset cannot be negative")


class Store:
    """A connection to the log database. Use it as a context manager."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        try:
            self._conn = sqlite3.connect(str(path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.executescript(_SCHEMA)
        except sqlite3.Error as exc:
            hint = " (this SQLite build may lack FTS5 support)" if "fts5" in str(exc).lower() else ""
            raise StorageError(f"cannot open database {str(path)!r}: {exc}{hint}") from exc

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # ---------------------------------------------------------------- writing

    def has_file(self, sha256: str) -> bool:
        row = self._conn.execute("SELECT 1 FROM files WHERE sha256 = ?", (sha256,)).fetchone()
        return row is not None

    def add_file(
        self,
        name: str,
        sha256: str,
        entries: Iterable[AnalyzedEntry],
        now: datetime,
    ) -> int | None:
        """Store a file's entries atomically. Returns the entry count, or None if the file was already stored.

        ``entries`` may be a lazy iterator. If it raises part-way (for example the file
        becomes unreadable), the transaction is rolled back and nothing is kept.
        """
        if self.has_file(sha256):
            return None
        try:
            with self._conn:  # one transaction: commit on success, roll back on any exception
                self._conn.execute(
                    "INSERT INTO files (sha256, name, ingested_at, entries) VALUES (?, ?, ?, 0)",
                    (sha256, name, to_iso(now)),
                )
                total = 0
                batch: list[tuple[Any, ...]] = []
                for item in entries:
                    entry = item.entry
                    batch.append(
                        (
                            sha256,
                            entry.line_no,
                            None if entry.timestamp is None else to_iso(entry.timestamp),
                            entry.level,
                            entry.source,
                            entry.message,
                            item.category,
                            item.fingerprint,
                            item.template,
                        )
                    )
                    if len(batch) >= _BATCH:
                        total += self._flush(batch)
                        batch = []
                total += self._flush(batch)
                self._conn.execute(
                    "INSERT INTO entries_fts (rowid, message, source) "
                    "SELECT id, message, source FROM entries WHERE file_sha = ?",
                    (sha256,),
                )
                self._conn.execute("UPDATE files SET entries = ? WHERE sha256 = ?", (total, sha256))
        except sqlite3.Error as exc:
            raise StorageError(f"database error while storing {name!r}: {exc}") from exc
        return total

    def _flush(self, batch: list[tuple[Any, ...]]) -> int:
        if batch:
            self._conn.executemany(
                "INSERT INTO entries (file_sha, line_no, ts, level, source, message, category, fingerprint, template) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                batch,
            )
        return len(batch)

    # ---------------------------------------------------------------- reading

    def search(
        self,
        filters: Filters = Filters(),
        *,
        limit: int = 50,
        offset: int = 0,
        descending: bool = False,
    ) -> list[StoredEntry]:
        _check_page(limit, offset)
        where, params = _where(filters)
        direction = "DESC" if descending else "ASC"
        sql = (
            "SELECT e.id, e.line_no, e.ts, e.level, e.source, e.message, e.category, e.fingerprint "
            f"FROM entries e{where} ORDER BY (e.ts IS NULL), e.ts {direction}, e.id {direction} LIMIT ? OFFSET ?"
        )
        rows = self._query(sql, [*params, limit, offset])
        return [
            StoredEntry(
                r["id"], r["line_no"], r["ts"], r["level"], r["source"], r["message"], r["category"], r["fingerprint"]
            )
            for r in rows
        ]

    def count(self, filters: Filters = Filters()) -> int:
        where, params = _where(filters)
        row = self._query(f"SELECT COUNT(*) AS n FROM entries e{where}", params)[0]
        return int(row["n"])

    def groups(self, filters: Filters = Filters(), *, limit: int = 20) -> list[ErrorGroup]:
        """Entries grouped by fingerprint: most severe first, then most frequent."""
        _check_page(limit)
        where, params = _where(filters)
        sql = (
            "WITH g AS ("
            " SELECT e.fingerprint AS fp, COUNT(*) AS n, MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen,"
            f"  MAX({_rank_sql('e')}) AS top_rank, MIN(e.id) AS sample_id"
            f" FROM entries e{where} GROUP BY e.fingerprint)"
            " SELECT g.fp, g.n, g.first_seen, g.last_seen, g.top_rank, s.category, s.template, s.message"
            " FROM g JOIN entries s ON s.id = g.sample_id"
            " ORDER BY g.top_rank DESC, g.n DESC, g.fp LIMIT ?"
        )
        rows = self._query(sql, [*params, limit])
        return [
            ErrorGroup(
                fingerprint=r["fp"],
                count=r["n"],
                level=_RANK_BY_VALUE.get(r["top_rank"], "UNKNOWN"),
                category=r["category"],
                template=r["template"],
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
                sample=headline(r["message"]),
            )
            for r in rows
        ]

    def group(self, fingerprint: str) -> ErrorGroup | None:
        found = self.groups(Filters(fingerprint=fingerprint), limit=1)
        return found[0] if found else None

    def samples(self, fingerprint: str, limit: int = 3) -> list[StoredEntry]:
        return self.search(Filters(fingerprint=fingerprint), limit=limit)

    def stats(self) -> dict[str, Any]:
        files = self._query("SELECT COUNT(*) AS n FROM files", [])[0]["n"]
        total = self._query("SELECT COUNT(*) AS n FROM entries", [])[0]["n"]
        by_level = {
            r["level"]: r["n"] for r in self._query("SELECT level, COUNT(*) AS n FROM entries GROUP BY level", [])
        }
        by_category = {
            r["category"]: r["n"]
            for r in self._query(
                "SELECT category, COUNT(*) AS n FROM entries GROUP BY category ORDER BY n DESC, category", []
            )
        }
        span = self._query("SELECT MIN(ts) AS first, MAX(ts) AS last FROM entries", [])[0]
        return {
            "files": files,
            "entries": total,
            "by_level": by_level,
            "by_category": by_category,
            "first_timestamp": span["first"],
            "last_timestamp": span["last"],
        }

    def _query(self, sql: str, params: list[Any]) -> list[sqlite3.Row]:
        try:
            return self._conn.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise StorageError(f"database error: {exc}") from exc
