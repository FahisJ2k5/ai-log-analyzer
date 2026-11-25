"""Command-line interface: ``logan ingest | search | errors | explain | stats``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from log_analyzer.classifier import CATEGORIES
from log_analyzer.config import Settings
from log_analyzer.errors import LogAnalyzerError
from log_analyzer.explain import explain_group
from log_analyzer.ingest import ingest_file, ingest_text
from log_analyzer.llm import LLMProvider, make_provider
from log_analyzer.models import ErrorGroup, Filters, StoredEntry
from log_analyzer.storage import Store
from log_analyzer.timeparse import parse_when


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logan",
        description="Ingest logs, group and classify errors, search them, and explain them with an LLM.",
    )
    parser.add_argument("--db", help="database file (default: $LOG_ANALYZER_DB or ./log_analyzer.db)")
    commands = parser.add_subparsers(dest="command", required=True)

    ingest = commands.add_parser("ingest", help="read log files into the database")
    ingest.add_argument("files", nargs="+", help="log files, or - to read standard input")
    ingest.add_argument("--year", type=int, help="year for syslog lines, which have none (default: current year)")

    for name, summary in (("search", "find log entries"), ("errors", "show grouped errors")):
        sub = commands.add_parser(name, help=summary)
        sub.add_argument("--level", help="minimum level: DEBUG, INFO, WARNING, ERROR or CRITICAL")
        sub.add_argument("--source", help="only this source or logger name")
        sub.add_argument("--category", choices=CATEGORIES, help="only this category")
        sub.add_argument("--since", help="start time: 2026-01-05, '2026-01-05 10:30', or relative like 2h or 7d")
        sub.add_argument("--until", help="end time (exclusive), same formats as --since")
        sub.add_argument("--json", action="store_true", help="print JSON instead of text")
        if name == "search":
            sub.add_argument("--text", help="full-text search words")
            sub.add_argument("--limit", type=int, default=50, help="maximum entries to show (default 50)")
            sub.add_argument("--offset", type=int, default=0, help="entries to skip")
            sub.add_argument("--newest-first", action="store_true", help="most recent entries first")
        else:
            sub.add_argument("--limit", type=int, default=20, help="maximum groups to show (default 20)")

    explain = commands.add_parser("explain", help="explain one error group with an LLM")
    explain.add_argument("fingerprint", help="a fingerprint shown by the errors command")

    stats = commands.add_parser("stats", help="summary of what is stored")
    stats.add_argument("--json", action="store_true", help="print JSON instead of text")
    return parser


def _filters(args: argparse.Namespace, now: datetime) -> Filters:
    return Filters(
        min_level=args.level,
        source=args.source,
        category=args.category,
        since=None if args.since is None else parse_when(args.since, now),
        until=None if args.until is None else parse_when(args.until, now),
        text=getattr(args, "text", None),
    )


def _entry_line(entry: StoredEntry) -> str:
    first = entry.message.split("\n", 1)[0]
    extra = " (+more lines)" if "\n" in entry.message else ""
    source = f" {entry.source}:" if entry.source else ""
    return f"{entry.ts_text:<19} {entry.level:<8}{source} {first}{extra}  [{entry.category} {entry.fingerprint}]"


def _group_line(group: ErrorGroup) -> str:
    return f"{group.fingerprint}  {group.level:<8} x{group.count:<5} {group.category:<14} {group.sample}"


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    now: datetime | None = None,
    provider: LLMProvider | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the CLI. The keyword arguments let tests inject a clock, a fake provider and streams."""
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    environment = os.environ if environ is None else environ
    clock = now or datetime.now(timezone.utc).replace(tzinfo=None)

    args = build_parser().parse_args(argv)
    settings = Settings.from_env(environment)
    db_path = args.db or settings.db_path

    try:
        with Store(db_path) as store:
            return _run(args, store, settings, clock, provider, stdin or sys.stdin, out)
    except LogAnalyzerError as exc:
        print(f"error [{exc.code}]: {exc.message}", file=err)
        return 1


def _run(
    args: argparse.Namespace,
    store: Store,
    settings: Settings,
    now: datetime,
    provider: LLMProvider | None,
    stdin: TextIO,
    out: TextIO,
) -> int:
    def emit(value: Any) -> None:
        print(json.dumps(value, indent=2, default=str), file=out)

    if args.command == "ingest":
        year = args.year or now.year
        for name in args.files:
            if name == "-":
                result = ingest_text(store, "<stdin>", stdin.read(), year, now)
            else:
                result = ingest_file(store, Path(name), year, now)
            if result.skipped:
                print(f"{result.name}: already ingested (same content), skipped", file=out)
            else:
                print(
                    f"{result.name}: {result.entries} entries from {result.lines} lines "
                    f"({result.continuation_lines} continuation lines)",
                    file=out,
                )
        return 0

    if args.command == "search":
        filters = _filters(args, now)
        entries = store.search(filters, limit=args.limit, offset=args.offset, descending=args.newest_first)
        total = store.count(filters)
        if args.json:
            emit({"total": total, "entries": [e.to_dict() for e in entries]})
        else:
            for entry in entries:
                print(_entry_line(entry), file=out)
            print(f"-- showing {len(entries)} of {total} matching entries", file=out)
        return 0

    if args.command == "errors":
        filters = _filters(args, now)
        groups = store.groups(filters, limit=args.limit)
        if args.json:
            emit({"groups": [g.to_dict() for g in groups]})
        elif not groups:
            print("no matching entries", file=out)
        else:
            for group in groups:
                print(_group_line(group), file=out)
        return 0

    if args.command == "explain":
        chosen = provider if provider is not None else make_provider(settings)
        explanation = explain_group(store, args.fingerprint, chosen)
        print(f"Explanation for {explanation.fingerprint}:\n\n{explanation.text}", file=out)
        return 0

    if args.command == "stats":
        data = store.stats()
        if args.json:
            emit(data)
        else:
            print(f"files: {data['files']}   entries: {data['entries']}", file=out)
            print(f"time range: {data['first_timestamp'] or '-'} to {data['last_timestamp'] or '-'}", file=out)
            print("by level:    " + ", ".join(f"{k} {v}" for k, v in data["by_level"].items()), file=out)
            print("by category: " + ", ".join(f"{k} {v}" for k, v in data["by_category"].items()), file=out)
        return 0

    raise AssertionError(f"unhandled command {args.command!r}")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
