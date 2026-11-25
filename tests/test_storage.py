"""Storage, search, filtering and grouping, against a real (in-memory) SQLite database."""

from __future__ import annotations

import tempfile
import unittest
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from log_analyzer.errors import InputFileError, InputValidationError, StorageError
from log_analyzer.ingest import MAX_LINE_CHARS, analyze, ingest_file, ingest_text, read_lines
from log_analyzer.models import AnalyzedEntry, Filters
from log_analyzer.parsers import parse_text
from log_analyzer.storage import MAX_LIMIT, Store, fts_query
from tests.helpers import NOW, YEAR, loaded_store, sample_text


class Ingest(unittest.TestCase):
    def test_all_samples_load(self) -> None:
        with loaded_store("app.log", "access.log", "syslog.log", "app.jsonl") as store:
            self.assertEqual(store.stats()["entries"], 34)
            self.assertEqual(store.stats()["files"], 4)

    def test_same_content_is_not_stored_twice(self) -> None:
        with Store() as store:
            first = ingest_text(store, "a", sample_text("app.log"), YEAR, NOW)
            again = ingest_text(store, "renamed", sample_text("app.log"), YEAR, NOW)
            self.assertFalse(first.skipped)
            self.assertTrue(again.skipped)
            self.assertEqual(store.count(), first.entries)

    def test_changed_content_is_stored(self) -> None:
        with Store() as store:
            ingest_text(store, "a", "2026-01-05 09:00:00 INFO a: one", YEAR, NOW)
            second = ingest_text(store, "a", "2026-01-05 09:00:00 INFO a: two", YEAR, NOW)
            self.assertFalse(second.skipped)
            self.assertEqual(store.count(), 2)

    def test_failure_part_way_keeps_nothing(self) -> None:
        def exploding() -> Iterator[AnalyzedEntry]:
            entries, _ = parse_text("2026-01-05 09:00:00 ERROR a: first", YEAR)
            yield analyze(entries[0])
            raise RuntimeError("disk vanished")

        with Store() as store:
            with self.assertRaises(RuntimeError):
                store.add_file("f", "abc", exploding(), NOW)
            self.assertEqual(store.count(), 0)
            self.assertFalse(store.has_file("abc"))

    def test_missing_directory_and_binary_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder, Store() as store:
            with self.assertRaises(InputFileError):
                ingest_file(store, Path(folder) / "nope.log", YEAR, NOW)
            with self.assertRaises(InputFileError):
                ingest_file(store, Path(folder), YEAR, NOW)
            binary = Path(folder) / "blob.log"
            binary.write_bytes(b"\x00\x01\x02 not text")
            with self.assertRaises(InputFileError):
                ingest_file(store, binary, YEAR, NOW)

    def test_file_with_invalid_utf8_still_loads(self) -> None:
        with tempfile.TemporaryDirectory() as folder, Store() as store:
            path = Path(folder) / "latin.log"
            path.write_bytes(b"2026-01-05 09:00:00 ERROR a: caf\xe9 broke\n")
            self.assertEqual(ingest_file(store, path, YEAR, NOW).entries, 1)

    def test_a_giant_line_is_cut_not_loaded_whole(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "big.log"
            path.write_text("2026-01-05 09:00:00 ERROR a: " + "y" * 500_000 + "\nnext\n", encoding="utf-8")
            lines = list(read_lines(path))
            self.assertEqual(len(lines), 2)
            self.assertLessEqual(len(lines[0]), MAX_LINE_CHARS + 20)
            self.assertTrue(lines[0].endswith("[line truncated]"))


class Search(unittest.TestCase):
    def setUp(self) -> None:
        self.store = loaded_store("app.log", "access.log", "syslog.log", "app.jsonl")
        self.addCleanup(self.store.close)

    def messages(self, filters: Filters) -> list[str]:
        return [e.message.split("\n")[0] for e in self.store.search(filters)]

    def test_minimum_level(self) -> None:
        found = self.store.search(Filters(min_level="error"), limit=100)
        # 19 = 8 (app.log) + 3 (access.log: HTTP 5xx) + 4 (syslog) + 4 (app.jsonl). Counted independently
        # of the project code by reading the sample files directly.
        self.assertEqual(len(found), 19)
        self.assertTrue(all(e.level in ("ERROR", "CRITICAL") for e in found))

    def test_source_is_case_insensitive(self) -> None:
        self.assertEqual(self.store.count(Filters(source="APP.DB")), 4)

    def test_category(self) -> None:
        self.assertEqual(self.store.count(Filters(category="timeout")), 3)

    def test_time_window_is_inclusive_then_exclusive(self) -> None:
        window = Filters(source="app.db", since=datetime(2026, 1, 5, 9, 15, 10), until=datetime(2026, 1, 5, 9, 16, 5))
        self.assertEqual(
            self.messages(window),
            [
                "Connection to 10.0.0.5:5432 timed out after 30s",
                "Connection to 10.0.0.7:5432 timed out after 30s",
            ],
        )

    def test_entries_without_timestamps_never_match_a_time_filter(self) -> None:
        with Store() as store:
            ingest_text(store, "x", "no timestamp here\n2026-01-05 09:00:00 INFO a: dated", YEAR, NOW)
            self.assertEqual(store.count(Filters(since=datetime(2000, 1, 1))), 1)
            self.assertEqual(store.count(), 2)

    def test_full_text_search(self) -> None:
        self.assertEqual(self.store.count(Filters(text="timed out")), 3)
        self.assertEqual(self.store.count(Filters(text="TIMED")), 3)  # case-insensitive
        self.assertEqual(self.store.count(Filters(text="nonexistentword")), 0)

    def test_search_matches_the_source_column_too(self) -> None:
        self.assertGreater(self.store.count(Filters(text="sshd")), 0)

    def test_filters_combine_with_and(self) -> None:
        self.assertEqual(self.store.count(Filters(text="timed out", min_level="CRITICAL")), 0)
        self.assertEqual(self.store.count(Filters(text="timed out", category="timeout", source="app.db")), 3)

    def test_ordering_and_paging(self) -> None:
        everything = self.store.search(limit=100)
        stamps = [e.timestamp for e in everything if e.timestamp]
        self.assertEqual(stamps, sorted(stamps))
        newest = self.store.search(limit=1, descending=True)[0]
        self.assertEqual(newest.timestamp, "2026-01-05T11:00:00")
        page1 = self.store.search(limit=5, offset=0)
        page2 = self.store.search(limit=5, offset=5)
        self.assertEqual(len({e.id for e in page1 + page2}), 10)

    def test_limit_bounds(self) -> None:
        for bad in (0, -1, MAX_LIMIT + 1):
            with self.assertRaises(InputValidationError):
                self.store.search(limit=bad)
        with self.assertRaises(InputValidationError):
            self.store.search(offset=-1)

    def test_bad_level_filter(self) -> None:
        with self.assertRaises(InputValidationError):
            self.store.count(Filters(min_level="loud"))


class SqlSafety(unittest.TestCase):
    """User text must never be able to change the meaning of a query."""

    def setUp(self) -> None:
        self.store = loaded_store("app.log")
        self.addCleanup(self.store.close)

    def test_quote_and_operator_text_is_just_words(self) -> None:
        total = self.store.count()
        for text in (
            '" OR 1=1 --',
            "'; DROP TABLE entries; --",
            "NEAR(",
            "a AND",
            "*",
            '"unbalanced',
            "timed OR failed",
            "x:y",
            "-foo",
            "()",
        ):
            with self.subTest(text=text):
                self.store.count(Filters(text=text))  # must not raise a syntax error
        self.assertEqual(self.store.count(), total)  # nothing was dropped

    def test_filter_values_are_parameters(self) -> None:
        total = self.store.count()
        for value in ("x' OR '1'='1", "'; DELETE FROM entries; --", '" ; --'):
            self.assertEqual(self.store.count(Filters(source=value)), 0)
            self.assertEqual(self.store.count(Filters(category=value)), 0)
            self.assertEqual(self.store.count(Filters(fingerprint=value)), 0)
        self.assertEqual(self.store.count(), total)

    def test_text_limits(self) -> None:
        with self.assertRaises(InputValidationError):
            fts_query("   ")
        with self.assertRaises(InputValidationError):
            fts_query(" ".join(["w"] * 21))
        with self.assertRaises(InputValidationError):
            fts_query("z" * 201)

    def test_quotes_are_escaped(self) -> None:
        self.assertEqual(fts_query('say "hi"'), '"say" """hi"""')


class Groups(unittest.TestCase):
    def setUp(self) -> None:
        self.store = loaded_store("app.log", "access.log", "syslog.log", "app.jsonl")
        self.addCleanup(self.store.close)

    def test_repeated_errors_collapse_into_one_group(self) -> None:
        group = next(g for g in self.store.groups(limit=100) if g.category == "timeout" and "30s" in g.sample)
        self.assertEqual(group.count, 3)
        self.assertEqual(group.first_seen, "2026-01-05T09:15:10")
        self.assertEqual(group.last_seen, "2026-01-05T09:16:05")

    def test_ordered_by_severity_then_frequency(self) -> None:
        groups = self.store.groups(Filters(min_level="WARNING"), limit=100)
        ranks = {"CRITICAL": 3, "ERROR": 2, "WARNING": 1}
        keys = [(ranks[g.level], g.count) for g in groups]
        self.assertEqual(keys, sorted(keys, reverse=True))
        self.assertEqual(groups[0].level, "CRITICAL")

    def test_filters_apply_to_groups(self) -> None:
        groups = self.store.groups(Filters(category="authentication"), limit=100)
        self.assertEqual(sum(g.count for g in groups), 4)

    def test_group_lookup_and_samples(self) -> None:
        top = self.store.groups(limit=1)[0]
        self.assertEqual(self.store.group(top.fingerprint), top)
        self.assertEqual(len(self.store.samples(top.fingerprint, limit=3)), min(3, top.count))
        self.assertIsNone(self.store.group("doesnotexist"))

    def test_a_multi_line_error_is_one_group_regardless_of_the_trace(self) -> None:
        with Store() as store:
            text = (
                "2026-01-05 09:00:00 ERROR w: job 11 failed\nTraceback\nKeyError: 'a'\n"
                "2026-01-05 09:01:00 ERROR w: job 22 failed\nTraceback\nValueError: 'b'\n"
            )
            ingest_text(store, "t", text, YEAR, NOW)
            self.assertEqual(len(store.groups()), 1)
            self.assertEqual(store.groups()[0].count, 2)

    def test_the_most_severe_level_in_a_group_is_reported(self) -> None:
        with Store() as store:
            ingest_text(
                store,
                "t",
                "2026-01-05 09:00:00 WARNING a: disk 90% full\n2026-01-05 09:01:00 ERROR a: disk 95% full\n",
                YEAR,
                NOW,
            )
            (group,) = store.groups()
            self.assertEqual((group.level, group.count), ("ERROR", 2))

    def test_stats_shape(self) -> None:
        stats = self.store.stats()
        self.assertEqual(stats["first_timestamp"], "2026-01-05T09:00:00")
        self.assertEqual(sum(stats["by_level"].values()), stats["entries"])
        self.assertEqual(sum(stats["by_category"].values()), stats["entries"])


class OpeningDatabases(unittest.TestCase):
    def test_a_file_database_persists(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "logs.db"
            with Store(path) as store:
                ingest_text(store, "a", sample_text("app.log"), YEAR, NOW)
            with Store(path) as store:
                self.assertEqual(store.count(), 14)

    def test_unusable_path_is_a_clean_error(self) -> None:
        with self.assertRaises(StorageError):
            Store("/this/folder/does/not/exist/logs.db")


if __name__ == "__main__":
    unittest.main()
