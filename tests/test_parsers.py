"""Parsing each format, joining multi-line records, and surviving garbage."""

from __future__ import annotations

import random
import string
import unittest
from datetime import datetime

from log_analyzer.errors import InputValidationError
from log_analyzer.models import levels_at_least, normalize_level
from log_analyzer.parsers import MAX_MESSAGE_CHARS, LogParser, parse_text
from log_analyzer.timeparse import parse_timestamp, parse_when
from tests.helpers import YEAR, sample_text


class PythonStyle(unittest.TestCase):
    def test_fields(self) -> None:
        (entry,), _ = parse_text("2026-01-05 09:15:10 ERROR app.db: Connection lost", YEAR)
        self.assertEqual(entry.timestamp, datetime(2026, 1, 5, 9, 15, 10))
        self.assertEqual((entry.level, entry.source, entry.message), ("ERROR", "app.db", "Connection lost"))

    def test_bracketed_level_and_comma_milliseconds(self) -> None:
        (entry,), _ = parse_text("2026-01-05 09:15:10,123 [WARN] cache: nearly full", YEAR)
        self.assertEqual((entry.level, entry.source), ("WARNING", "cache"))

    def test_no_source(self) -> None:
        (entry,), _ = parse_text("2026-01-05T09:15:10Z INFO started", YEAR)
        self.assertEqual((entry.source, entry.message), ("", "started"))

    def test_time_zone_offset_is_converted_to_utc(self) -> None:
        (entry,), _ = parse_text("2026-01-05 10:00:00+02:00 INFO x: hello", YEAR)
        self.assertEqual(entry.timestamp, datetime(2026, 1, 5, 8, 0, 0))

    def test_unknown_level_word_is_not_a_log_line(self) -> None:
        entries, stats = parse_text("2026-01-05 09:15:10 SOMETHING x: y", YEAR)
        self.assertEqual(entries[0].level, "UNKNOWN")  # kept, as an unparsed line
        self.assertEqual(stats.leading_unparsed, 1)

    def test_impossible_date_keeps_the_entry_but_not_the_timestamp(self) -> None:
        # The line is clearly a log record with a level. Dropping it into the previous entry as a
        # "continuation" would silently lose an ERROR, so it is kept, with no timestamp.
        text = "2026-01-05 09:00:00 INFO a: fine\n2026-13-45 09:15:10 ERROR x: y"
        entries, _ = parse_text(text, YEAR)
        self.assertEqual(len(entries), 2)
        self.assertEqual((entries[1].level, entries[1].source, entries[1].message), ("ERROR", "x", "y"))
        self.assertIsNone(entries[1].timestamp)


class MultiLine(unittest.TestCase):
    def test_stack_trace_stays_with_its_record(self) -> None:
        entries, stats = parse_text(sample_text("app.log"), YEAR)
        crash = next(e for e in entries if "Unhandled exception" in e.message)
        self.assertIn("KeyError: 'customer_id'", crash.message)
        self.assertEqual(crash.message.count("\n"), 6)
        self.assertEqual(stats.continuation_lines, 6)
        self.assertEqual(len(entries), 14)

    def test_every_non_blank_line_is_counted(self) -> None:
        text = "2026-01-05 09:00:00 INFO a: one\n\n   \ncontinued\n2026-01-05 09:00:01 INFO a: two\n"
        entries, stats = parse_text(text, YEAR)
        self.assertEqual(stats.lines, 3)
        self.assertEqual(len(entries), 2)

    def test_unparseable_first_line_is_kept_as_unknown(self) -> None:
        entries, stats = parse_text("garbage first\n2026-01-05 09:00:00 INFO a: ok", YEAR)
        self.assertEqual([e.level for e in entries], ["UNKNOWN", "INFO"])
        self.assertEqual(stats.leading_unparsed, 1)

    def test_a_huge_record_is_bounded(self) -> None:
        head = "2026-01-05 09:00:00 ERROR a: start"
        text = head + "\n" + "\n".join("x" * 1000 for _ in range(100))
        (entry,), _ = parse_text(text, YEAR)
        self.assertLessEqual(len(entry.message), MAX_MESSAGE_CHARS + 200)
        self.assertTrue(entry.message.startswith("start"))

    def test_empty_input(self) -> None:
        entries, stats = parse_text("", YEAR)
        self.assertEqual((entries, stats.lines), ([], 0))


class Json(unittest.TestCase):
    def test_common_field_names(self) -> None:
        (entry,), _ = parse_text(
            '{"timestamp":"2026-01-05T09:00:00Z","level":"error","logger":"api","message":"boom"}', YEAR
        )
        self.assertEqual((entry.level, entry.source, entry.message), ("ERROR", "api", "boom"))
        self.assertEqual(entry.timestamp, datetime(2026, 1, 5, 9, 0, 0))

    def test_alternative_names_and_epoch_seconds(self) -> None:
        (entry,), _ = parse_text('{"ts":1767603900,"severity":"CRITICAL","service":"queue","msg":"crashed"}', YEAR)
        self.assertEqual((entry.level, entry.source, entry.message), ("CRITICAL", "queue", "crashed"))
        self.assertEqual(entry.timestamp, datetime(2026, 1, 5, 9, 5, 0))

    def test_epoch_milliseconds(self) -> None:
        (entry,), _ = parse_text('{"ts":1767603900000,"level":"info","message":"x"}', YEAR)
        self.assertEqual(entry.timestamp, datetime(2026, 1, 5, 9, 5, 0))

    def test_cause_is_part_of_the_headline(self) -> None:
        (entry,), _ = parse_text('{"level":"error","message":"call failed","error":"timeout"}', YEAR)
        self.assertEqual(entry.message, "call failed: timeout")

    def test_stack_goes_after_the_headline(self) -> None:
        (entry,), _ = parse_text('{"level":"error","message":"crashed","stack":"line1\\nline2"}', YEAR)
        self.assertEqual(entry.message, "crashed\nline1\nline2")

    def test_missing_level_is_unknown(self) -> None:
        (entry,), _ = parse_text('{"message":"hello"}', YEAR)
        self.assertEqual(entry.level, "UNKNOWN")

    def test_json_without_a_message_is_not_a_log_record(self) -> None:
        entries, _ = parse_text('{"status":200}', YEAR)
        self.assertEqual(entries[0].level, "UNKNOWN")

    def test_broken_json_does_not_raise(self) -> None:
        entries, _ = parse_text('{"message": "unterminated', YEAR)
        self.assertEqual(len(entries), 1)

    def test_non_object_json(self) -> None:
        entries, _ = parse_text("[1, 2, 3]", YEAR)
        self.assertEqual(entries[0].level, "UNKNOWN")


class Syslog(unittest.TestCase):
    def test_fields_and_supplied_year(self) -> None:
        (entry,), _ = parse_text("Jan  5 09:30:12 web01 kernel: Out of memory: Killed process 4211", 2025)
        self.assertEqual(entry.timestamp, datetime(2025, 1, 5, 9, 30, 12))
        self.assertEqual((entry.source, entry.level), ("kernel", "ERROR"))

    def test_process_id_is_not_part_of_the_source(self) -> None:
        (entry,), _ = parse_text("Jan  5 09:00:01 web01 sshd[2211]: Accepted publickey for deploy", YEAR)
        self.assertEqual((entry.source, entry.level), ("sshd", "INFO"))

    def test_leap_day_needs_the_right_year(self) -> None:
        good, _ = parse_text("Feb 29 10:00:00 h p: msg", 2024)
        bad, _ = parse_text("Feb 29 10:00:00 h p: msg", 2025)
        self.assertEqual(good[0].timestamp, datetime(2024, 2, 29, 10, 0, 0))
        self.assertIsNone(bad[0].timestamp)


class Access(unittest.TestCase):
    LINE = '203.0.113.5 - - [05/Jan/2026:10:02:30 +0000] "POST /api/checkout HTTP/1.1" 500 97 "-" "x"'

    def test_server_error_is_an_error(self) -> None:
        (entry,), _ = parse_text(self.LINE, YEAR)
        self.assertEqual((entry.level, entry.source), ("ERROR", "access"))
        self.assertEqual(entry.timestamp, datetime(2026, 1, 5, 10, 2, 30))

    def test_levels_follow_the_status_class(self) -> None:
        def level(status: str) -> str:
            line = f'1.2.3.4 - - [05/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" {status} 1'
            return parse_text(line, YEAR)[0][0].level

        self.assertEqual((level("200"), level("302"), level("404"), level("503")), ("INFO", "INFO", "WARNING", "ERROR"))

    def test_client_address_is_not_in_the_message(self) -> None:
        (entry,), _ = parse_text(self.LINE, YEAR)
        self.assertNotIn("203.0.113.5", entry.message)

    def test_time_zone_is_applied(self) -> None:
        line = '1.2.3.4 - - [05/Jan/2026:10:00:00 -0500] "GET / HTTP/1.1" 200 1'
        self.assertEqual(parse_text(line, YEAR)[0][0].timestamp, datetime(2026, 1, 5, 15, 0, 0))


class Garbage(unittest.TestCase):
    def test_random_text_never_raises_and_never_loses_lines(self) -> None:
        rng = random.Random(7)
        alphabet = string.printable + "éß漢字\x00\x07"
        for _ in range(300):
            lines = [
                "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 80))) for _ in range(rng.randrange(0, 12))
            ]
            parser = LogParser(YEAR)
            entries = []
            for line in lines:
                entries.extend(parser.feed(line))
            entries.extend(parser.finish())
            non_blank = sum(1 for line in lines if line.strip())
            self.assertEqual(parser.stats.lines, non_blank)
            self.assertEqual(len(entries) == 0, non_blank == 0)

    def test_pathological_lines(self) -> None:
        nasty = ["{" * 5000, "[" * 5000, "9" * 100_000, "\\" * 10_000, "a:" * 20_000]
        entries, _ = parse_text("\n".join(nasty), YEAR)
        self.assertGreaterEqual(len(entries), 1)


class Levels(unittest.TestCase):
    def test_aliases(self) -> None:
        self.assertEqual(
            [normalize_level(x) for x in ("warn", "FATAL", " err ", "trace")], ["WARNING", "CRITICAL", "ERROR", "DEBUG"]
        )
        self.assertIsNone(normalize_level("loud"))

    def test_at_least(self) -> None:
        self.assertEqual(levels_at_least("error"), ["ERROR", "CRITICAL"])
        with self.assertRaises(InputValidationError):
            levels_at_least("loud")


class Times(unittest.TestCase):
    NOW = datetime(2026, 1, 6, 12, 0, 0)

    def test_absolute_formats(self) -> None:
        self.assertEqual(parse_timestamp("2026-01-05"), datetime(2026, 1, 5))
        self.assertEqual(parse_timestamp("2026-01-05 10:30"), datetime(2026, 1, 5, 10, 30))
        self.assertEqual(parse_timestamp("2026-01-05T10:30:15.250Z"), datetime(2026, 1, 5, 10, 30, 15))

    def test_rejects_bad_values(self) -> None:
        for bad in ("2026-02-30", "2026-13-01", "yesterday", "", "2026-01-05 25:00", "2026-01-05 10:00+99:99"):
            self.assertIsNone(parse_timestamp(bad), bad)

    def test_relative(self) -> None:
        self.assertEqual(parse_when("2h", self.NOW), datetime(2026, 1, 6, 10, 0, 0))
        self.assertEqual(parse_when("7d", self.NOW), datetime(2025, 12, 30, 12, 0, 0))

    def test_unusable_time_is_a_clean_error(self) -> None:
        for bad in ("soon", "99999999999999d"):
            with self.assertRaises(InputValidationError):
                parse_when(bad, self.NOW)


if __name__ == "__main__":
    unittest.main()
