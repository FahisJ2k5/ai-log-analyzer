"""Fingerprinting, classification and redaction."""

from __future__ import annotations

import unittest

from log_analyzer.classifier import CATEGORIES, classify
from log_analyzer.fingerprint import fingerprint, headline, make_template
from log_analyzer.redact import MAX_PROMPT_CHARS, prepare_for_model, redact


def fp(message: str) -> str:
    return fingerprint(make_template(message))


class Fingerprints(unittest.TestCase):
    def test_variable_parts_do_not_change_the_group(self) -> None:
        a = fp("Connection to 10.0.0.5:5432 timed out after 30s")
        b = fp("Connection to 10.0.0.9:5432 timed out after 12s")
        self.assertEqual(a, b)

    def test_ids_paths_and_hex_are_masked(self) -> None:
        self.assertEqual(
            fp("job 7f3a9c1e-1b2d-4c5e-9f00-aabbccddeeff failed"), fp("job 00000000-0000-0000-0000-000000000000 failed")
        )
        self.assertEqual(fp("cannot open /var/data/a.csv"), fp("cannot open /srv/other/b.csv"))
        self.assertEqual(fp("pointer 0xdeadbeef bad"), fp("pointer 0x1234 bad"))
        self.assertEqual(fp("commit a1b2c3d4e5f6 broke it"), fp("commit 99887766aabb broke it"))

    def test_emails_are_masked(self) -> None:
        self.assertEqual(fp("login failed for a@x.com"), fp("login failed for someone.else@example.org"))

    def test_different_problems_stay_apart(self) -> None:
        self.assertNotEqual(fp("disk full"), fp("out of memory"))

    def test_http_status_is_kept_so_500_and_502_differ(self) -> None:
        self.assertNotEqual(fp("POST /api/x HTTP/1.1 -> 500"), fp("POST /api/x HTTP/1.1 -> 502"))

    def test_digits_inside_words_are_not_masked(self) -> None:
        self.assertEqual(make_template("port 40022 ssh2"), "port <num> ssh2")

    def test_ordinary_words_that_look_like_hex_survive(self) -> None:
        self.assertIn("defaced", make_template("the page was defaced"))

    def test_only_the_first_line_counts(self) -> None:
        self.assertEqual(fp("crashed\ntrace A"), fp("crashed\ntrace B"))
        self.assertEqual(headline("a\nb"), "a")

    def test_case_and_spacing_are_ignored(self) -> None:
        self.assertEqual(fp("Disk   FULL"), fp("disk full"))

    def test_is_stable_and_short(self) -> None:
        self.assertEqual(fp("x"), fp("x"))
        self.assertEqual(len(fp("x")), 12)

    def test_empty_message(self) -> None:
        self.assertEqual(len(fp("")), 12)


class Classification(unittest.TestCase):
    def check(self, message: str, expected: str, level: str = "ERROR") -> None:
        self.assertEqual(classify(level, message), expected, msg=message)

    def test_each_category(self) -> None:
        self.check("Out of memory: killed process 4211", "out_of_memory")
        self.check("No space left on device", "disk")
        self.check("Authentication failed for user bob", "authentication")
        self.check("Failed password for invalid user admin", "authentication")
        self.check("Connection to db timed out after 30s", "timeout")
        self.check("deadlock detected in transaction", "database")
        self.check("connect() failed (111: Connection refused)", "network")
        self.check("POST /api/x HTTP/1.1 -> 500", "server_error")
        self.check("file config.yml not found", "not_found")
        self.check("missing config value", "configuration")
        self.check("request validation failed", "validation")
        self.check("worker crashed", "crash")

    def test_specific_beats_general(self) -> None:
        self.check("database connection timed out", "timeout")
        self.check("SSL certificate verify failed: connection reset", "network")

    def test_stack_trace_details_cannot_relabel_the_entry(self) -> None:
        trace = "Unhandled exception in job\nTraceback (most recent call last):\n  ...\nKeyError: 'x'"
        self.check(trace, "crash")

    def test_trace_details_can_make_an_otherwise_plain_entry_a_crash(self) -> None:
        self.check("job failed\nTraceback (most recent call last):\nRuntimeError: boom", "crash")

    def test_low_levels_are_info_whatever_they_say(self) -> None:
        self.check("timed out", "info", level="INFO")
        self.check("timed out", "info", level="DEBUG")

    def test_unparsed_lines_are_still_classified(self) -> None:
        self.check("something timed out", "timeout", level="UNKNOWN")

    def test_nothing_matches(self) -> None:
        self.check("cache miss rate high", "unclassified", level="WARNING")

    def test_every_returned_category_is_declared(self) -> None:
        for message in ("x", "timed out", "disk full", "->500"):
            self.assertIn(classify("ERROR", message), CATEGORIES)


class Redaction(unittest.TestCase):
    def test_key_value_secrets(self) -> None:
        for text in (
            "password=hunter2",
            "PASSWORD: hunter2",
            'secret="hunter2"',
            "api_key=hunter2",
            "token: hunter2",
            "client_secret=hunter2",
        ):
            cleaned = redact(f"login with {text} now")
            self.assertNotIn("hunter2", cleaned, text)
            self.assertIn("<redacted>", cleaned, text)

    def test_json_style_secrets(self) -> None:
        cleaned = redact('{"password": "hunter2", "user": "bob"}')
        self.assertNotIn("hunter2", cleaned)
        self.assertIn("bob", cleaned)

    def test_authorization_headers(self) -> None:
        for text in (
            "Authorization: Bearer abcdef123456",
            "authorization=Basic dXNlcjpwYXNz",
            "Authorization: Token abc123def456",
        ):
            self.assertNotIn("abcdef123456", redact(text))
        self.assertNotIn("dXNlcjpwYXNz", redact("authorization=Basic dXNlcjpwYXNz"))
        self.assertNotIn("abc123def456", redact("Authorization: Token abc123def456"))

    def test_bearer_token_anywhere(self) -> None:
        self.assertNotIn("abcdefgh12345678", redact("sent Bearer abcdefgh12345678 to api"))

    def test_well_known_token_shapes(self) -> None:
        fake_secrets = [
            "sk-" + "a" * 24,
            "ghp_" + "b" * 30,
            "AKIA" + "C" * 16,
            "xoxb-" + "1" * 12,
            "eyJhbGciOi.eyJzdWIiOiIx.c2lnbmF0dXJl",
        ]
        for secret in fake_secrets:
            self.assertNotIn(secret, redact(f"value {secret} here"), secret)

    def test_password_inside_a_url(self) -> None:
        cleaned = redact("connect postgres://admin:hunter2@db.internal:5432/app")
        self.assertNotIn("hunter2", cleaned)
        self.assertIn("admin", cleaned)

    def test_private_key_block(self) -> None:
        block = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\ndef\n-----END RSA PRIVATE KEY-----"
        cleaned = redact(f"key:\n{block}\nafter")
        self.assertNotIn("MIIabc", cleaned)
        self.assertIn("after", cleaned)

    def test_email_and_ip(self) -> None:
        cleaned = redact("user alice@example.com from 203.0.113.9")
        self.assertNotIn("alice@example.com", cleaned)
        self.assertNotIn("203.0.113.9", cleaned)
        self.assertIn("<email>", cleaned)
        self.assertIn("<ip>", cleaned)

    def test_ordinary_text_is_untouched(self) -> None:
        text = "Connection to database timed out after 30 seconds"
        self.assertEqual(redact(text), text)

    def test_is_idempotent(self) -> None:
        once = redact("password=hunter2 from 203.0.113.9")
        self.assertEqual(redact(once), once)

    def test_redacts_before_truncating(self) -> None:
        # A secret that straddles the size limit must be masked, not cut in half and sent.
        secret = "password=" + "S3cretValue" * 5
        text = "x" * (MAX_PROMPT_CHARS - 12) + secret
        sent = prepare_for_model(text)
        self.assertNotIn("S3cretValue", sent)
        self.assertNotIn("S3cret", sent)

    def test_output_is_bounded(self) -> None:
        sent = prepare_for_model("a" * 100_000)
        self.assertLessEqual(len(sent), MAX_PROMPT_CHARS + 20)
        self.assertTrue(sent.endswith("[truncated]"))


if __name__ == "__main__":
    unittest.main()
