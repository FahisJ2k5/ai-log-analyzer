"""Shared helpers for the test suite."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from log_analyzer.ingest import ingest_text
from log_analyzer.storage import Store

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
NOW = datetime(2026, 1, 6, 12, 0, 0)
YEAR = 2026

FAKE_KEY = "fake-key-for-tests-0123456789"


def sample_text(name: str) -> str:
    return (SAMPLES / name).read_text(encoding="utf-8")


def loaded_store(*names: str) -> Store:
    """An in-memory store with the given sample files ingested."""
    store = Store()
    for name in names:
        ingest_text(store, name, sample_text(name), YEAR, NOW)
    return store


class FakeProvider:
    """Records what it was asked and returns a fixed reply. No network, no key."""

    def __init__(self, reply: str = "It looks like a database timeout.") -> None:
        self.reply = reply
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        return self.reply
