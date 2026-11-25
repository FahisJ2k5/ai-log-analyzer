"""Settings, read from environment variables only.

Secrets are never hardcoded and never written to disk by this package. The API
key is wrapped in ``Secret`` so that printing the settings object, logging it,
or showing it in a traceback cannot reveal the value.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from log_analyzer.errors import ConfigError

DEFAULT_DB = "log_analyzer.db"
DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_TIMEOUT_SECONDS = 300.0


class Secret:
    """Holds a sensitive string. The only way to read it is the explicit ``reveal()`` call."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret('**********')"

    __str__ = __repr__

    def __bool__(self) -> bool:
        return bool(self._value)


@dataclass(frozen=True)
class Settings:
    db_path: str = DEFAULT_DB
    api_key: Secret | None = field(default=None, repr=False)
    model: str | None = None
    timeout_text: str | None = None

    @property
    def llm_configured(self) -> bool:
        return self.api_key is not None

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> Settings:
        key = environ.get("ANTHROPIC_API_KEY", "").strip()
        model = environ.get("ANTHROPIC_MODEL", "").strip()
        return cls(
            db_path=environ.get("LOG_ANALYZER_DB", "").strip() or DEFAULT_DB,
            api_key=Secret(key) if key else None,
            model=model or None,
            timeout_text=environ.get("LOG_ANALYZER_LLM_TIMEOUT", "").strip() or None,
        )

    def timeout_seconds(self) -> float:
        """Parsed lazily, so a bad value only affects commands that call the model."""
        if self.timeout_text is None:
            return DEFAULT_TIMEOUT_SECONDS
        try:
            value = float(self.timeout_text)
        except ValueError:
            raise ConfigError("LOG_ANALYZER_LLM_TIMEOUT must be a number of seconds") from None
        if not 0 < value <= MAX_TIMEOUT_SECONDS:
            raise ConfigError(f"LOG_ANALYZER_LLM_TIMEOUT must be between 0 and {MAX_TIMEOUT_SECONDS:g} seconds")
        return value
