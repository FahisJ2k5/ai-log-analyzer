"""Exception types. Each carries a stable ``code`` so callers can react without parsing text."""

from __future__ import annotations


class LogAnalyzerError(Exception):
    """Base class for every error this package raises on purpose."""

    code = "log_analyzer_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class InputValidationError(LogAnalyzerError):
    """A value supplied by the user is not acceptable."""

    code = "invalid_input"


class InputFileError(LogAnalyzerError):
    """A log file could not be read, or is not a text log."""

    code = "input_file_error"


class StorageError(LogAnalyzerError):
    """The SQLite database could not be opened or used."""

    code = "storage_error"


class NotFoundError(LogAnalyzerError):
    """Nothing matches the requested identifier."""

    code = "not_found"


class ConfigError(LogAnalyzerError):
    """An environment variable has an unusable value."""

    code = "config_error"


class LLMDisabledError(LogAnalyzerError):
    """AI explanations were requested but are not configured."""

    code = "llm_disabled"


class LLMError(LogAnalyzerError):
    """The language-model service failed or returned something unusable."""

    code = "llm_error"
