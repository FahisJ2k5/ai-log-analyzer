"""Language-model providers.

The rest of the program only knows the ``LLMProvider`` protocol, so a provider
can be swapped (or faked in tests) without touching anything else.

Security notes:
  * The key comes from the environment and is held in ``Secret``.
  * The request goes to one fixed HTTPS address. It cannot be redirected with a
    setting, so the key can only ever be sent to Anthropic.
  * Error messages never include request headers, the key, or the prompt.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Protocol

from log_analyzer.config import Secret, Settings
from log_analyzer.errors import ConfigError, LLMDisabledError, LLMError

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
MAX_RESPONSE_BYTES = 1_000_000
DEFAULT_MAX_TOKENS = 600

# (url, headers, body, timeout seconds) -> (HTTP status, response body)
Transport = Callable[[str, dict[str, str], bytes, float], tuple[int, bytes]]


class LLMProvider(Protocol):
    def complete(self, system: str, user: str) -> str:
        """Return the model's reply to ``user``, guided by ``system``."""
        ...


class DisabledProvider:
    """Used when no API key is configured. Everything else in the tool still works."""

    def complete(self, system: str, user: str) -> str:
        raise LLMDisabledError(
            "AI explanations are not configured. Set the ANTHROPIC_API_KEY and ANTHROPIC_MODEL "
            "environment variables to enable them."
        )


def urllib_transport(url: str, headers: dict[str, str], body: bytes, timeout: float) -> tuple[int, bytes]:
    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310 (fixed https URL)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, response.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_RESPONSE_BYTES)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        # Only the exception's class name is reported, never its text.
        raise LLMError(f"could not reach the language-model service ({exc.__class__.__name__})") from None


class AnthropicProvider:
    def __init__(
        self,
        api_key: Secret,
        model: str,
        timeout: float,
        transport: Transport = urllib_transport,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._timeout = timeout
        self._transport = transport
        self._max_tokens = max_tokens

    def __repr__(self) -> str:
        return f"AnthropicProvider(model={self._model!r}, api_key=Secret('**********'))"

    def complete(self, system: str, user: str) -> str:
        body = json.dumps(
            {
                "model": self._model,
                "max_tokens": self._max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            }
        ).encode("utf-8")
        headers = {
            "x-api-key": self._api_key.reveal(),
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
        }
        status, payload = self._transport(API_URL, headers, body, self._timeout)
        return self._read_reply(status, payload)

    @staticmethod
    def _read_reply(status: int, payload: bytes) -> str:
        if status in (401, 403):
            raise LLMError(f"the service rejected the API key (HTTP {status})")
        if status == 429:
            raise LLMError("the service is rate limiting requests (HTTP 429); try again shortly")
        try:
            data = json.loads(payload)
        except ValueError:
            data = None
        if status != 200:
            detail = ""
            if isinstance(data, dict) and isinstance(data.get("error"), dict):
                message = data["error"].get("message")
                if isinstance(message, str):
                    detail = f": {message[:200]}"
            raise LLMError(f"the service returned HTTP {status}{detail}")
        if not isinstance(data, dict) or not isinstance(data.get("content"), list):
            raise LLMError("the service returned a reply in an unexpected format")
        text = "".join(
            block["text"]
            for block in data["content"]
            if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str)
        ).strip()
        if not text:
            raise LLMError("the service returned an empty reply")
        return text


def make_provider(settings: Settings, transport: Transport = urllib_transport) -> LLMProvider:
    """A real provider when a key is configured, otherwise the disabled one."""
    if settings.api_key is None:
        return DisabledProvider()
    if not settings.model:
        raise ConfigError(
            "ANTHROPIC_MODEL is not set. The model name is not built in because model names change; "
            "set it to a model listed in Anthropic's documentation."
        )
    return AnthropicProvider(settings.api_key, settings.model, settings.timeout_seconds(), transport)
