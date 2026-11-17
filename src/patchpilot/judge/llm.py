"""OpenAI-compatible ``chat/completions`` LLM adapter (standard library only).

Endpoint and credentials come from fixed environment variables so the project
configuration never stores secrets: ``PATCHPILOT_LLM_ENDPOINT`` and
``PATCHPILOT_LLM_API_KEY``.  The model name comes from
``config.judge.llm.model``.

Error categories follow ``models.JUDGE_ERROR_*``: timeout, auth, rate_limited,
unavailable and invalid_output.  Error messages only carry a category and a
short reason; the API key is never included, and the raw provider body is never
propagated anywhere.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from typing import Any

from .. import models
from ..config import Config
from .contract import AdapterResult, JudgeAdapterError, JudgeRequest

MAX_RESPONSE_BYTES = 256 * 1024
_USER_AGENT = "PatchPilot/0.2 (+local impact judge)"

SYSTEM_PROMPT = (
    "You are PatchPilot's conservative impact judge. You receive a changed Python "
    "symbol and one statically resolved caller path. Decide whether the change can "
    "affect the caller. Reply with ONLY a JSON object using this schema: "
    '{"candidate_id": string, "verdict": "affected" | "unaffected" | "uncertain", '
    '"reason": string (non-empty, <=1000 chars), "evidence": [{"evidence_id": '
    'string, "path": string, "side": "before" | "after", "start_line": integer, '
    '"end_line": integer}], "conditions": [string, ...] (<=10), "uncertainty": '
    "string or null (<=300 chars)}. Cite only evidence ids that appear in the "
    "context; never invent paths or line ranges."
)


class LlmAdapter:
    """One OpenAI-compatible endpoint; one model; one timeout."""

    name = "llm"

    def __init__(
        self,
        endpoint: str,
        *,
        model: str,
        api_key: str | None = None,
        timeout_seconds: int = 20,
        max_output_tokens: int = 800,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self._api_key = (api_key or "").strip() or None
        self._timeout_seconds = max(1, int(timeout_seconds))
        self._max_output_tokens = max(1, int(max_output_tokens))

    # -- helpers ----------------------------------------------------------
    @property
    def request_url(self) -> str:
        return self.endpoint + "/chat/completions"

    def _build_body(self, request: JudgeRequest) -> dict[str, Any]:
        context_text = request.context.text if request.context is not None else ""
        return {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": context_text},
            ],
            "temperature": 0,
            "max_tokens": self._max_output_tokens,
            "response_format": {"type": "json_object"},
            "stream": False,
        }

    @staticmethod
    def _http_error_category(status: int) -> str:
        if status in (401, 403):
            return models.JUDGE_ERROR_AUTH
        if status == 429:
            return models.JUDGE_ERROR_RATE_LIMITED
        if status >= 500:
            return models.JUDGE_ERROR_UNAVAILABLE
        return models.JUDGE_ERROR_INVALID_OUTPUT

    @staticmethod
    def _is_timeout(reason: Any) -> bool:
        if isinstance(reason, (socket.timeout, TimeoutError)):
            return True
        return "timed out" in str(reason).lower()

    # -- adapter interface ------------------------------------------------
    def classify(self, request: JudgeRequest) -> AdapterResult:
        if request.context is None or not request.context.text:
            raise JudgeAdapterError(
                models.JUDGE_ERROR_CONTEXT_INSUFFICIENT,
                "no context text available for the LLM request",
            )

        body = json.dumps(self._build_body(request), ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        timeout = self._timeout_seconds
        if request.deadline_seconds and request.deadline_seconds > 0:
            timeout = max(1, min(timeout, int(request.deadline_seconds)))

        http_request = urllib.request.Request(
            self.request_url,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(http_request, timeout=timeout) as response:
                payload_bytes = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            category = self._http_error_category(int(exc.code))
            raise JudgeAdapterError(
                category, f"llm endpoint returned HTTP {int(exc.code)}"
            ) from None
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            reason = getattr(exc, "reason", exc)
            if self._is_timeout(reason):
                raise JudgeAdapterError(
                    models.JUDGE_ERROR_TIMEOUT, "llm request timed out"
                ) from None
            raise JudgeAdapterError(
                models.JUDGE_ERROR_UNAVAILABLE, "llm endpoint is unavailable"
            ) from None
        except OSError:
            raise JudgeAdapterError(
                models.JUDGE_ERROR_UNAVAILABLE, "llm endpoint is unavailable"
            ) from None

        if len(payload_bytes) > MAX_RESPONSE_BYTES:
            raise JudgeAdapterError(
                models.JUDGE_ERROR_INVALID_OUTPUT,
                "llm response exceeds the 256KB limit",
            )

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise JudgeAdapterError(
                models.JUDGE_ERROR_INVALID_OUTPUT, "llm response is not valid JSON"
            ) from None
        if not isinstance(payload, dict):
            raise JudgeAdapterError(
                models.JUDGE_ERROR_INVALID_OUTPUT, "llm response is not a JSON object"
            )

        request_id = payload.get("id")
        if not isinstance(request_id, str):
            request_id = None
        usage = payload.get("usage")
        if not isinstance(usage, dict):
            usage = {}

        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise JudgeAdapterError(
                models.JUDGE_ERROR_INVALID_OUTPUT, "llm response has no choices"
            )
        first = choices[0]
        if not isinstance(first, dict):
            raise JudgeAdapterError(
                models.JUDGE_ERROR_INVALID_OUTPUT, "llm response has no choices"
            )
        message = first.get("message")
        if not isinstance(message, dict):
            raise JudgeAdapterError(
                models.JUDGE_ERROR_INVALID_OUTPUT, "llm response has no message"
            )
        content = message.get("content")
        raw: Any
        if isinstance(content, dict):
            raw = content
        elif isinstance(content, str):
            try:
                raw = json.loads(content)
            except ValueError:
                raise JudgeAdapterError(
                    models.JUDGE_ERROR_INVALID_OUTPUT,
                    "llm message content is not valid JSON",
                ) from None
        else:
            raise JudgeAdapterError(
                models.JUDGE_ERROR_INVALID_OUTPUT, "llm message content is missing"
            )
        if not isinstance(raw, dict):
            raise JudgeAdapterError(
                models.JUDGE_ERROR_INVALID_OUTPUT,
                "llm message content must be a JSON object",
            )
        return AdapterResult(
            adapter=self.name,
            model=self.model,
            raw=raw,
            request_id=request_id,
            usage=usage,
        )


def build_llm_adapter(config: Config) -> LlmAdapter | None:
    """Build the LLM adapter when protocol, endpoint and model are all configured."""

    if config.judge.llm.protocol != "openai":
        return None
    endpoint = os.environ.get("PATCHPILOT_LLM_ENDPOINT", "").strip()
    model = config.judge.llm.model
    if not endpoint or not model:
        return None
    api_key = os.environ.get("PATCHPILOT_LLM_API_KEY", "").strip()
    return LlmAdapter(
        endpoint,
        model=model,
        api_key=api_key,
        timeout_seconds=config.judge.timeout_seconds,
        max_output_tokens=config.judge.max_output_tokens_per_attempt,
    )
