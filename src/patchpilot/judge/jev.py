"""JEV adapter boundary.

The real JEV HTTP contract is not confirmed yet (implementation plan §7.3), so
``profile == "http"`` returns an adapter that always reports ``not_configured``
with an explanatory message instead of guessing request/authentication shapes.
``profile == "fake"`` reads a deterministic JSON fixture from the
``PATCHPILOT_JEV_FAKE`` environment variable; this is what tests and demos use.

Fixture format::

    {
      "responses": [
        {"candidate_id": "cand:...", "verdict": {"verdict": "affected", ...}},
        {"verdict": {"verdict": "unaffected", ...}}
      ],
      "default": {"verdict": "uncertain", "reason": "...", ...},
      "error": "timeout"
    }

``responses`` entries are matched by ``candidate_id``; when no entry matches (or
an entry has no ``candidate_id``) ``default`` is used.  ``error`` simulates an
adapter failure with a normalized ``models.JUDGE_ERROR_*`` category.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .. import models
from ..config import Config
from .contract import AdapterResult, JudgeAdapterError, JudgeRequest


@runtime_checkable
class JevAdapter(Protocol):
    name: str
    model: str | None

    def classify(self, request: JudgeRequest) -> AdapterResult: ...


def _not_configured(message: str) -> JudgeAdapterError:
    return JudgeAdapterError(models.JUDGE_ERROR_NOT_CONFIGURED, message)


class _FakeJevAdapter:
    name = "jev"

    def __init__(
        self,
        fixture: dict[str, Any] | None,
        *,
        model: str | None = None,
        load_error: str | None = None,
    ) -> None:
        self.model = model
        self._fixture = fixture or {}
        self._load_error = load_error
        self._requests = 0

    def _select_raw(self, request: JudgeRequest) -> dict[str, Any] | None:
        responses = self._fixture.get("responses")
        if isinstance(responses, list):
            for entry in responses:
                if not isinstance(entry, dict):
                    continue
                if entry.get("candidate_id") != request.candidate_id:
                    continue
                raw = entry.get("verdict")
                if isinstance(raw, dict):
                    return raw
        default = self._fixture.get("default")
        if isinstance(default, dict):
            nested = default.get("verdict")
            if isinstance(nested, dict):
                return nested
            return default
        return None

    def classify(self, request: JudgeRequest) -> AdapterResult:
        if self._load_error:
            raise _not_configured(self._load_error)
        error = self._fixture.get("error")
        if error:
            category = (
                error if error in models.JUDGE_ERRORS else models.JUDGE_ERROR_INVALID_OUTPUT
            )
            raise JudgeAdapterError(category, f"fake JEV fixture requested error: {error}")
        raw = self._select_raw(request)
        if raw is None:
            raise JudgeAdapterError(
                models.JUDGE_ERROR_INVALID_OUTPUT,
                "fake JEV fixture has no response for this candidate",
            )
        raw = dict(raw)
        # The fixture may use a shared ``default`` payload; the adapter is
        # responsible for echoing the candidate it was asked about.
        raw.setdefault("candidate_id", request.candidate_id)
        self._requests += 1
        return AdapterResult(
            adapter=self.name,
            model=self.model,
            raw=raw,
            request_id=f"fake-jev-{self._requests:03d}",
        )


class _UnavailableHttpJevAdapter:
    """Placeholder for the not-yet-confirmed real JEV HTTP contract."""

    name = "jev"
    model = None

    def classify(self, request: JudgeRequest) -> AdapterResult:
        raise _not_configured(
            "real JEV contract not confirmed (plan §7.3); "
            "use judge.jev.profile=fake for fixtures or leave JEV disabled"
        )


def fake_jev_adapter(config: Config) -> JevAdapter | None:
    """Build the fixture-backed JEV adapter (``judge.jev.profile == "fake"``)."""

    if config.judge.jev.profile != "fake":
        return None
    raw_path = os.environ.get("PATCHPILOT_JEV_FAKE", "").strip()
    model = config.judge.jev.model
    if not raw_path:
        return _FakeJevAdapter(None, model=model, load_error="PATCHPILOT_JEV_FAKE is not set")
    path = Path(raw_path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return _FakeJevAdapter(
            None,
            model=model,
            load_error=f"cannot read JEV fixture ({type(exc).__name__})",
        )
    try:
        fixture = json.loads(text)
    except ValueError:
        return _FakeJevAdapter(None, model=model, load_error="JEV fixture is not valid JSON")
    if not isinstance(fixture, dict):
        return _FakeJevAdapter(
            None, model=model, load_error="JEV fixture must be a JSON object"
        )
    return _FakeJevAdapter(fixture, model=model)


def http_jev_adapter(config: Config) -> JevAdapter | None:
    """Return the placeholder adapter for ``profile == "http"`` (never configured)."""

    if config.judge.jev.profile != "http":
        return None
    return _UnavailableHttpJevAdapter()


def build_jev_adapter(config: Config) -> JevAdapter | None:
    """Convenience factory used by the runner: fake first, then the http placeholder."""

    if config.judge.jev.profile == "fake":
        return fake_jev_adapter(config)
    if config.judge.jev.profile == "http":
        return http_jev_adapter(config)
    return None
