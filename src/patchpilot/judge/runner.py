"""Judge orchestration: JEV first, LLM fallback, budgets, attempts and caching.

The runner never stores raw adapter requests or responses.  Only validated
verdicts and normalized attempt metadata (digest, sizes, token estimate,
duration, category) leave this module, so a database or diagnostic dump cannot
leak source excerpts or provider payloads.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .. import models
from ..config import Config
from . import jev, llm
from .contract import (
    AdapterResult,
    JudgeAdapterError,
    JudgeContext,
    JudgeRequest,
    validate_verdict,
)
from .context import contains_secret

Progress = Callable[[str], None]

# Attempt adapter values: real adapters plus the two synthetic kinds.
_ADAPTER_CACHE = "cache"
_ADAPTER_CONTEXT = "context"


@dataclass
class JudgeRunResult:
    status: str
    attempts: list[models.JudgeAttempt] = field(default_factory=list)
    verdicts: list[models.JudgeVerdict] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    diagnostics: list[models.Diagnostic] = field(default_factory=list)


def _monotonic() -> float:
    return time.monotonic()


def _elapsed(start: float) -> float:
    return _monotonic() - start


def _safe_message(exc: BaseException) -> str:
    """Error text that never contains credentials or secret-looking values."""

    text = str(exc) or exc.__class__.__name__
    key = os.environ.get("PATCHPILOT_LLM_API_KEY", "").strip()
    if key:
        text = text.replace(key, "***")
    if contains_secret(text):
        return "adapter error (details redacted)"
    return text[:200]


def _diag(
    code: str,
    message: str,
    severity: str = "warning",
    details: dict[str, Any] | None = None,
) -> models.Diagnostic:
    return models.diag(code, message, severity=severity, details=dict(details or {}))


# --------------------------------------------------------------------------
# cache plumbing (duck typed; storage may expose .get/.put or .cache_get/_put)
# --------------------------------------------------------------------------


def _cache_get(cache: Any, kind: str, key: str) -> Any:
    for name in ("get", "cache_get"):
        function = getattr(cache, name, None)
        if callable(function):
            return function(kind, key)
    return None


def _cache_put(cache: Any, kind: str, key: str, value: dict, ttl_seconds: int) -> None:
    for name in ("put", "cache_put"):
        function = getattr(cache, name, None)
        if not callable(function):
            continue
        try:
            function(kind, key, value, ttl_seconds=ttl_seconds)
        except TypeError:
            function(kind, key, value)
        return


def _cache_key(context: JudgeContext, adapter: Any, config: Config) -> str:
    payload = {
        "context_digest": context.digest,
        "adapter": getattr(adapter, "name", "unknown"),
        "model": getattr(adapter, "model", None) or "",
        "schema_version": models.JUDGE_SCHEMA_VERSION,
        "prompt_version": models.JUDGE_PROMPT_VERSION,
        "fallback_on": list(config.judge.fallback_on),
        "side": context.side,
    }
    return hashlib.sha256(models.canonical_json(payload).encode("utf-8")).hexdigest()


def _cache_value(verdict: models.JudgeVerdict) -> dict[str, Any]:
    return {
        "candidate_id": verdict.candidate_id,
        "verdict": verdict.verdict,
        "reason": verdict.reason,
        "evidence": list(verdict.evidence),
        "conditions": list(verdict.conditions),
        "uncertainty": verdict.uncertainty,
        "schema_version": verdict.schema_version,
        "adapter": verdict.adapter,
        "model": verdict.model,
    }


def _verdict_from_cache(value: Any, context: JudgeContext) -> models.JudgeVerdict:
    if not isinstance(value, dict):
        raise ValueError("cached verdict is not an object")
    if value.get("candidate_id") != context.candidate_id:
        raise ValueError("cached verdict belongs to another candidate")
    verdict = value.get("verdict")
    if verdict not in (models.VERDICT_AFFECTED, models.VERDICT_UNAFFECTED):
        raise ValueError("only affected/unaffected verdicts are cached")
    reason = value.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("cached verdict is missing a reason")
    evidence = value.get("evidence") or []
    if not isinstance(evidence, list):
        raise ValueError("cached verdict evidence must be a list")
    conditions = value.get("conditions") or []
    if not isinstance(conditions, list):
        conditions = []
    uncertainty = value.get("uncertainty")
    if uncertainty is not None and not isinstance(uncertainty, str):
        uncertainty = None
    schema_version = value.get("schema_version", models.JUDGE_SCHEMA_VERSION)
    if not isinstance(schema_version, int):
        schema_version = models.JUDGE_SCHEMA_VERSION
    return models.JudgeVerdict(
        candidate_id=context.candidate_id,
        attempt_no=0,
        verdict=verdict,
        reason=reason,
        adapter=value.get("adapter") or "cache",
        model=value.get("model"),
        evidence=list(evidence),
        conditions=list(conditions),
        uncertainty=uncertainty,
        schema_version=schema_version,
    )


# --------------------------------------------------------------------------
# run state
# --------------------------------------------------------------------------


class _RunState:
    def __init__(
        self,
        config: Config,
        cache: Any,
        adapters: list[Any],
        contexts: list[JudgeContext],
    ) -> None:
        self.config = config
        self.cache = cache
        self.adapters = adapters
        self.contexts = contexts
        self.attempts: list[models.JudgeAttempt] = []
        self.verdicts: list[models.JudgeVerdict] = []
        self.diagnostics: list[models.Diagnostic] = []
        self.tokens_estimated = 0
        self.cache_hits = 0
        self.fallback_count = 0
        self.start = _monotonic()

    # -- records ----------------------------------------------------------
    def record_attempt(
        self,
        context: JudgeContext,
        attempt_no: int,
        *,
        adapter: str,
        model: str | None,
        started_at: str,
        duration_ms: float,
        valid: bool,
        cache_hit: bool = False,
        error_category: str | None = None,
        fallback_reason: str | None = None,
        request_id: str | None = None,
        usage: dict | None = None,
    ) -> models.JudgeAttempt:
        context_bytes = len(context.text.encode("utf-8", "replace"))
        attempt = models.JudgeAttempt(
            attempt_id=f"att:{context.candidate_id}:{attempt_no:02d}",
            candidate_id=context.candidate_id,
            attempt_no=attempt_no,
            adapter=adapter,
            model=model,
            started_at=started_at,
            duration_ms=max(0, int(duration_ms)),
            context_digest=context.digest,
            context_bytes=context_bytes,
            context_tokens_estimate=context.estimated_tokens,
            cache_hit=cache_hit,
            valid=valid,
            error_category=error_category,
            fallback_reason=fallback_reason,
            request_id=request_id,
            context_summary={
                "side": context.side,
                "evidence": len(context.evidence),
                "omitted": list(context.omitted),
                "tokens": context.estimated_tokens,
                "bytes": context_bytes,
            },
            usage=dict(usage or {}),
        )
        self.attempts.append(attempt)
        return attempt

    def diagnostic(self, code: str, message: str, severity: str = "warning", **details: Any) -> None:
        self.diagnostics.append(_diag(code, message, severity=severity, details=details))


# --------------------------------------------------------------------------
# per candidate judging
# --------------------------------------------------------------------------


def _make_request(
    context: JudgeContext,
    config: Config,
    attempt_no: int,
    deadline_remaining: float,
) -> JudgeRequest:
    remaining = max(1, int(deadline_remaining))
    return JudgeRequest(
        request_id=f"req:{context.candidate_id}:{attempt_no:02d}",
        candidate_id=context.candidate_id,
        symbol_change_id=context.symbol_change_id,
        context=context,
        deadline_seconds=min(config.judge.timeout_seconds, remaining),
    )


def _lookup_cache(state: _RunState, key: str) -> Any:
    if state.cache is None or not state.config.cache.judge_enabled:
        return None
    try:
        return _cache_get(state.cache, "judge", key)
    except Exception as exc:  # cache must never break judging
        state.diagnostic(
            "judge_cache_error",
            f"judge cache read failed: {type(exc).__name__}",
            severity="info",
        )
        return None


def _store_cache(state: _RunState, key: str, verdict: models.JudgeVerdict) -> None:
    if state.cache is None or not state.config.cache.judge_enabled:
        return
    ttl_seconds = max(0, int(state.config.cache.ttl_days)) * 86400
    try:
        _cache_put(state.cache, "judge", key, _cache_value(verdict), ttl_seconds)
    except Exception as exc:  # cache must never break judging
        state.diagnostic(
            "judge_cache_error",
            f"judge cache write failed: {type(exc).__name__}",
            severity="info",
        )


def _record_context_failure(
    state: _RunState,
    context: JudgeContext,
    category: str,
) -> None:
    started_at = models.utc_now()
    state.record_attempt(
        context,
        1,
        adapter=_ADAPTER_CONTEXT,
        model=None,
        started_at=started_at,
        duration_ms=0,
        valid=False,
        error_category=category,
    )
    state.diagnostic(
        "judge_context_insufficient",
        "judge context is insufficient; adapter was not called",
        severity="info",
        candidate_id=context.candidate_id,
        reasons=list(context.omitted),
    )


def _judge_candidate(
    state: _RunState, context: JudgeContext
) -> tuple[models.JudgeVerdict | None, str | None]:
    """Judge one candidate; returns ``(verdict, stop_reason)``.

    ``stop_reason`` is set when a run-wide budget (attempts, wall clock or total
    tokens) was exhausted and the remaining candidates must be skipped.
    """

    config = state.config
    if "context_insufficient" in context.omitted or context.estimated_tokens == 0:
        _record_context_failure(state, context, models.JUDGE_ERROR_CONTEXT_INSUFFICIENT)
        return None, None
    if context.estimated_tokens > config.judge.max_input_tokens_per_attempt:
        _record_context_failure(state, context, models.JUDGE_ERROR_CONTEXT_INSUFFICIENT)
        return None, None

    attempt_no = 0
    trigger: str | None = None

    for position, adapter in enumerate(state.adapters):
        if len(state.attempts) >= config.judge.max_attempts:
            return None, "max_attempts"
        elapsed = _elapsed(state.start)
        if elapsed >= config.judge.run_deadline_seconds:
            return None, "deadline"
        if state.tokens_estimated + context.estimated_tokens > config.judge.max_total_tokens:
            return None, "max_total_tokens"

        attempt_no += 1
        request = _make_request(
            context,
            config,
            attempt_no,
            config.judge.run_deadline_seconds - elapsed,
        )
        cache_key = _cache_key(context, adapter, config)
        cached_value = _lookup_cache(state, cache_key)
        if cached_value is not None:
            try:
                cached_verdict = _verdict_from_cache(cached_value, context)
            except (TypeError, ValueError) as exc:
                state.diagnostic(
                    "judge_cache_invalid",
                    f"ignoring invalid cached verdict: {type(exc).__name__}",
                    severity="info",
                )
            else:
                started_at = models.utc_now()
                attempt = state.record_attempt(
                    context,
                    attempt_no,
                    adapter=_ADAPTER_CACHE,
                    model=cached_verdict.model,
                    started_at=started_at,
                    duration_ms=0,
                    valid=True,
                    cache_hit=True,
                )
                cached_verdict.attempt_no = attempt_no
                attempt.cache_hit = True
                state.cache_hits += 1
                return cached_verdict, None

        started_at = models.utc_now()
        monotonic_start = _monotonic()
        try:
            result = adapter.classify(request)
            if not isinstance(result, AdapterResult):
                raise JudgeAdapterError(
                    models.JUDGE_ERROR_INVALID_OUTPUT,
                    "adapter returned an unexpected result type",
                )
            if not isinstance(result.raw, dict):
                raise JudgeAdapterError(
                    models.JUDGE_ERROR_INVALID_OUTPUT,
                    "adapter output must be a JSON object",
                )
            verdict = validate_verdict(result.raw, request)
            duration_ms = (_monotonic() - monotonic_start) * 1000.0
            verdict.attempt_no = attempt_no
            verdict.adapter = result.adapter or getattr(adapter, "name", "unknown")
            verdict.model = (
                result.model
                if result.model is not None
                else getattr(adapter, "model", None)
            )
            state.tokens_estimated += context.estimated_tokens
            attempt = state.record_attempt(
                context,
                attempt_no,
                adapter=verdict.adapter,
                model=verdict.model,
                started_at=started_at,
                duration_ms=duration_ms,
                valid=True,
                request_id=result.request_id,
                usage=result.usage,
            )
        except JudgeAdapterError as exc:
            duration_ms = (_monotonic() - monotonic_start) * 1000.0
            state.tokens_estimated += context.estimated_tokens
            attempt = state.record_attempt(
                context,
                attempt_no,
                adapter=getattr(adapter, "name", "unknown"),
                model=getattr(adapter, "model", None),
                started_at=started_at,
                duration_ms=duration_ms,
                valid=False,
                error_category=exc.category,
                request_id=exc.request_id,
            )
            trigger = exc.category
            state.diagnostic(
                "judge_attempt_failed",
                f"adapter {attempt.adapter} failed with {exc.category}: {_safe_message(exc)}",
                severity="info",
                candidate_id=context.candidate_id,
                adapter=attempt.adapter,
                error_category=exc.category,
            )
        except Exception as exc:  # adapter bug or transport surprise
            duration_ms = (_monotonic() - monotonic_start) * 1000.0
            state.tokens_estimated += context.estimated_tokens
            category = (
                models.JUDGE_ERROR_TIMEOUT
                if isinstance(exc, TimeoutError)
                else models.JUDGE_ERROR_UNAVAILABLE
            )
            attempt = state.record_attempt(
                context,
                attempt_no,
                adapter=getattr(adapter, "name", "unknown"),
                model=getattr(adapter, "model", None),
                started_at=started_at,
                duration_ms=duration_ms,
                valid=False,
                error_category=category,
            )
            trigger = category
            state.diagnostic(
                "judge_attempt_failed",
                f"adapter {attempt.adapter} failed with {category}: {_safe_message(exc)}",
                severity="info",
                candidate_id=context.candidate_id,
                adapter=attempt.adapter,
                error_category=category,
            )
        else:
            if verdict.verdict == models.VERDICT_UNCERTAIN:
                if (
                    models.VERDICT_UNCERTAIN in config.judge.fallback_on
                    and position + 1 < len(state.adapters)
                ):
                    attempt.fallback_reason = models.VERDICT_UNCERTAIN
                    state.fallback_count += 1
                    trigger = models.VERDICT_UNCERTAIN
                    continue
                return verdict, None
            _store_cache(state, cache_key, verdict)
            return verdict, None

        # A trigger from ``fallback_on`` moves to the next adapter.  A merely
        # unconfigured adapter is also skipped even though ``not_configured`` is
        # not a selectable fallback trigger: it says nothing about the
        # candidate, so a second configured adapter should still get a chance.
        fallbackable = trigger in config.judge.fallback_on or (
            trigger == models.JUDGE_ERROR_NOT_CONFIGURED
        )
        if fallbackable and position + 1 < len(state.adapters):
            attempt.fallback_reason = trigger
            state.fallback_count += 1
            continue
        return None, None

    return None, None


# --------------------------------------------------------------------------
# public entry point
# --------------------------------------------------------------------------


def run_judge(
    *,
    contexts: list[JudgeContext],
    config: Config,
    cache: Any = None,
    jev_adapter: Any = None,
    llm_adapter: Any = None,
    progress: Progress | None = None,
) -> JudgeRunResult:
    """Judge every context, returning attempts, verdicts and run metrics."""

    context_list = list(contexts or ())
    attempts: list[models.JudgeAttempt] = []
    verdicts: list[models.JudgeVerdict] = []
    diagnostics: list[models.Diagnostic] = []
    started = _monotonic()

    def _metrics(**overrides: Any) -> dict[str, Any]:
        values: dict[str, Any] = {
            "attempts": len(attempts),
            "cache_hits": 0,
            "affected": 0,
            "unaffected": 0,
            "uncertain": 0,
            "failed": 0,
            "tokens_estimated": 0,
            "duration_ms": max(0, int((_monotonic() - started) * 1000.0)),
            "fallback_count": 0,
        }
        values.update(overrides)
        return values

    def _finish(status: str) -> JudgeRunResult:
        return JudgeRunResult(
            status=status,
            attempts=attempts,
            verdicts=verdicts,
            metrics=_metrics(),
            diagnostics=diagnostics,
        )

    if not config.judge.enabled:
        diagnostics.append(
            _diag(
                "judge_disabled",
                "judge is disabled by configuration",
                severity="warning",
            )
        )
        return _finish(models.JUDGE_DISABLED)

    resolved_jev = (
        jev_adapter if jev_adapter is not None else jev.build_jev_adapter(config)
    )
    resolved_llm = (
        llm_adapter if llm_adapter is not None else llm.build_llm_adapter(config)
    )
    adapters = [adapter for adapter in (resolved_jev, resolved_llm) if adapter is not None]
    if not adapters:
        diagnostics.append(
            _diag(
                "judge_not_configured",
                "judge is enabled but no adapter is configured "
                "(set judge.jev.profile=fake/http or judge.llm.protocol=openai)",
                severity="warning",
            )
        )
        return _finish(models.JUDGE_DISABLED)

    if progress is not None:
        progress(f"[judge] {len(context_list)} candidate(s), adapters="
                 + ",".join(getattr(adapter, "name", "unknown") for adapter in adapters))

    state = _RunState(config, cache, adapters, context_list)
    stop_reason: str | None = None

    for index, context in enumerate(context_list, start=1):
        if len(state.attempts) >= config.judge.max_attempts:
            stop_reason = "max_attempts"
            break
        if _elapsed(state.start) >= config.judge.run_deadline_seconds:
            stop_reason = "deadline"
            break
        verdict, candidate_stop = _judge_candidate(state, context)
        if verdict is not None:
            state.verdicts.append(verdict)
        if progress is not None:
            outcome = verdict.verdict if verdict is not None else "no verdict"
            progress(
                f"[judge] {index}/{len(context_list)} "
                f"{context.candidate_id} -> {outcome}"
            )
        if candidate_stop is not None:
            stop_reason = candidate_stop
            break

    attempts.extend(state.attempts)
    verdicts.extend(state.verdicts)
    diagnostics.extend(state.diagnostics)
    if stop_reason is not None:
        diagnostics.append(
            _diag(
                "judge_budget_exhausted",
                f"judge stopped before judging every candidate ({stop_reason})",
                severity="warning",
                details={
                    "reason": stop_reason,
                    "attempts": len(state.attempts),
                    "candidates": len(context_list),
                    "tokens_estimated": state.tokens_estimated,
                },
            )
        )

    status = (
        models.JUDGE_COMPLETED
        if len(verdicts) == len(context_list)
        else models.JUDGE_PARTIAL
    )
    if progress is not None:
        progress(
            f"[judge] finished: status={status} verdicts={len(verdicts)}/"
            f"{len(context_list)} attempts={len(attempts)} "
            f"cache_hits={state.cache_hits}"
        )

    return JudgeRunResult(
        status=status,
        attempts=attempts,
        verdicts=verdicts,
        metrics=_metrics(
            cache_hits=state.cache_hits,
            affected=sum(1 for verdict in verdicts if verdict.verdict == models.VERDICT_AFFECTED),
            unaffected=sum(1 for verdict in verdicts if verdict.verdict == models.VERDICT_UNAFFECTED),
            uncertain=sum(1 for verdict in verdicts if verdict.verdict == models.VERDICT_UNCERTAIN),
            failed=len(context_list) - len(verdicts),
            tokens_estimated=state.tokens_estimated,
            fallback_count=state.fallback_count,
        ),
        diagnostics=diagnostics,
    )
