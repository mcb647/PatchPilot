"""Analysis pipeline orchestration.

The pipeline follows the plan's stage order and commits each stage in its own
short transaction:

    create run + snapshot manifest
    -> file changes / line diffs
    -> old & new AST indexes
    -> symbol changes
    -> impact candidates
    -> test recommendations
    -> finish run

A failure in one stage keeps the evidence committed by earlier stages and is
recorded as a structured diagnostic; the run then finishes as ``partial``.
Capture failures before any analysis commit finish as ``failed`` but still
leave a queryable run row (with an empty snapshot).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import ast_index, changes, git_snapshot, impact, models, recommend, storage
from .config import Config, resolve_db_path
from .models import (
    JUDGE_COMPLETED,
    JUDGE_DISABLED,
    MODE_BASE,
    MODE_COMMIT,
    MODE_RANGE,
    MODE_STAGED,
    MODE_WORKING_TREE,
    RUN_COMPLETED,
    RUN_FAILED,
    RUN_PARTIAL,
    SUMMARY_CANDIDATES_FOUND,
    SUMMARY_NO_CANDIDATES,
    SUMMARY_NO_CHANGES,
    SUMMARY_UNKNOWN,
    AnalysisRun,
    Diagnostic,
    Snapshot,
    SnapshotSide,
)

Progress = Callable[[str], None]
StageCallback = Callable[[str, str, dict[str, Any]], None]


@dataclass
class AnalysisOutcome:
    run: AnalysisRun
    detail: Any | None = None  # storage.RunDetail when committed
    exit_code: int = 0
    error: str | None = None
    db_path: str | None = None


@dataclass
class _PipelineState:
    diagnostics: list[Diagnostic] = field(default_factory=list)
    stage_timings: dict[str, int] = field(default_factory=dict)
    stage_errors: list[str] = field(default_factory=list)
    truncated: bool = False
    on_stage: Any = None
    cache: dict[str, int] = field(
        default_factory=lambda: {"ast_hits": 0, "ast_misses": 0, "judge_hits": 0}
    )

    def add(self, diagnostic: Diagnostic) -> None:
        self.diagnostics.append(diagnostic)


_COVERAGE_GAP_CODES = {
    "diff_limit",
    "side_unavailable",
    "symbol_mapping_unknown",
    "object_missing",
    "python_limit",
    "edge_limit",
}


def _emit(progress: Progress | None, message: str) -> None:
    if progress is not None:
        progress(message)


def _emit_stage(
    on_stage: StageCallback | None,
    stage: str,
    status: str,
    **details: Any,
) -> None:
    """Report one enumerated stage event without letting a sink break analysis."""

    if on_stage is None:
        return
    try:
        on_stage(stage, status, dict(details))
    except Exception:  # noqa: BLE001 - progress sinks are best effort
        pass


def _endpoint_labels(
    mode: str,
    base_ref: str | None,
    commit_ref: str | None = None,
    range_spec: str | None = None,
) -> tuple[str, str]:
    base = base_ref or "main"
    if mode == MODE_STAGED:
        return "HEAD", "index"
    if mode == MODE_WORKING_TREE:
        return "index", "worktree"
    if mode == MODE_BASE:
        return f"merge-base({base}, HEAD)", "HEAD"
    if mode == MODE_COMMIT:
        rev = commit_ref or "REV"
        return f"{rev} parent", rev
    if mode == MODE_RANGE:
        spec = range_spec or "A..B"
        return f"range {spec}", spec.split("..", 1)[-1] if ".." in spec else spec
    return "HEAD", "worktree"


def _empty_snapshot(
    repo_root: Path,
    config: Config,
    mode: str,
    base_ref: str | None,
    commit_ref: str | None = None,
    range_spec: str | None = None,
) -> Snapshot:
    before_label, after_label = _endpoint_labels(
        mode, base_ref, commit_ref=commit_ref, range_spec=range_spec
    )
    return Snapshot(
        mode=mode,
        repo_root=str(repo_root),
        repo_id=models.repo_id_for(repo_root),
        display_name=models.repo_display_name(repo_root),
        branch=None,
        detached=False,
        endpoint_before=before_label,
        endpoint_after=after_label,
        before=SnapshotSide(side=models.SIDE_BEFORE),
        after=SnapshotSide(side=models.SIDE_AFTER),
        config_digest=config.digest(),
    )


def _error_stage_diag(stage: str, exc: BaseException) -> Diagnostic:
    detail = f"{type(exc).__name__}: {exc}"
    if len(detail) > 500:
        detail = detail[:497] + "..."
    return Diagnostic(
        code=f"{stage}_failed",
        message=f"analysis stage '{stage}' failed: {detail}",
        severity="error",
        details={"stage": stage, "exception": type(exc).__name__},
    )


def _run_stage(
    stage: str,
    state: _PipelineState,
    progress: Progress | None,
    func: Callable[[], Any],
) -> Any | None:
    _emit(progress, f"[{stage}] ...")
    on_stage: StageCallback | None = state.on_stage
    _emit_stage(on_stage, stage, "start")
    started = time.perf_counter()
    try:
        value = func()
    except Exception as exc:  # noqa: BLE001 - stage isolation is intentional
        state.stage_errors.append(stage)
        state.add(_error_stage_diag(stage, exc))
        state.stage_timings[stage] = int((time.perf_counter() - started) * 1000)
        _emit_stage(
            on_stage,
            stage,
            "failed",
            duration_ms=state.stage_timings[stage],
            error=type(exc).__name__,
        )
        _emit(progress, f"[{stage}] failed: {type(exc).__name__}: {exc}")
        return None
    state.stage_timings[stage] = int((time.perf_counter() - started) * 1000)
    _emit_stage(on_stage, stage, "done", duration_ms=state.stage_timings[stage])
    _emit(progress, f"[{stage}] done in {state.stage_timings[stage]} ms")
    return value


def _count_metric(index: Any) -> dict[str, Any]:
    if index is None:
        return {}
    stats = getattr(index, "stats", None) or {}
    data = dict(stats) if isinstance(stats, dict) else {}
    return data


def run_analysis(
    repo_root: Path,
    config: Config,
    mode: str | None = None,
    base_ref: str | None = None,
    *,
    commit_ref: str | None = None,
    range_spec: str | None = None,
    parent_index: int | None = None,
    judge: bool = False,
    coverage: Any = None,
    task_id: str | None = None,
    db_path: Path | None = None,
    worker_token: str | None = None,
    on_stage: StageCallback | None = None,
    progress: Progress | None = None,
) -> AnalysisOutcome:
    """Run the analysis pipeline and persist every stage."""

    repo_root = Path(repo_root)
    effective_mode = mode or config.git.mode
    selected_base = base_ref or config.git.base
    judge_requested = bool(judge)
    repo_id = models.repo_id_for(repo_root)
    db_path = db_path if db_path is not None else resolve_db_path(config, repo_id)
    store = storage.Storage(
        db_path,
        evidence_mode=config.storage.evidence_mode,
        max_evidence_bytes_per_run=config.storage.max_evidence_bytes_per_run,
        task_owner=(task_id, worker_token) if task_id and worker_token else None,
    )
    store.initialize()
    state = _PipelineState()
    state.on_stage = on_stage

    _emit(progress, f"capturing snapshot ({effective_mode}) ...")
    _emit_stage(on_stage, "snapshot", "start", mode=effective_mode)
    started_stamp = models.utc_now()
    try:
        snapshot = git_snapshot.capture(
            repo_root,
            config,
            mode=effective_mode,
            base_ref=selected_base if effective_mode == MODE_BASE else None,
            commit_ref=commit_ref if effective_mode == MODE_COMMIT else None,
            range_spec=range_spec if effective_mode == MODE_RANGE else None,
            parent_index=parent_index if effective_mode == MODE_COMMIT else None,
        )
    except git_snapshot.SnapshotError as exc:
        _emit_stage(on_stage, "snapshot", "failed", error=type(exc).__name__)
        empty = _empty_snapshot(
            repo_root,
            config,
            effective_mode,
            selected_base,
            commit_ref=commit_ref,
            range_spec=range_spec,
        )
        run = AnalysisRun(
            run_id=models.new_run_id(),
            repo_id=repo_id,
            display_name=models.repo_display_name(repo_root),
            repo_root=str(repo_root),
            branch=None,
            detached=False,
            mode=effective_mode,
            endpoint_before=empty.endpoint_before,
            endpoint_after=empty.endpoint_after,
            started_at=started_stamp,
            config_digest=config.digest(),
            task_id=task_id,
        )
        state.add(
            Diagnostic(
                code="snapshot_failed",
                message=str(exc),
                severity="error",
                details={"mode": effective_mode},
            )
        )
        metrics = {"stages": {}, "errors": ["snapshot"]}
        try:
            store.create_run(run, empty)
            store.finish_run(
                run.run_id,
                RUN_FAILED,
                SUMMARY_UNKNOWN,
                metrics,
                state.diagnostics,
            )
        finally:
            store.close()
        run.status = RUN_FAILED
        run.summary = SUMMARY_UNKNOWN
        run.finished_at = models.utc_now()
        run.metrics = metrics
        run.diagnostics = list(state.diagnostics)
        return AnalysisOutcome(
            run=run,
            exit_code=1,
            error=f"snapshot capture failed: {exc}",
            db_path=str(db_path),
        )

    run = AnalysisRun(
        run_id=models.new_run_id(),
        repo_id=repo_id,
        display_name=snapshot.display_name,
        repo_root=snapshot.repo_root,
        branch=snapshot.branch,
        detached=snapshot.detached,
        mode=snapshot.mode,
        endpoint_before=snapshot.endpoint_before,
        endpoint_after=snapshot.endpoint_after,
        started_at=started_stamp,
        config_digest=config.digest(),
        task_id=task_id,
    )
    run.diagnostics = list(snapshot.diagnostics)
    state.diagnostics.extend(snapshot.diagnostics)
    if any(d.severity == "error" for d in snapshot.diagnostics):
        state.truncated = True

    _emit_stage(
        on_stage,
        "snapshot",
        "done",
        endpoint_before=snapshot.endpoint_before,
        endpoint_after=snapshot.endpoint_after,
    )
    _emit(progress, f"captured snapshot: {snapshot.endpoint_before} -> {snapshot.endpoint_after}")
    try:
        store.create_run(run, snapshot)
    except Exception as exc:  # local storage failure is fatal
        store.close()
        run.status = RUN_FAILED
        run.finished_at = models.utc_now()
        return AnalysisOutcome(
            run=run,
            exit_code=1,
            error=f"local storage error: {type(exc).__name__}: {exc}",
            db_path=str(db_path),
        )

    # ---- stage 1: file changes and line diffs --------------------------
    change_list = _run_stage(
        "changes",
        state,
        progress,
        lambda: _changes_stage(store, run.run_id, snapshot, config),
    )
    if change_list is None:
        change_list = []

    # ---- stage 2: AST indexes (with optional AST cache) -----------------
    before_result = _run_stage(
        "ast_before",
        state,
        progress,
        lambda: _index_stage(store, run.run_id, snapshot.before, config, state),
    )
    before_index = before_result[0] if before_result is not None else None
    before_hit = bool(before_result[1]) if before_result is not None else False
    after_result = _run_stage(
        "ast_after",
        state,
        progress,
        lambda: _index_stage(store, run.run_id, snapshot.after, config, state),
    )
    after_index = after_result[0] if after_result is not None else None
    after_hit = bool(after_result[1]) if after_result is not None else False
    if before_index is not None:
        state.cache["ast_hits"] += int(before_hit)
        state.cache["ast_misses"] += int(not before_hit)
    if after_index is not None:
        state.cache["ast_hits"] += int(after_hit)
        state.cache["ast_misses"] += int(not after_hit)

    for _side, _index in (("before", before_index), ("after", after_index)):
        if _index is None:
            continue
        for diagnostic in getattr(_index, "diagnostics", []) or []:
            if diagnostic.severity in ("warning", "error"):
                state.diagnostics.append(diagnostic)

    # ---- stage 3: symbol changes ---------------------------------------
    symbol_change_list: list[models.SymbolChange] = []
    if before_index is not None and after_index is not None:
        mapped = _run_stage(
            "symbol_changes",
            state,
            progress,
            lambda: _symbol_changes_stage(
                store, run.run_id, change_list, before_index, after_index
            ),
        )
        if mapped is not None:
            symbol_change_list = mapped
    else:
        state.add(
            Diagnostic(
                code="symbol_mapping_skipped",
                message="symbol mapping skipped because one side could not be indexed",
                severity="warning",
            )
        )

    # ---- stage 4: impact candidates ------------------------------------
    candidate_list: list[models.ImpactCandidate] = []
    if before_index is not None and after_index is not None and symbol_change_list:
        candidates = _run_stage(
            "impacts",
            state,
            progress,
            lambda: impact.trace_impacts(
                symbol_change_list, before_index, after_index, config
            ),
        )
        if candidates is not None:
            candidate_list = candidates
            limit = config.analysis.max_candidates_per_run
            if len(candidate_list) > limit:
                candidate_list = candidate_list[:limit]
                state.truncated = True
                state.add(
                    Diagnostic(
                        code="candidate_limit",
                        message=(
                            f"candidate list truncated to the run limit of {limit}; "
                            "impact coverage is incomplete"
                        ),
                        severity="warning",
                        details={"limit": limit},
                    )
                )
            _run_stage(
                "save_impacts",
                state,
                progress,
                lambda: store.save_impacts(run.run_id, candidate_list),
            )
            if "save_impacts" in state.stage_errors:
                candidate_list = []
    elif change_list:
        state.add(
            Diagnostic(
                code="impact_skipped",
                message="impact tracing skipped: no usable symbol changes",
                severity="warning",
            )
        )

    # ---- stage 5: test recommendations (strong + weak) -----------------
    test_list: list[models.TestRecommendation] = []
    if (
        before_index is not None
        and after_index is not None
        and (candidate_list or symbol_change_list)
    ):
        recs = _run_stage(
            "tests",
            state,
            progress,
            lambda: recommend.recommend_tests(
                candidate_list,
                symbol_change_list,
                before_index,
                after_index,
                changes=change_list,
                coverage=coverage,
            ),
        )
        if recs is not None:
            test_list = recs
            _run_stage(
                "save_tests",
                state,
                progress,
                lambda: store.save_tests(run.run_id, test_list),
            )
            if "save_tests" in state.stage_errors:
                test_list = []

    # ---- stage 6: Judge (P1, explicit opt-in) --------------------------
    judge_status = JUDGE_DISABLED
    judge_metrics: dict[str, Any] = {}
    if judge_requested:
        judge_result = _judge_stage(
            store,
            run.run_id,
            config,
            state,
            progress,
            symbol_change_list,
            candidate_list,
            change_list,
            before_index,
            after_index,
            snapshot,
        )
        if judge_result is not None:
            judge_status = judge_result[0]
            judge_metrics = judge_result[1]
            state.cache["judge_hits"] += int(judge_metrics.get("cache_hits", 0))

    # ---- aggregate diagnostics and metrics -----------------------------
    for change in change_list:
        state.diagnostics.extend(change.diagnostics)
    for symbol_change in symbol_change_list:
        state.diagnostics.extend(symbol_change.diagnostics)
    state.diagnostics.extend(_mapping_unknown_diagnostics(change_list, before_index, after_index))
    state.diagnostics = _dedupe_diagnostics(state.diagnostics)
    coverage_incomplete = any(d.code in _COVERAGE_GAP_CODES for d in state.diagnostics)
    if judge_requested and judge_status != JUDGE_COMPLETED:
        coverage_incomplete = True
    state.truncated |= coverage_incomplete

    metrics = {
        "changes": len(change_list),
        "symbol_changes": len(symbol_change_list),
        "candidates": len(candidate_list),
        "tests": len(test_list),
        "stages": dict(state.stage_timings),
        "stage_errors": list(state.stage_errors),
        "analysis": {
            "max_depth": config.analysis.max_depth,
            "max_candidates_per_change": config.analysis.max_candidates_per_change,
            "max_candidates_per_run": config.analysis.max_candidates_per_run,
            "max_edges": config.analysis.max_edges,
            "rename_similarity_threshold": config.analysis.rename_similarity_threshold,
        },
        "before": _count_metric(before_index),
        "after": _count_metric(after_index),
        "truncated": bool(state.truncated),
        "snapshot_diagnostics": len(snapshot.diagnostics),
        "cache": dict(state.cache),
        "judge": {
            "requested": judge_requested,
            "status": judge_status,
            **judge_metrics,
        },
    }

    summary, status = _derive_status(state, change_list, candidate_list, coverage_incomplete)
    run.status = status
    run.summary = summary
    run.finished_at = models.utc_now()
    run.metrics = metrics
    run.diagnostics = list(state.diagnostics)

    try:
        store.finish_run(run.run_id, status, summary, metrics, state.diagnostics, run.finished_at)
    except Exception as exc:  # noqa: BLE001
        state.add(
            Diagnostic(
                code="finish_run_failed",
                message=f"could not finalise run record: {type(exc).__name__}: {exc}",
                severity="error",
            )
        )
        run.status = RUN_PARTIAL
        status = RUN_PARTIAL
        summary = SUMMARY_UNKNOWN

    detail = None
    try:
        detail = store.load_run(run.run_id)
    except Exception:  # noqa: BLE001 - query layer problems are reported via error
        detail = None

    exit_code = 0 if status == RUN_COMPLETED else (3 if status == RUN_PARTIAL else 1)
    error = None
    if status != RUN_COMPLETED:
        error = _first_error_message(state.diagnostics)
    store.close()
    _emit(progress, f"run {run.run_id} finished as {status} ({summary})")
    return AnalysisOutcome(
        run=run,
        detail=detail,
        exit_code=exit_code,
        error=error,
        db_path=str(db_path),
    )


# --------------------------------------------------------------------------
# stage helpers
# --------------------------------------------------------------------------


def _changes_stage(
    store: storage.Storage,
    run_id: str,
    snapshot: Snapshot,
    config: Config,
) -> list[models.Change]:
    change_list = changes.compute_changes(snapshot, config)
    store.save_changes(run_id, change_list)
    return change_list


def _index_stage(
    store: storage.Storage,
    run_id: str,
    side: SnapshotSide,
    config: Config,
) -> Any:
    index = ast_index.build_index(side, config)
    store.save_index(run_id, index)
    return index


def _symbol_changes_stage(
    store: storage.Storage,
    run_id: str,
    change_list: list[models.Change],
    before_index: Any,
    after_index: Any,
) -> list[models.SymbolChange]:
    mapped = changes.map_symbol_changes(change_list, before_index, after_index)
    store.save_symbol_changes(run_id, mapped)
    return mapped


def _ast_cache_key(side: SnapshotSide, config: Config) -> str:
    """Content-addressed key for the per-side AST index cache."""

    relevant = {
        "source_roots": list(config.files.source_roots),
        "max_edges": config.analysis.max_edges,
        "max_python_files_per_side": config.analysis.max_python_files_per_side,
        "max_python_bytes_per_side": config.analysis.max_python_bytes_per_side,
    }
    return models.digest_of(
        {
            "schema": models.SCHEMA_VERSION,
            "analyzer": models.ANALYZER_VERSION,
            "snapshot_format": models.SNAPSHOT_FORMAT_VERSION,
            "ast_cache_format": ast_index.CACHE_FORMAT_VERSION,
            "side": side.side,
            "manifest": side.manifest_digest,
            "config": relevant,
        }
    )


def _index_stage(
    store: storage.Storage,
    run_id: str,
    side: SnapshotSide,
    config: Config,
    state: _PipelineState,
) -> tuple[Any, bool]:
    """Build one side index, reusing (and populating) the AST cache."""

    cache_key = _ast_cache_key(side, config)
    cache_enabled = config.cache.ast_enabled and config.storage.evidence_mode != "metadata_only"
    if cache_enabled:
        try:
            cached = store.cache_get("ast", cache_key)
        except Exception:  # noqa: BLE001 - cache problems must not break analysis
            cached = None
        if cached:
            try:
                index = ast_index.Index.from_cache_dict(side.side, cached, config)
            except Exception:  # noqa: BLE001 - stale/corrupt cache entry -> rebuild
                index = None
            if index is not None:
                store.save_index(run_id, index)
                return index, True
    index = ast_index.build_index(side, config)
    store.save_index(run_id, index)
    if cache_enabled:
        try:
            store.cache_put(
                "ast",
                cache_key,
                index.to_cache_dict(),
                ttl_seconds=max(0, config.cache.ttl_days) * 86400,
                max_total_bytes=config.cache.max_bytes,
            )
        except Exception:  # noqa: BLE001 - cache writes are best effort
            pass
    return index, False


class _JudgeCache:
    """Adapt the generic storage cache to the Judge runner's small protocol."""

    def __init__(self, store: storage.Storage, config: Config) -> None:
        self.store = store
        self.ttl_seconds = max(0, config.cache.ttl_days) * 86400
        self.max_bytes = config.cache.max_bytes

    def get(self, kind: str, key: str) -> dict | None:
        return self.store.cache_get(kind, key)

    def put(self, kind: str, key: str, value: dict, ttl_seconds: int | None = None) -> None:
        self.store.cache_put(
            kind,
            key,
            value,
            ttl_seconds=self.ttl_seconds if ttl_seconds is None else ttl_seconds,
            max_total_bytes=self.max_bytes,
        )


def _judge_stage(
    store: storage.Storage,
    run_id: str,
    config: Config,
    state: _PipelineState,
    progress: Progress | None,
    symbol_changes: list[models.SymbolChange],
    candidates: list[models.ImpactCandidate],
    change_list: list[models.Change],
    before_index: Any,
    after_index: Any,
    snapshot: Snapshot,
) -> tuple[str, dict[str, Any]] | None:
    """Run the P1 Judge pipeline; Judge problems never fail the static run."""

    _emit(progress, "[judge] ...")
    started = time.perf_counter()
    if before_index is None or after_index is None or not candidates or not symbol_changes:
        state.add(
            Diagnostic(
                code="judge_skipped",
                message="Judge skipped: no impact candidates with complete snapshot indexes",
                severity="info",
            )
        )
        return JUDGE_DISABLED, {"attempts": 0, "verdicts": 0}
    try:
        from .judge import context as judge_context
        from .judge import runner as judge_runner
    except Exception as exc:  # noqa: BLE001 - optional P1 component
        state.add(
            Diagnostic(
                code="judge_unavailable",
                message=f"Judge package is unavailable: {type(exc).__name__}: {exc}",
                severity="error",
            )
        )
        return JUDGE_DISABLED, {"attempts": 0, "verdicts": 0}
    try:
        judge_config = config
        if not config.judge.enabled:
            import copy

            judge_config = copy.deepcopy(config)
            judge_config.judge.enabled = True
        contexts = judge_context.build_contexts(
            symbol_changes,
            candidates,
            change_list,
            before_index,
            after_index,
            snapshot,
            judge_config,
        )
        cache = _JudgeCache(store, judge_config) if judge_config.cache.judge_enabled else None
        store.require_task_ownership()
        result = judge_runner.run_judge(
            contexts=contexts,
            config=judge_config,
            cache=cache,
            progress=None,
        )
    except Exception as exc:  # noqa: BLE001 - stage isolation
        state.stage_errors.append("judge")
        state.add(_error_stage_diag("judge", exc))
        state.stage_timings["judge"] = int((time.perf_counter() - started) * 1000)
        return JUDGE_DISABLED, {"attempts": 0, "verdicts": 0}
    try:
        store.save_judge_attempts(run_id, list(result.attempts))
        store.save_judge_verdicts(run_id, list(result.verdicts))
    except Exception as exc:  # noqa: BLE001
        state.stage_errors.append("save_judge")
        state.add(_error_stage_diag("save_judge", exc))
    state.diagnostics.extend(result.diagnostics)
    metrics = dict(result.metrics)
    metrics["attempts"] = len(result.attempts)
    metrics["verdicts"] = len(result.verdicts)
    state.stage_timings["judge"] = int((time.perf_counter() - started) * 1000)
    _emit(progress, f"[judge] {result.status} ({len(result.verdicts)} verdict(s))")
    return result.status, metrics


def _mapping_unknown_diagnostics(
    change_list: list[models.Change],
    before_index: Any,
    after_index: Any,
) -> list[Diagnostic]:
    """Surface files whose symbol mapping was skipped because one side is unparsable."""

    out: list[Diagnostic] = []
    if before_index is None or after_index is None:
        return out
    before_errors = getattr(before_index, "parse_errors", {}) or {}
    after_errors = getattr(after_index, "parse_errors", {}) or {}
    seen: set[str] = set()
    for change in change_list:
        if change.analysis_status != "analyzed":
            continue
        for path in (change.old_path, change.new_path):
            if not path or path in seen:
                continue
            if path in before_errors or path in after_errors:
                seen.add(path)
                out.append(
                    Diagnostic(
                        code="symbol_mapping_unknown",
                        message=(
                            f"symbol changes for {path} are unknown because one side "
                            "could not be parsed"
                        ),
                        severity="warning",
                        path=path,
                        details={
                            "before_parse_error": path in before_errors,
                            "after_parse_error": path in after_errors,
                        },
                    )
                )
    return out


def _first_error_message(diagnostics: list[Diagnostic]) -> str | None:
    for diagnostic in diagnostics:
        if diagnostic.severity == "error":
            return diagnostic.message
    for diagnostic in diagnostics:
        if diagnostic.code in _COVERAGE_GAP_CODES:
            return diagnostic.message
    return "analysis completed with warnings" if diagnostics else None


def _dedupe_diagnostics(diagnostics: list[Diagnostic]) -> list[Diagnostic]:
    """Keep the report readable while preserving first-seen order."""

    seen: set[tuple[Any, ...]] = set()
    unique: list[Diagnostic] = []
    for diagnostic in diagnostics:
        key = (
            diagnostic.code,
            diagnostic.severity,
            diagnostic.path,
            diagnostic.line,
            diagnostic.message,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(diagnostic)
    return unique


def _derive_status(
    state: _PipelineState,
    change_list: list[models.Change],
    candidate_list: list[models.ImpactCandidate],
    coverage_incomplete: bool,
) -> tuple[str, str]:
    """Return ``(summary, run_status)`` following the plan's semantics.

    Any error or coverage gap makes the run ``partial``; the business summary stays
    ``unknown`` in that case because coverage is known to be incomplete.  A run
    that completed within its declared capability bounds reports
    ``no_changes``/``no_candidates``/``candidates_found``.
    """

    has_error = any(d.severity == "error" for d in state.diagnostics)
    if has_error or coverage_incomplete:
        return SUMMARY_UNKNOWN, RUN_PARTIAL
    if not change_list:
        return SUMMARY_NO_CHANGES, RUN_COMPLETED
    if not candidate_list:
        if state.truncated:
            return SUMMARY_UNKNOWN, RUN_PARTIAL
        return SUMMARY_NO_CANDIDATES, RUN_COMPLETED
    return SUMMARY_CANDIDATES_FOUND, RUN_COMPLETED
