"""M1 task submission, single-worker execution and recovery.

A *task* is one queued analysis request (mode + frozen refs + frozen config)
that a single worker executes synchronously.  Submission is the only place that
resolves user supplied refs: they are frozen to commit OIDs immediately, so a
running task always analyses exactly the commits the user saw when queuing it,
even if branches move afterwards.

The worker is deliberately simple: one thread, one repository, one running task
at a time.  Storage enforces those constraints atomically; this module only
orchestrates claim -> execute -> finish and never touches git or the network
itself.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import analyze, config as config_module, models, storage
from .storage import TaskRecord

Progress = Callable[[str], None]
TaskEventListener = Callable[[dict], None]

_MODE_COMMIT = models.MODE_COMMIT
_MODE_RANGE = models.MODE_RANGE
_MODE_BASE = models.MODE_BASE
_MODE_WORKING_TREE = models.MODE_WORKING_TREE

_OID_RE = re.compile(r"^[0-9a-f]{40,64}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_TERMINAL_STATUSES = {
    models.TASK_COMPLETED,
    models.TASK_PARTIAL,
    models.TASK_FAILED,
    models.TASK_CANCELLED,
    models.TASK_INTERRUPTED,
}
_MAX_DIAGNOSTICS = 200
_MAX_MESSAGE_CHARS = 300
_GIT_TIMEOUT_SECONDS = 30


@dataclass
class TaskParams:
    """One submitted analysis request (Web and CLI share this shape)."""

    mode: str
    base_ref: str | None = None
    commit_ref: str | None = None
    range_spec: str | None = None
    parent_index: int | None = None
    judge: bool = False
    include_untracked: bool = False


class TaskValidationError(Exception):
    """The submitted parameters or refs are invalid (maps to HTTP 400)."""

    def __init__(self, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.field = field


# --------------------------------------------------------------------------
# parameter validation and ref freezing
# --------------------------------------------------------------------------


def _clean_ref(value: Any, field_name: str) -> str:
    """Validate one user supplied git ref before it is passed to git."""

    if not isinstance(value, str) or not value.strip():
        raise TaskValidationError(f"{field_name} must be a non-empty string", field=field_name)
    ref = value.strip()
    if _CONTROL_RE.search(ref) or any(character.isspace() for character in ref):
        raise TaskValidationError(f"{field_name} contains invalid characters", field=field_name)
    if ref.startswith("-"):
        raise TaskValidationError(f"{field_name} must not start with '-'", field=field_name)
    if ".." in ref:
        raise TaskValidationError(f"{field_name} must be a single ref, not a range", field=field_name)
    if len(ref) > 512:
        raise TaskValidationError(f"{field_name} is too long", field=field_name)
    return ref


def _parse_range_spec(spec: Any) -> tuple[str, str, str]:
    """Split ``A..B`` / ``A...B`` into (left, operator, right)."""

    if not isinstance(spec, str) or not spec.strip():
        raise TaskValidationError("range_spec must be a non-empty string", field="range_spec")
    text = spec.strip()
    if _CONTROL_RE.search(text) or any(character.isspace() for character in text):
        raise TaskValidationError("range_spec contains invalid characters", field="range_spec")
    if "..." in text:
        operator = "..."
        left, right = text.split("...", 1)
    elif ".." in text:
        operator = ".."
        left, right = text.split("..", 1)
    else:
        raise TaskValidationError(
            "range_spec must look like A..B or A...B", field="range_spec"
        )
    if not left or not right:
        raise TaskValidationError(
            "range_spec must have a ref on both sides", field="range_spec"
        )
    if ".." in left or ".." in right:
        raise TaskValidationError("range_spec has too many range separators", field="range_spec")
    left = _clean_ref(left, "range_spec")
    right = _clean_ref(right, "range_spec")
    return left, operator, right


def _validate_params(params: TaskParams) -> None:
    if not isinstance(params, TaskParams):
        raise TaskValidationError("task parameters are missing")
    mode = params.mode
    if mode not in models.ALL_MODES:
        raise TaskValidationError(
            f"unsupported mode: {mode!r} (allowed: {', '.join(models.ALL_MODES)})",
            field="mode",
        )
    if not isinstance(params.judge, bool):
        raise TaskValidationError("judge must be a boolean", field="judge")
    if not isinstance(params.include_untracked, bool):
        raise TaskValidationError("include_untracked must be a boolean", field="include_untracked")

    if params.commit_ref is not None and mode != _MODE_COMMIT:
        raise TaskValidationError(
            "commit_ref is only valid in commit mode", field="commit_ref"
        )
    if params.range_spec is not None and mode != _MODE_RANGE:
        raise TaskValidationError(
            "range_spec is only valid in range mode", field="range_spec"
        )
    if params.base_ref is not None and mode != _MODE_BASE:
        raise TaskValidationError(
            "base_ref is only valid in base mode", field="base_ref"
        )
    if params.parent_index is not None and mode != _MODE_COMMIT:
        raise TaskValidationError(
            "parent_index is only valid in commit mode", field="parent_index"
        )
    if params.parent_index is not None:
        if (
            isinstance(params.parent_index, bool)
            or not isinstance(params.parent_index, int)
            or params.parent_index < 1
        ):
            raise TaskValidationError(
                "parent_index must be a positive integer", field="parent_index"
            )
    if params.include_untracked and mode != _MODE_WORKING_TREE:
        raise TaskValidationError(
            "include_untracked is only valid in working-tree mode",
            field="include_untracked",
        )
    if mode == _MODE_COMMIT and params.commit_ref is None:
        raise TaskValidationError("commit mode requires commit_ref", field="commit_ref")
    if mode == _MODE_RANGE and params.range_spec is None:
        raise TaskValidationError("range mode requires range_spec", field="range_spec")


def _run_git(repo_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise TaskValidationError(f"cannot run git: {type(exc).__name__}") from exc


def _rev_parse_commit(repo_root: Path, ref: str, label: str) -> str:
    result = _run_git(
        repo_root,
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        ref + "^{commit}",
    )
    oid = (result.stdout or "").strip().splitlines()
    if result.returncode != 0 or not oid:
        raise TaskValidationError(f"invalid {label} ref: {ref}", field=label)
    resolved = oid[0]
    if not _OID_RE.match(resolved):
        raise TaskValidationError(f"invalid {label} ref: {ref}", field=label)
    return resolved


def _freeze_refs(
    repo_root: Path, params: TaskParams, config: Any
) -> tuple[str | None, str | None, str | None, int | None]:
    """Resolve user refs to commit OIDs.  Returns (base, commit, range, parent)."""

    mode = params.mode
    if mode == _MODE_COMMIT:
        return None, _rev_parse_commit(repo_root, params.commit_ref or "", "commit_ref"), None, params.parent_index
    if mode == _MODE_RANGE:
        left, operator, right = _parse_range_spec(params.range_spec)
        left_oid = _rev_parse_commit(repo_root, left, "range_spec")
        right_oid = _rev_parse_commit(repo_root, right, "range_spec")
        return None, None, f"{left_oid}{operator}{right_oid}", None
    if mode == _MODE_BASE:
        base_ref = params.base_ref if params.base_ref is not None else config.git.base
        if params.base_ref is not None:
            base_ref = _clean_ref(params.base_ref, "base_ref")
        return _rev_parse_commit(repo_root, base_ref, "base_ref"), None, None, None
    return None, None, None, None


# --------------------------------------------------------------------------
# submission
# --------------------------------------------------------------------------


def _frozen_config(config: Any, params: TaskParams) -> tuple[dict, str]:
    config_json = config.to_dict()
    git_section = config_json.setdefault("git", {})
    if params.mode == _MODE_WORKING_TREE:
        # The checkbox is authoritative for this task, independent of what the
        # project file currently says (the frozen config then disagrees; the
        # task record keeps include_untracked separately for display).
        git_section["include_untracked"] = bool(params.include_untracked)
    config_digest = models.digest_of(config_json)
    return config_json, config_digest


def submit_task(
    store: storage.Storage,
    repo_root: Path,
    repo_id: str,
    config: Any,
    params: TaskParams,
    *,
    task_key: str | None = None,
) -> TaskRecord:
    """Validate parameters, freeze refs/config and persist a queued task.

    Idempotency is delegated to ``store.create_task``: when ``task_key`` is
    supplied and ``(repo_id, task_key)`` already exists, the existing record is
    returned unchanged.
    """

    if not isinstance(repo_id, str) or not repo_id.strip():
        raise TaskValidationError("repo_id must be a non-empty string", field="repo_id")
    if task_key is not None:
        if not isinstance(task_key, str) or not task_key.strip():
            raise TaskValidationError("task_key must be a non-empty string", field="task_key")
        task_key = task_key.strip()
        if len(task_key) > 200 or _CONTROL_RE.search(task_key):
            raise TaskValidationError("task_key is invalid", field="task_key")

    root = Path(repo_root)
    if not root.is_dir():
        raise TaskValidationError("repository path does not exist", field="repo_root")
    root = root.resolve()

    _validate_params(params)
    base_ref, commit_ref, range_spec, parent_index = _freeze_refs(root, params, config)
    config_json, config_digest = _frozen_config(config, params)
    created_at = models.utc_now()

    request = {
        "mode": params.mode,
        "base_ref": params.base_ref,
        "commit_ref": params.commit_ref,
        "range_spec": params.range_spec,
        "parent_index": params.parent_index,
        "judge": params.judge,
        "include_untracked": params.include_untracked,
    }
    record = TaskRecord(
        task_id=models.new_run_id(),
        repo_id=repo_id,
        repo_root=str(root),
        status=models.TASK_QUEUED,
        mode=params.mode,
        base_ref=base_ref,
        commit_ref=commit_ref,
        range_spec=range_spec,
        parent_index=parent_index,
        judge=params.judge,
        include_untracked=params.include_untracked,
        request=request,
        config_digest=config_digest,
        config_json=config_json,
        stages=[],
        diagnostics=[],
        error_code=None,
        task_key=task_key,
        run_id=None,
        created_at=created_at,
        started_at=None,
        finished_at=None,
        worker_token=None,
        worker_heartbeat_at=None,
    )
    return store.create_task(record)


def submit_params_from_task(task: TaskRecord) -> TaskParams:
    """Rebuild :class:`TaskParams` from a stored task (retry pre-fill)."""

    request = getattr(task, "request", None)
    if isinstance(request, dict):
        mode = request.get("mode")
        if isinstance(mode, str) and mode in models.ALL_MODES:
            params = TaskParams(
                mode=mode,
                base_ref=_optional_str(request.get("base_ref")),
                commit_ref=_optional_str(request.get("commit_ref")),
                range_spec=_optional_str(request.get("range_spec")),
                parent_index=_optional_int(request.get("parent_index")),
                judge=bool(request.get("judge", getattr(task, "judge", False))),
                include_untracked=bool(
                    request.get("include_untracked", getattr(task, "include_untracked", False))
                ),
            )
            return params
    # Fall back to the frozen record fields.  Frozen OIDs are valid refs, so a
    # retry of a commit/range/base task reproduces the same commits.
    return TaskParams(
        mode=getattr(task, "mode"),
        base_ref=getattr(task, "base_ref", None),
        commit_ref=getattr(task, "commit_ref", None),
        range_spec=getattr(task, "range_spec", None),
        parent_index=getattr(task, "parent_index", None),
        judge=bool(getattr(task, "judge", False)),
        include_untracked=bool(getattr(task, "include_untracked", False)),
    )


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _optional_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


# --------------------------------------------------------------------------
# execution
# --------------------------------------------------------------------------


def _diagnostic_list(run: Any) -> list[dict]:
    diagnostics: list[dict] = []
    for diagnostic in getattr(run, "diagnostics", None) or ():
        if hasattr(diagnostic, "to_dict"):
            item = diagnostic.to_dict()
        elif isinstance(diagnostic, dict):
            item = dict(diagnostic)
        else:  # pragma: no cover - defensive
            continue
        diagnostics.append(item)
        if len(diagnostics) >= _MAX_DIAGNOSTICS:
            break
    return diagnostics


def _safe_exception_message(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}".replace("\n", " ").strip()
    return text[:_MAX_MESSAGE_CHARS]


def _run_status_to_task_status(run_status: str | None) -> str:
    if run_status == models.RUN_COMPLETED:
        return models.TASK_COMPLETED
    if run_status == models.RUN_PARTIAL:
        return models.TASK_PARTIAL
    if run_status == models.RUN_FAILED:
        return models.TASK_FAILED
    # A run still marked running after run_analysis returned means the pipeline
    # stopped before finishing; treat it as a failed task, never as completed.
    return models.TASK_FAILED


def _task_message(task: Any, key: str) -> Any:
    return getattr(task, key, None)


def _append_stage(store: Any, task: Any, event: dict) -> bool:
    token = _task_message(task, "worker_token")
    if not isinstance(token, str) or not token:
        return False
    try:
        return bool(
            store.append_task_stage(_task_message(task, "task_id"), token, dict(event))
        )
    except Exception:  # noqa: BLE001 - progress sinks must not break analysis
        return False


def _heartbeat(store: Any, task: Any, now: str) -> bool:
    token = _task_message(task, "worker_token")
    if not isinstance(token, str) or not token:
        return False
    try:
        return bool(store.heartbeat_task(_task_message(task, "task_id"), token, now=now))
    except Exception:  # noqa: BLE001 - best effort
        return False


def _finish(store: Any, task: Any, status: str, *, now: str, **kwargs: Any) -> bool:
    token = _task_message(task, "worker_token")
    if not isinstance(token, str) or not token:
        return False
    try:
        return bool(
            store.finish_task(
                _task_message(task, "task_id"),
                token,
                status,
                now=now,
                **kwargs,
            )
        )
    except Exception:  # noqa: BLE001 - reporting a failed finish must not raise
        return False


def execute_task(
    store: storage.Storage,
    task: TaskRecord,
    *,
    progress: Progress | None = None,
) -> dict:
    """Execute one claimed task synchronously; never raises.

    Returns a summary dict with ``task_id``, ``status`` (final task status),
    ``run_id``, ``run_status``, ``error_code``, ``diagnostics`` and ``finished``
    (whether ``finish_task`` accepted the transition).
    """

    task_id = _task_message(task, "task_id")
    existing_status = _task_message(task, "status")
    if existing_status in _TERMINAL_STATUSES:
        return {
            "task_id": task_id,
            "status": existing_status,
            "run_id": _task_message(task, "run_id"),
            "run_status": None,
            "error_code": _task_message(task, "error_code"),
            "diagnostics": [],
            "finished": False,
            "skipped": "already terminal",
        }

    started = models.utc_now()
    _heartbeat(store, task, started)

    def on_stage(stage: str, status: str, details: dict | None = None) -> None:
        payload = dict(details or {})
        at = models.utc_now()
        duration = payload.get("duration_ms")
        if isinstance(duration, bool) or not isinstance(duration, int):
            duration = 0
        event = {"stage": str(stage), "status": str(status), "at": at, "duration_ms": duration}
        _append_stage(store, task, event)
        _heartbeat(store, task, at)

    run = None
    try:
        config = config_module.config_from_dict(_task_message(task, "config_json") or {})
        run_analysis = analyze.run_analysis
        run = _call_run_analysis(
            run_analysis,
            Path(str(_task_message(task, "repo_root"))),
            config,
            task,
            getattr(store, "db_path", None),
            on_stage,
            progress,
        )
        outcome = run
        analysis_run = getattr(outcome, "run", None) if not isinstance(outcome, models.AnalysisRun) else outcome
        run_id = _linked_run_id(store, task_id, _run_id_of(run))
        run_status = getattr(analysis_run, "status", None)
        mapped_status = _run_status_to_task_status(run_status)
        diagnostics = _diagnostic_list(analysis_run)
        error_code = None
        if mapped_status == models.TASK_FAILED:
            error_code = _failed_error_code(analysis_run, outcome)
        finished = _finish(
            store,
            task,
            mapped_status,
            now=models.utc_now(),
            run_id=run_id,
            diagnostics=diagnostics,
            error_code=error_code,
        )
        return {
            "task_id": task_id,
            "status": mapped_status,
            "run_id": run_id,
            "run_status": run_status,
            "error_code": error_code,
            "diagnostics": diagnostics,
            "finished": finished,
        }
    except Exception as exc:  # noqa: BLE001 - a bad task must not kill the worker
        message = _safe_exception_message(exc)
        diagnostic = models.Diagnostic(
            code="task_execution_failed",
            message=message,
            severity="error",
            details={"task_id": task_id},
        ).to_dict()
        on_stage("execute", "failed", {"duration_ms": 0})
        partial_run_id = _linked_run_id(store, task_id, _run_id_of(run))
        finished = _finish(
            store,
            task,
            models.TASK_FAILED,
            now=models.utc_now(),
            run_id=partial_run_id,
            diagnostics=[diagnostic],
            error_code="execution_exception",
        )
        return {
            "task_id": task_id,
            "status": models.TASK_FAILED,
            "run_id": partial_run_id,
            "run_status": None,
            "error_code": "execution_exception",
            "diagnostics": [diagnostic],
            "finished": finished,
        }


def _run_id_of(outcome: Any) -> str | None:
    """Extract a run id from an ``AnalysisOutcome`` / ``AnalysisRun`` / None."""

    if outcome is None:
        return None
    if isinstance(outcome, models.AnalysisRun):
        return outcome.run_id
    run_id = getattr(getattr(outcome, "run", None), "run_id", None)
    if isinstance(run_id, str):
        return run_id
    run_id = getattr(outcome, "run_id", None)
    return run_id if isinstance(run_id, str) else None


def _linked_run_id(store: Any, task_id: str, fallback: str | None) -> str | None:
    if getattr(store, "db_path", None) is None:
        return fallback
    # create_run links the task and Run in one transaction. An in-memory outcome
    # can contain a generated ID even when that transaction failed.
    try:
        task = store.get_task(task_id)
    except storage.StorageError:
        return None
    return task.run_id if task is not None else None


def _call_run_analysis(
    run_analysis: Any,
    repo_root: Path,
    config: Any,
    task: Any,
    db_path: Path | None,
    on_stage: Callable[[str, str, dict], None],
    progress: Progress | None,
) -> Any:
    """Call the pipeline with the M1 contract keyword arguments."""

    return run_analysis(
        repo_root,
        config,
        mode=_task_message(task, "mode"),
        base_ref=_task_message(task, "base_ref"),
        commit_ref=_task_message(task, "commit_ref"),
        range_spec=_task_message(task, "range_spec"),
        parent_index=_task_message(task, "parent_index"),
        judge=bool(_task_message(task, "judge")),
        progress=progress,
        task_id=_task_message(task, "task_id"),
        db_path=db_path,
        worker_token=_task_message(task, "worker_token"),
        on_stage=on_stage,
    )


def _failed_error_code(analysis_run: Any, outcome: Any) -> str:
    for diagnostic in getattr(analysis_run, "diagnostics", None) or ():
        if getattr(diagnostic, "severity", None) == "error":
            code = getattr(diagnostic, "code", None)
            if isinstance(code, str) and code:
                return code
    error = getattr(outcome, "error", None)
    if isinstance(error, str) and error:
        return "analysis_failed"
    return "analysis_failed"


# --------------------------------------------------------------------------
# single-thread worker
# --------------------------------------------------------------------------


class TaskWorker:
    """One background thread polling for queued tasks of one repository."""

    def __init__(
        self,
        store: storage.Storage,
        repo_id: str,
        *,
        interval: float = 0.5,
        stale_seconds: int = 30,
        on_event: TaskEventListener | None = None,
    ) -> None:
        self.store = store
        self.repo_id = repo_id
        self.interval = max(0.01, float(interval))
        self.stale_seconds = max(1, int(stale_seconds))
        self.on_event = on_event
        self.worker_token = f"worker-{uuid.uuid4().hex}"
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._recovery_due = 0.0

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._recover_stale(self.store)
        self._thread = threading.Thread(
            target=self._loop,
            name=f"patchpilot-worker-{self.repo_id[:8]}",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=max(0.0, float(timeout)))
            if not thread.is_alive():
                self._thread = None

    def __enter__(self) -> "TaskWorker":
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.stop()

    # -- events -----------------------------------------------------------
    def _emit(self, event: dict) -> None:
        if self.on_event is None:
            return
        try:
            self.on_event(dict(event))
        except Exception:  # noqa: BLE001 - observers are best effort
            pass

    def _recover_stale(self, store: storage.Storage) -> None:
        self._recovery_due = time.monotonic() + min(5.0, self.stale_seconds / 2)
        try:
            recovered = store.recover_stale_tasks(
                now=models.utc_now(), stale_seconds=self.stale_seconds, repo_id=self.repo_id
            )
        except Exception as exc:  # noqa: BLE001 - recovery problems are surfaced, not fatal
            self._emit({"event": "recover_error", "error": type(exc).__name__})
            return
        for item in recovered or ():
            if isinstance(item, dict):
                self._emit({"event": "recovered", **item})

    # -- main loop --------------------------------------------------------
    def _loop(self) -> None:
        db_path = getattr(self.store, "db_path", None)
        polling_store = storage.Storage(db_path) if db_path is not None else self.store
        try:
            while not self._stop.is_set():
                try:
                    processed = self._run_once(polling_store)
                except Exception as exc:  # noqa: BLE001 - keep polling after a bad batch
                    self._emit({"event": "error", "error": type(exc).__name__})
                    processed = False
                if not processed and not self._stop.is_set():
                    self._stop.wait(self.interval)
        finally:
            if db_path is not None:
                polling_store.close()

    def run_once(self) -> bool:
        """Claim and execute at most one task; ``True`` when a task was handled."""
        return self._run_once(self.store)

    def _run_once(self, store: storage.Storage) -> bool:
        if time.monotonic() >= self._recovery_due:
            self._recover_stale(store)
        task = store.claim_next_task(
            self.repo_id,
            self.worker_token,
            now=models.utc_now(),
            lease_seconds=self.stale_seconds,
        )
        if task is None:
            return False
        self._emit(
            {
                "event": "claimed",
                "task_id": _task_message(task, "task_id"),
                "mode": _task_message(task, "mode"),
            }
        )
        stopped = threading.Event()
        db_path = getattr(store, "db_path", None)
        lease = None
        if db_path is not None:
            lease = threading.Thread(
                target=self._keep_lease, args=(db_path, task, stopped),
                name="patchpilot-task-heartbeat", daemon=True,
            )
            lease.start()
        try:
            result = execute_task(store, task)
        finally:
            stopped.set()
            if lease is not None:
                lease.join()
        self._emit({"event": "finished", **result})
        return True

    def _keep_lease(self, db_path: Path, task: TaskRecord, stopped: threading.Event) -> None:
        store = storage.Storage(db_path)
        try:
            while not stopped.wait(min(5.0, self.stale_seconds / 3)):
                _heartbeat(store, task, models.utc_now())
        finally:
            store.close()
