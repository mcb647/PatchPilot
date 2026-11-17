"""SQLite persistence and query layer for PatchPilot analysis runs.

The storage layer is the only module that talks to SQLite.  It persists one
:class:`~patchpilot.models.AnalysisRun` as a small graph of rows -- run
metadata, the snapshot manifest, changes with their evidence, the per-side
symbol/call graph, symbol changes, impact candidates and test recommendations --
so the CLI, reports and the read-only web dashboard can replay an analysis
after the working tree has moved on.  P1 adds the Judge attempt/verdict tables,
the AST/Judge content caches and explicit history pruning.

Design rules (see ``docs/CONTRACTS.md`` section 5, ``docs/CONTRACTS-P1.md``
section 4 and the implementation plan section 9):

* every write method owns one short transaction (``BEGIN IMMEDIATE`` ...
  ``COMMIT``/``ROLLBACK``); a failure leaves no half written graph behind;
* foreign keys are enabled on every connection and composite foreign keys
  ``(run_id, ...)`` make cross-run references impossible;
* schema upgrades use ordered ``user_version`` migrations read from
  ``patchpilot/migrations`` through :mod:`importlib.resources`, so wheels ship
  the SQL as package data;
* read-only instances open the database through a ``mode=ro`` URI and refuse to
  write; a database created by a newer PatchPilot is refused instead of being
  silently misread.

The module intentionally has no third party dependencies; reports and the web
application consume the :class:`RunSummary` / :class:`RunDetail` DTOs below.
"""

from __future__ import annotations

import base64
import importlib.resources
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .models import (
    ALL_MODES,
    JUDGE_SCHEMA_VERSION,
    RUN_COMPLETED,
    RUN_FAILED,
    RUN_PARTIAL,
    RUN_RUNNING,
    RUN_STATUSES,
    SIDES,
    SUMMARY_UNKNOWN,
    TASK_CANCELLED,
    TASK_COMPLETED,
    TASK_FAILED,
    TASK_INTERRUPTED,
    TASK_PARTIAL,
    TASK_QUEUED,
    TASK_RUNNING,
    TASK_STATUSES,
    TEST_STRENGTH_STRONG,
    TEST_STRENGTH_WEAK,
    AnalysisRun,
    CallEdge,
    Change,
    Diagnostic,
    Hunk,
    ImpactCandidate,
    JudgeAttempt,
    JudgeVerdict,
    Snapshot,
    SnapshotEntry,
    Symbol,
    SymbolChange,
    TestRecommendation,
    dataclass_from_dict,
    dump_json,
    is_valid_run_id,
    load_json,
    persistent_edge_target,
    utc_now,
)

#: Upper bound for SQLite's busy timeout on every connection (milliseconds).
_BUSY_TIMEOUT_MS = 5000
DATABASE_SCHEMA_VERSION = 4

#: Migration scripts are named ``NNN_description.sql`` and applied in order.
_MIGRATION_NAME = re.compile(r"^(\d+)_.*\.sql$")

#: Cache ``kind`` -> table storing that cache (P1).
_CACHE_TABLES = {"ast": "ast_cache", "judge": "judge_cache"}
_CACHE_KINDS = ("ast", "judge")

#: Hard upper bound for every bounded list page (US-2 web queries).
_MAX_PAGE_LIMIT = 200

#: Child tables deleted before a run row; referencing rows come first so the
#: immediate foreign key constraints never see a dangling reference.
_PRUNE_DELETE_ORDER = (
    "judge_verdicts",
    "judge_attempts",
    "impact_candidates",
    "test_recommendations",
    "symbol_changes",
    "call_edges",
    "symbols",
    "changes",
    "snapshot_entries",
)

#: Task lifecycle states that cannot transition any more (M1).
_TASK_TERMINAL_STATUSES = (
    TASK_COMPLETED,
    TASK_PARTIAL,
    TASK_FAILED,
    TASK_CANCELLED,
    TASK_INTERRUPTED,
)

#: Map a finished run lifecycle status onto the matching task status (M1).
_RUN_TO_TASK_STATUS = {
    RUN_COMPLETED: TASK_COMPLETED,
    RUN_PARTIAL: TASK_PARTIAL,
    RUN_FAILED: TASK_FAILED,
}


def _utc_now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _cache_table(kind: str) -> str:
    try:
        return _CACHE_TABLES[kind]
    except (KeyError, TypeError):
        raise StorageError(
            f"unknown cache kind: {kind!r} (expected 'ast' or 'judge')"
        ) from None


def _cache_tables(kind: str | None) -> list[str]:
    if kind is None:
        return [_CACHE_TABLES[item] for item in _CACHE_KINDS]
    return [_cache_table(kind)]


class StorageError(Exception):
    """Raised when storage is unavailable, inconsistent or a write fails."""



# --------------------------------------------------------------------------
# read-side DTOs (used directly by reports.py and web/)
# --------------------------------------------------------------------------


@dataclass
class RunSummary:
    """One row of the history listing."""

    run_id: str
    repo_id: str
    display_name: str
    repo_root: str
    branch: str | None
    detached: bool
    mode: str
    endpoint_before: str
    endpoint_after: str
    started_at: str
    finished_at: str | None
    status: str
    summary: str
    counts: dict[str, int] = field(default_factory=dict)


@dataclass
class RunDetail:
    """Everything persisted for one analysis run."""

    run: AnalysisRun
    changes: list[Change] = field(default_factory=list)
    symbols: dict[str, Symbol] = field(default_factory=dict)
    edges: list[CallEdge] = field(default_factory=list)
    symbol_changes: list[SymbolChange] = field(default_factory=list)
    candidates: list[ImpactCandidate] = field(default_factory=list)
    test_recommendations: list[TestRecommendation] = field(default_factory=list)
    snapshot_entries: list[SnapshotEntry] = field(default_factory=list)
    # P1 Judge results; empty for runs analysed without the Judge stage and for
    # databases that never stored any Judge data.
    judge_attempts: list[JudgeAttempt] = field(default_factory=list)
    judge_verdicts: list[JudgeVerdict] = field(default_factory=list)


@dataclass
class PruneReport:
    """Result of :meth:`Storage.prune_runs`."""

    total_before: int
    retained: int
    to_delete: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    dry_run: bool = False
    running_skipped: list[str] = field(default_factory=list)


@dataclass
class TaskRecord:
    """One local analysis task (M1 queue entry).

    ``request`` and ``config_json`` are JSON-friendly dictionaries; ``stages``
    and ``diagnostics`` are JSON-friendly lists.  ``worker_token`` identifies the
    worker that currently owns a running task.
    """

    task_id: str
    repo_id: str
    repo_root: str
    status: str
    mode: str
    base_ref: str | None
    commit_ref: str | None
    range_spec: str | None
    parent_index: int | None
    judge: bool
    include_untracked: bool
    request: dict
    config_digest: str
    config_json: dict
    stages: list[dict]
    diagnostics: list[dict]
    error_code: str | None
    task_key: str | None
    run_id: str | None
    created_at: str
    started_at: str | None
    finished_at: str | None
    worker_token: str | None
    worker_heartbeat_at: str | None


@dataclass
class RunOverview:
    """Bounded first-screen summary of one run (no hunk text, no full graph).

    Used by the web run page so it never has to load the complete
    :class:`RunDetail` (hunks, call edges, all symbols) to render its header.
    """

    run: AnalysisRun
    counts: dict[str, int]
    scope: dict[str, int]
    diagnostics: list[Diagnostic]
    stages: dict[str, int]
    stage_errors: list[str]
    truncated: bool
    judge_attempts_count: int
    judge_verdicts_count: int
    judge_counts: dict[str, int]
    judge_cache_hits: int
    task_id: str | None


@dataclass
class ChangeSummary:
    """One row of the change list without any diff/hunk body text.

    ``has_hunks`` reports stored hunk ranges (not line text); in
    ``metadata_only`` mode ranges are kept while ``diff_truncated`` marks that
    no line evidence exists.
    """

    change_id: str
    old_path: str | None
    new_path: str | None
    kind: str
    analysis_status: str
    old_changed_lines: int
    new_changed_lines: int
    diff_truncated: bool
    has_hunks: bool
    symbol_change_count: int


# --------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------


class Storage:
    """SQLite backed history for one repository database.

    Parameters
    ----------
    db_path:
        Path of the SQLite database file.
    read_only:
        Open the database through a ``mode=ro`` URI and reject every write.
    evidence_mode:
        ``"excerpts"`` (default) keeps hunk lines up to the byte budget;
        ``"metadata_only"`` keeps hunk ranges/counts and graph positions,
        omitting line text and call/import target labels.
    max_evidence_bytes_per_run:
        Cumulative UTF-8 budget for stored hunk lines of one run.
    """

    def __init__(
        self,
        db_path: Path,
        read_only: bool = False,
        evidence_mode: str = "excerpts",
        max_evidence_bytes_per_run: int = 2 * 1024 * 1024,
        *,
        task_owner: tuple[str, str] | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.read_only = bool(read_only)
        self.evidence_mode = evidence_mode or "excerpts"
        self._task_owner = task_owner
        try:
            self.max_evidence_bytes_per_run = max(0, int(max_evidence_bytes_per_run))
        except (TypeError, ValueError):
            self.max_evidence_bytes_per_run = 0
        self._conn: sqlite3.Connection | None = None

    # -- connection lifecycle ------------------------------------------------

    def _ensure_conn(self) -> sqlite3.Connection:
        """Return the lazily opened connection.

        The write connection sets ``foreign_keys=ON`` and a bounded
        ``busy_timeout``; the read-only connection additionally uses a
        ``mode=ro`` URI so a mistake can never mutate the history.
        """

        if self._conn is not None:
            return self._conn
        if self.read_only:
            if not self.db_path.is_file():
                raise StorageError(f"database does not exist: {self.db_path}")
            uri = self.db_path.resolve().as_uri() + "?mode=ro"
            try:
                conn = sqlite3.connect(uri, uri=True, timeout=_BUSY_TIMEOUT_MS / 1000.0)
            except sqlite3.Error as exc:
                raise StorageError(f"cannot open database read-only: {exc}") from exc
        else:
            parent = self.db_path.parent
            if not parent.exists():
                raise StorageError(
                    f"database directory does not exist: {parent} "
                    "(call Storage.initialize() first)"
                )
            try:
                conn = sqlite3.connect(str(self.db_path), timeout=_BUSY_TIMEOUT_MS / 1000.0)
            except sqlite3.Error as exc:
                raise StorageError(f"cannot open database: {exc}") from exc
        conn.row_factory = sqlite3.Row
        # Transactions are controlled explicitly so every write phase is one
        # short BEGIN IMMEDIATE transaction.
        conn.isolation_level = None
        try:
            conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
            conn.execute("PRAGMA foreign_keys = ON")
            if self.read_only:
                conn.execute("PRAGMA query_only = ON")
        except sqlite3.Error as exc:  # pragma: no cover - hard to trigger
            conn.close()
            raise StorageError(f"cannot configure database connection: {exc}") from exc
        self._conn = conn
        return conn

    def close(self) -> None:
        """Close the underlying connection; safe to call more than once."""

        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:  # pragma: no cover - closing twice
                pass

    def initialize(self) -> None:
        """Create the database directory and apply pending migrations."""

        if self.read_only:
            raise StorageError("cannot initialize a storage opened read-only")
        parent = self.db_path.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise StorageError(f"cannot create database directory {parent}: {exc}") from exc
        conn = self._ensure_conn()
        try:
            version = self._read_user_version(conn)
        except sqlite3.Error as exc:
            raise StorageError(f"cannot read database schema version: {exc}") from exc
        if version > DATABASE_SCHEMA_VERSION:
            raise StorageError(self._newer_schema_message(version))
        if version == DATABASE_SCHEMA_VERSION:
            return
        scripts = self._migration_scripts()
        pending = range(version + 1, DATABASE_SCHEMA_VERSION + 1)
        missing = [target for target in pending if target not in scripts]
        if missing:
            raise StorageError(
                "missing database migration script(s) for schema version(s): "
                + ", ".join(str(target) for target in missing)
            )
        for target in pending:
            script = (
                "BEGIN IMMEDIATE;\n"
                + scripts[target].strip()
                + f"\nPRAGMA user_version = {int(target)};\nCOMMIT;"
            )
            try:
                conn.executescript(script)
            except sqlite3.Error as exc:
                self._rollback(conn)
                raise StorageError(
                    f"database migration to schema version {target} failed: {exc}"
                ) from exc

    def probe_schema(self) -> int:
        """Return the database ``user_version`` (0 when not initialized yet).

        A database created by a newer PatchPilot raises :class:`StorageError`
        instead of being interpreted with the wrong schema.
        """

        if not self.read_only and not self.db_path.is_file():
            return 0
        conn = self._ensure_conn()
        try:
            version = self._read_user_version(conn)
        except sqlite3.Error as exc:
            raise StorageError(f"cannot read database schema version: {exc}") from exc
        if version > DATABASE_SCHEMA_VERSION:
            raise StorageError(self._newer_schema_message(version))
        return version

    @staticmethod
    def _read_user_version(conn: sqlite3.Connection) -> int:
        row = conn.execute("PRAGMA user_version").fetchone()
        return int(row[0]) if row is not None else 0

    @staticmethod
    def _newer_schema_message(version: int) -> str:
        return (
            f"database schema version {version} is newer than this PatchPilot "
            f"supports ({DATABASE_SCHEMA_VERSION}); upgrade PatchPilot to read it"
        )

    def _require_schema(self, conn: sqlite3.Connection) -> int:
        try:
            version = self._read_user_version(conn)
        except sqlite3.Error as exc:
            raise StorageError(f"cannot read database schema version: {exc}") from exc
        if version > DATABASE_SCHEMA_VERSION:
            raise StorageError(self._newer_schema_message(version))
        # Version 4 invalidates old caches without changing report tables.
        if version != DATABASE_SCHEMA_VERSION and not (self.read_only and version == 3):
            raise StorageError(
                f"database schema version {version} is not initialized; "
                "call Storage.initialize() first"
            )
        return version

    @staticmethod
    def _migration_scripts() -> dict[int, str]:
        """Load ``NNN_*.sql`` migrations as package resources.

        ``importlib.resources`` makes wheels and zip imports work; the plain
        filesystem location is only a fallback for unusual source checkouts.
        """

        scripts: dict[int, str] = {}
        try:
            base = importlib.resources.files("patchpilot").joinpath("migrations")
        except (ImportError, ModuleNotFoundError, TypeError):  # pragma: no cover
            base = None
        if base is not None:
            try:
                for entry in base.iterdir():
                    match = _MIGRATION_NAME.match(entry.name)
                    if match is not None:
                        scripts[int(match.group(1))] = entry.read_text(encoding="utf-8")
            except (OSError, AttributeError, TypeError, UnicodeDecodeError):
                scripts = {}
        if not scripts:
            fallback = Path(__file__).resolve().parent / "migrations"
            try:
                for path in sorted(fallback.glob("*.sql")):
                    match = _MIGRATION_NAME.match(path.name)
                    if match is not None:
                        scripts[int(match.group(1))] = path.read_text(encoding="utf-8")
            except OSError:  # pragma: no cover - defensive
                scripts = {}
        if not scripts:
            raise StorageError(
                "no database migration scripts found "
                "(expected patchpilot/migrations/NNN_*.sql)"
            )
        return scripts

    # -- transactions ---------------------------------------------------------

    def require_task_ownership(self, conn: sqlite3.Connection | None = None) -> None:
        if self._task_owner is None:
            return
        connection = conn if conn is not None else self._ensure_conn()
        task_id, token = self._task_owner
        owner = connection.execute(
            "SELECT 1 FROM analysis_tasks WHERE task_id = ? AND status = ? AND worker_token = ?",
            (task_id, TASK_RUNNING, token),
        ).fetchone()
        if owner is None:
            raise StorageError(f"worker lost ownership of task {task_id}")

    def _transaction(
        self,
        action: Callable[[sqlite3.Connection], None],
        *,
        phase: str,
        run_id: str | None = None,
    ) -> None:
        """Run ``action`` inside one short write transaction.

        When ``run_id`` is given the run header must already exist, so a phase
        can never write orphan rows (even for an empty list).
        """

        if self.read_only:
            raise StorageError(f"cannot save {phase}: storage was opened read-only")
        conn = self._ensure_conn()
        self._require_schema(conn)
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise StorageError(f"cannot start transaction for {phase}: {exc}") from exc
        try:
            self.require_task_ownership(conn)
            if run_id is not None:
                row = conn.execute(
                    "SELECT 1 FROM analysis_runs WHERE run_id = ?", (run_id,)
                ).fetchone()
                if row is None:
                    raise StorageError(f"run not found: {run_id}")
            action(conn)
        except StorageError:
            self._rollback(conn)
            raise
        except sqlite3.Error as exc:
            self._rollback(conn)
            raise StorageError(f"failed to save {phase}: {exc}") from exc
        except BaseException:
            self._rollback(conn)
            raise
        try:
            conn.execute("COMMIT")
        except sqlite3.Error as exc:  # pragma: no cover - commit failure
            self._rollback(conn)
            raise StorageError(f"failed to commit {phase}: {exc}") from exc

    @staticmethod
    def _rollback(conn: sqlite3.Connection) -> None:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    # -- write phases ---------------------------------------------------------

    def create_run(
        self,
        run: AnalysisRun,
        snapshot: Snapshot,
        *,
        task_id: str | None = None,
    ) -> None:
        """Persist the run header and the full snapshot manifest.

        When ``task_id`` is given the run is linked to that queue task in the
        same transaction: ``analysis_runs.task_id`` is written and the task's
        ``run_id`` is updated.  The old two-argument call stays valid.
        """

        if not is_valid_run_id(run.run_id):
            raise StorageError(f"invalid run id: {run.run_id!r}")
        effective_task_id = task_id if task_id is not None else run.task_id
        if effective_task_id is not None and not is_valid_run_id(effective_task_id):
            raise StorageError(f"invalid task id: {effective_task_id!r}")
        entries = self._snapshot_entry_rows(run.run_id, snapshot)
        run_row = (
            run.run_id,
            run.repo_id,
            run.display_name,
            run.repo_root,
            run.branch,
            1 if run.detached else 0,
            run.mode,
            run.endpoint_before,
            run.endpoint_after,
            run.started_at,
            run.finished_at,
            run.status,
            run.summary,
            run.config_digest,
            run.analyzer_version,
            int(run.snapshot_format_version),
            int(run.schema_version),
            effective_task_id,
            dump_json(run.metrics or {}),
            dump_json([item.to_dict() for item in run.diagnostics or []]),
        )

        def action(conn: sqlite3.Connection) -> None:
            if effective_task_id is not None:
                row = conn.execute(
                    "SELECT 1 FROM analysis_tasks WHERE task_id = ? AND repo_id = ?",
                    (effective_task_id, run.repo_id),
                ).fetchone()
                if row is None:
                    raise StorageError(f"task not found: {effective_task_id}")
            conn.execute(
                """
                INSERT INTO analysis_runs (
                    run_id, repo_id, display_name, repo_root, branch, detached,
                    mode, endpoint_before, endpoint_after, started_at,
                    finished_at, status, summary, config_digest,
                    analyzer_version, snapshot_format_version, schema_version,
                    task_id, metrics_json, diagnostics_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                run_row,
            )
            if entries:
                conn.executemany(
                    """
                    INSERT INTO snapshot_entries (
                        run_id, side, path, status, content_sha256, git_oid,
                        size, is_python, detail
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    entries,
                )
            if effective_task_id is not None:
                cursor = conn.execute(
                    "UPDATE analysis_tasks SET run_id = ? WHERE task_id = ?",
                    (run.run_id, effective_task_id),
                )
                if cursor.rowcount == 0:  # pragma: no cover - checked above
                    raise StorageError(f"task not found: {effective_task_id}")

        self._transaction(action, phase="run")

    def save_changes(self, run_id: str, changes: list[Change]) -> None:
        """Persist the change list, applying the evidence retention policy."""

        self._require_valid_run_id(run_id)

        def action(conn: sqlite3.Connection) -> None:
            used_bytes = self._stored_evidence_bytes(conn, run_id)
            rows = []
            for change in changes or []:
                hunks, diagnostics, truncated, exhausted = self._apply_evidence_policy(
                    change, used_bytes
                )
                if exhausted:
                    used_bytes = self.max_evidence_bytes_per_run
                else:
                    used_bytes += sum(
                        len(line.encode("utf-8")) for hunk in hunks for line in hunk.lines
                    )
                rows.append(
                    (
                        run_id,
                        change.change_id,
                        change.kind,
                        change.old_path,
                        change.new_path,
                        change.old_sha256,
                        change.new_sha256,
                        change.rename_basis,
                        change.analysis_status,
                        dump_json(list(change.old_changed_lines or [])),
                        dump_json(list(change.new_changed_lines or [])),
                        dump_json([asdict(hunk) for hunk in hunks]),
                        1 if truncated else 0,
                        dump_json(diagnostics),
                    )
                )
            if rows:
                conn.executemany(
                    """
                    INSERT INTO changes (
                        run_id, change_id, kind, old_path, new_path,
                        old_sha256, new_sha256, rename_basis, analysis_status,
                        old_changed_lines_json, new_changed_lines_json,
                        hunks_json, diff_truncated, diagnostics_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )

        self._transaction(action, phase="changes", run_id=run_id)

    def save_index(self, run_id: str, index: Any) -> None:
        """Persist one side of the AST index (symbols and call/import edges)."""

        self._require_valid_run_id(run_id)
        symbols = self._index_symbols(index)
        edges = list(getattr(index, "edges", None) or [])
        index_side = getattr(index, "side", None)
        symbol_ids = {symbol.symbol_id for symbol in symbols}
        for symbol in symbols:
            if index_side is not None and symbol.side != index_side:
                raise StorageError(
                    f"symbol {symbol.symbol_id!r} belongs to side {symbol.side!r}, "
                    f"but the index declares side {index_side!r}"
                )
        for edge in edges:
            if index_side is not None and edge.side != index_side:
                raise StorageError(
                    f"edge {edge.edge_id!r} belongs to side {edge.side!r}, "
                    f"but the index declares side {index_side!r}"
                )
            if edge.caller_id not in symbol_ids:
                raise StorageError(
                    f"edge {edge.edge_id!r} references caller {edge.caller_id!r} "
                    "outside this index"
                )
            if edge.callee_id is not None and edge.callee_id not in symbol_ids:
                raise StorageError(
                    f"edge {edge.edge_id!r} references callee {edge.callee_id!r} "
                    "outside this index"
                )

        def action(conn: sqlite3.Connection) -> None:
            if symbols:
                conn.executemany(
                    """
                    INSERT INTO symbols (
                        run_id, symbol_id, side, path, module, qualified_name,
                        kind, parent_id, start_line, end_line, def_line,
                        decorator_start, is_test
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            run_id,
                            symbol.symbol_id,
                            symbol.side,
                            symbol.path,
                            symbol.module,
                            symbol.qualified_name,
                            symbol.kind,
                            symbol.parent_id,
                            int(symbol.start_line),
                            int(symbol.end_line),
                            int(symbol.def_line),
                            symbol.decorator_start,
                            1 if symbol.is_test else 0,
                        )
                        for symbol in symbols
                    ],
                )
            if edges:
                conn.executemany(
                    """
                    INSERT INTO call_edges (
                        run_id, edge_id, side, caller_id, callee_id, path,
                        line, col, edge_kind, resolution, reason, target,
                        callee_module
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            run_id,
                            edge.edge_id,
                            edge.side,
                            edge.caller_id,
                            edge.callee_id,
                            edge.path,
                            int(edge.line),
                            int(edge.col),
                            edge.edge_kind,
                            edge.resolution,
                            edge.reason,
                            self._stored_edge_target(edge),
                            edge.callee_module,
                        )
                        for edge in edges
                    ],
                )

        self._transaction(action, phase="index", run_id=run_id)

    def _stored_edge_target(self, edge: CallEdge) -> str | None:
        if self.evidence_mode == "metadata_only":
            return None
        return persistent_edge_target(edge)

    def save_symbol_changes(self, run_id: str, symbol_changes: list[SymbolChange]) -> None:
        """Persist mapped symbol changes (FK checked against changes/symbols)."""

        self._require_valid_run_id(run_id)
        rows = [
            (
                run_id,
                item.symbol_change_id,
                item.change_id,
                item.kind,
                item.reason,
                item.old_symbol_id,
                item.new_symbol_id,
                1 if item.structure_changed else 0,
                dump_json(list(item.old_changed_lines or [])),
                dump_json(list(item.new_changed_lines or [])),
                dump_json([diag.to_dict() for diag in item.diagnostics or []]),
                dump_json(dict(item.details or {})),
            )
            for item in symbol_changes or []
        ]

        def action(conn: sqlite3.Connection) -> None:
            if rows:
                conn.executemany(
                    """
                    INSERT INTO symbol_changes (
                        run_id, symbol_change_id, change_id, kind, reason,
                        old_symbol_id, new_symbol_id, structure_changed,
                        old_changed_lines_json, new_changed_lines_json,
                        diagnostics_json, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )

        self._transaction(action, phase="symbol_changes", run_id=run_id)

    def save_impacts(self, run_id: str, candidates: list[ImpactCandidate]) -> None:
        """Persist impact candidates and their ordered edge paths."""

        self._require_valid_run_id(run_id)
        rows = [
            (
                run_id,
                item.candidate_id,
                item.symbol_change_id,
                item.seed_symbol_id,
                item.candidate_symbol_id,
                item.side,
                int(item.min_depth),
                dump_json(list(item.edge_ids or [])),
                item.evidence,
                1 if item.truncated else 0,
            )
            for item in candidates or []
        ]

        def action(conn: sqlite3.Connection) -> None:
            if rows:
                conn.executemany(
                    """
                    INSERT INTO impact_candidates (
                        run_id, candidate_id, symbol_change_id, seed_symbol_id,
                        candidate_symbol_id, side, min_depth, edge_ids_json,
                        evidence, truncated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )

        self._transaction(action, phase="impact_candidates", run_id=run_id)

    def save_tests(self, run_id: str, recommendations: list[TestRecommendation]) -> None:
        """Persist test recommendations and their candidate links."""

        self._require_valid_run_id(run_id)
        rows = [
            (
                run_id,
                item.side,
                item.test_path,
                item.qualified_name if item.qualified_name is not None else "",
                dump_json(list(item.candidate_ids or [])),
                int(item.min_depth),
                item.strength,
                item.evidence,
                1 if item.exists_in_after else 0,
                item.test_symbol_id,
            )
            for item in recommendations or []
        ]

        def action(conn: sqlite3.Connection) -> None:
            if rows:
                conn.executemany(
                    """
                    INSERT INTO test_recommendations (
                        run_id, side, test_path, qualified_name,
                        candidate_ids_json, min_depth, strength, evidence,
                        exists_in_after, test_symbol_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )

        self._transaction(action, phase="test_recommendations", run_id=run_id)

    def save_judge_attempts(self, run_id: str, attempts: list[JudgeAttempt]) -> None:
        """Persist Judge attempts (one row per adapter call per candidate)."""

        self._require_valid_run_id(run_id)
        rows = [
            (
                run_id,
                item.candidate_id,
                int(item.attempt_no),
                item.attempt_id,
                item.adapter,
                item.model,
                item.started_at,
                int(item.duration_ms),
                item.context_digest,
                int(item.context_bytes),
                int(item.context_tokens_estimate),
                1 if item.cache_hit else 0,
                1 if item.valid else 0,
                item.error_category,
                item.fallback_reason,
                item.request_id,
                dump_json(dict(item.context_summary or {})),
                dump_json(dict(item.usage or {})),
            )
            for item in attempts or []
        ]

        def action(conn: sqlite3.Connection) -> None:
            if rows:
                conn.executemany(
                    """
                    INSERT INTO judge_attempts (
                        run_id, candidate_id, attempt_no, attempt_id, adapter,
                        model, started_at, duration_ms, context_digest,
                        context_bytes, context_tokens_estimate, cache_hit,
                        valid, error_category, fallback_reason, request_id,
                        context_summary_json, usage_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )

        self._transaction(action, phase="judge attempts", run_id=run_id)

    def save_judge_verdicts(self, run_id: str, verdicts: list[JudgeVerdict]) -> None:
        """Persist final Judge verdicts (FK checked against the attempts)."""

        self._require_valid_run_id(run_id)
        rows = [
            (
                run_id,
                item.candidate_id,
                int(item.attempt_no),
                item.verdict,
                item.reason,
                item.adapter,
                item.model,
                dump_json(list(item.evidence or [])),
                dump_json(list(item.conditions or [])),
                item.uncertainty,
                int(item.schema_version),
                item.validated_at,
            )
            for item in verdicts or []
        ]

        def action(conn: sqlite3.Connection) -> None:
            if rows:
                conn.executemany(
                    """
                    INSERT INTO judge_verdicts (
                        run_id, candidate_id, attempt_no, verdict, reason,
                        adapter, model, evidence_json, conditions_json,
                        uncertainty, schema_version, validated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )

        self._transaction(action, phase="judge verdicts", run_id=run_id)

    def finish_run(
        self,
        run_id: str,
        status: str,
        summary: str,
        metrics: dict,
        diagnostics: list[Diagnostic],
        finished_at: str | None = None,
    ) -> None:
        """Store the final lifecycle state, business summary and diagnostics."""

        self._require_valid_run_id(run_id)
        finished = finished_at or utc_now()
        metrics_json = dump_json(metrics or {})
        diagnostics_json = dump_json(
            [item.to_dict() for item in diagnostics or []]
        )

        def action(conn: sqlite3.Connection) -> None:
            cursor = conn.execute(
                """
                UPDATE analysis_runs
                   SET status = ?, summary = ?, finished_at = ?,
                       metrics_json = ?, diagnostics_json = ?
                 WHERE run_id = ?
                """,
                (status, summary, finished, metrics_json, diagnostics_json, run_id),
            )
            if cursor.rowcount == 0:
                raise StorageError(f"run not found: {run_id}")

        self._transaction(action, phase="run completion", run_id=run_id)

    # -- content caches (P1) --------------------------------------------------

    def cache_get(self, kind: str, key: str) -> dict | None:
        """Return a cached JSON object, or ``None`` when missing or expired.

        Expired rows are not removed here, so the method stays usable on
        read-only instances; :meth:`cache_prune` deletes them.
        """

        table = _cache_table(kind)
        if not isinstance(key, str) or not key:
            raise StorageError("cache key must be a non-empty string")
        conn = self._ensure_conn()
        self._require_schema(conn)
        try:
            row = conn.execute(
                f"SELECT value_json, expires_at FROM {table} WHERE cache_key = ?",
                (key,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError(f"failed to read {kind} cache: {exc}") from exc
        if row is None:
            return None
        expires = _parse_timestamp(row["expires_at"])
        if expires is not None and expires <= _utc_now_dt():
            return None
        value = load_json(row["value_json"], None)
        return value if isinstance(value, dict) else None

    def cache_put(
        self,
        kind: str,
        key: str,
        value: dict,
        *,
        ttl_seconds: int,
        max_total_bytes: int = 0,
    ) -> None:
        """Store (or replace) one cache entry.

        ``ttl_seconds <= 0`` stores an immediately expired entry.
        ``max_total_bytes > 0`` evicts the oldest entries of that kind until the
        summed ``size_bytes`` fits the budget; ``0`` disables size eviction.
        """

        table = _cache_table(kind)
        if not isinstance(key, str) or not key:
            raise StorageError("cache key must be a non-empty string")
        if not isinstance(value, dict):
            raise StorageError("cache value must be a JSON object")
        try:
            value_json = dump_json(value)
        except (TypeError, ValueError) as exc:
            raise StorageError(f"cache value is not JSON serialisable: {exc}") from exc
        size_bytes = len(value_json.encode("utf-8"))
        # Clamp so absurd CLI/configuration values cannot overflow datetime math.
        ttl = min(max(0, int(ttl_seconds)), 315_576_000)  # <= 10 years
        budget = max(0, int(max_total_bytes))
        created_dt = _utc_now_dt()
        created_at = _format_timestamp(created_dt)
        expires_at = _format_timestamp(created_dt + timedelta(seconds=ttl))

        if kind == "judge":
            adapter = value.get("adapter")
            model = value.get("model")
            schema_version = value.get("schema_version")
            columns = (
                "(cache_key, adapter, model, schema_version, created_at, "
                "expires_at, size_bytes, value_json)"
            )
            params: tuple[Any, ...] = (
                key,
                adapter if isinstance(adapter, str) else "",
                model if isinstance(model, str) else None,
                int(schema_version)
                if isinstance(schema_version, int) and not isinstance(schema_version, bool)
                else JUDGE_SCHEMA_VERSION,
                created_at,
                expires_at,
                size_bytes,
                value_json,
            )
            update = (
                "adapter = excluded.adapter, model = excluded.model, "
                "schema_version = excluded.schema_version, "
            )
        else:
            columns = "(cache_key, created_at, expires_at, size_bytes, value_json)"
            params = (key, created_at, expires_at, size_bytes, value_json)
            update = ""
        sql = (
            f"INSERT INTO {table} {columns} VALUES "
            f"({', '.join('?' for _ in params)}) "
            f"ON CONFLICT(cache_key) DO UPDATE SET {update}"
            "created_at = excluded.created_at, "
            "expires_at = excluded.expires_at, "
            "size_bytes = excluded.size_bytes, "
            "value_json = excluded.value_json"
        )

        def action(conn: sqlite3.Connection) -> None:
            conn.execute(sql, params)
            if budget:
                self._enforce_cache_budget(conn, table, budget)

        self._transaction(action, phase=f"{kind} cache put")

    def cache_prune(self, kind: str | None = None, ttl_days: int | None = None) -> int:
        """Delete expired (and optionally aged) cache entries; return the count."""

        tables = _cache_tables(kind)
        now_dt = _utc_now_dt()
        now_text = _format_timestamp(now_dt)
        cutoff: str | None = None
        if ttl_days is not None:
            age = min(max(0, int(ttl_days)), 3_650_000)
            cutoff = _format_timestamp(now_dt - timedelta(days=age))
        deleted = 0

        def action(conn: sqlite3.Connection) -> None:
            nonlocal deleted
            for table in tables:
                if cutoff is None:
                    cursor = conn.execute(
                        f"DELETE FROM {table} WHERE expires_at <= ?", (now_text,)
                    )
                else:
                    cursor = conn.execute(
                        f"DELETE FROM {table} "
                        "WHERE expires_at <= ? OR created_at < ?",
                        (now_text, cutoff),
                    )
                deleted += cursor.rowcount or 0

        self._transaction(action, phase="cache prune")
        return deleted

    def cache_stats(self) -> dict[str, dict[str, int]]:
        """Return live ``entries``/``bytes`` per cache kind (expired excluded)."""

        conn = self._ensure_conn()
        self._require_schema(conn)
        now_text = _format_timestamp(_utc_now_dt())
        stats: dict[str, dict[str, int]] = {}
        try:
            for kind in _CACHE_KINDS:
                table = _CACHE_TABLES[kind]
                row = conn.execute(
                    f"SELECT COUNT(*) AS entries, "
                    f"COALESCE(SUM(size_bytes), 0) AS bytes "
                    f"FROM {table} WHERE expires_at > ?",
                    (now_text,),
                ).fetchone()
                stats[kind] = {
                    "entries": int(row["entries"]),
                    "bytes": int(row["bytes"]),
                }
        except sqlite3.Error as exc:
            raise StorageError(f"failed to read cache stats: {exc}") from exc
        return stats

    @staticmethod
    def _enforce_cache_budget(
        conn: sqlite3.Connection, table: str, max_total_bytes: int
    ) -> None:
        total = int(
            conn.execute(f"SELECT COALESCE(SUM(size_bytes), 0) FROM {table}").fetchone()[0]
        )
        if total <= max_total_bytes:
            return
        rows = conn.execute(
            f"SELECT cache_key, size_bytes FROM {table} "
            "ORDER BY created_at ASC, cache_key ASC"
        ).fetchall()
        for row in rows:
            if total <= max_total_bytes:
                break
            conn.execute(f"DELETE FROM {table} WHERE cache_key = ?", (row["cache_key"],))
            total -= int(row["size_bytes"])

    # -- history pruning (P1) -------------------------------------------------

    def prune_runs(
        self,
        *,
        repo_id: str,
        retain_days: int,
        max_runs: int,
        dry_run: bool = False,
    ) -> PruneReport:
        """Delete old or excess terminal runs within one worktree.

        ``running`` runs are never deleted.  Completed runs are ranked by
        ``(started_at DESC, run_id DESC)``; the newest ``max_runs`` are kept and
        everything started before ``now - retain_days`` is removed.  Child rows
        of deleted runs are removed in the same transaction, so no orphans are
        left behind.  ``dry_run=True`` computes the same report without writing
        (and works on a read-only instance).
        """

        if not repo_id:
            raise StorageError("history prune requires a repository id")
        retain = min(max(0, int(retain_days)), 3_650_000)
        keep = max(0, int(max_runs))
        if self.read_only and not dry_run:
            raise StorageError("cannot prune history: storage was opened read-only")
        conn = self._ensure_conn()
        self._require_schema(conn)
        if dry_run:
            try:
                return self._plan_prune(conn, repo_id, retain, keep, True)
            except sqlite3.Error as exc:
                raise StorageError(f"failed to plan history prune: {exc}") from exc
        report: PruneReport | None = None

        def action(tx: sqlite3.Connection) -> None:
            nonlocal report
            plan = self._plan_prune(tx, repo_id, retain, keep, False)
            self._delete_runs(tx, plan.to_delete)
            plan.deleted = list(plan.to_delete)
            report = plan

        self._transaction(action, phase="run prune")
        assert report is not None
        return report

    def _plan_prune(
        self,
        conn: sqlite3.Connection,
        repo_id: str,
        retain_days: int,
        max_runs: int,
        dry_run: bool,
    ) -> PruneReport:
        rows = conn.execute(
            "SELECT run_id, status, started_at FROM analysis_runs "
            "WHERE repo_id = ? ORDER BY started_at DESC, run_id DESC",
            (repo_id,),
        ).fetchall()
        cutoff = _utc_now_dt() - timedelta(days=retain_days)
        to_delete: list[str] = []
        running_skipped: list[str] = []
        terminal_count = 0
        for row in rows:
            run_id = row["run_id"]
            if row["status"] == RUN_RUNNING:
                running_skipped.append(run_id)
                continue
            started = _parse_timestamp(row["started_at"])
            too_old = started is not None and started < cutoff
            beyond_limit = terminal_count >= max_runs
            terminal_count += 1
            if too_old or beyond_limit:
                to_delete.append(run_id)
        total_before = len(rows)
        return PruneReport(
            total_before=total_before,
            retained=total_before - len(to_delete),
            to_delete=sorted(to_delete),
            deleted=[],
            dry_run=dry_run,
            running_skipped=sorted(running_skipped),
        )

    @staticmethod
    def _delete_runs(conn: sqlite3.Connection, run_ids: list[str]) -> None:
        if not run_ids:
            return
        # Chunk to stay below SQLite's bound-parameter limit on large prunes.
        for start in range(0, len(run_ids), 500):
            chunk = run_ids[start : start + 500]
            placeholders = ", ".join("?" for _ in chunk)
            for table in _PRUNE_DELETE_ORDER:
                conn.execute(
                    f"DELETE FROM {table} WHERE run_id IN ({placeholders})", chunk
                )
            # Tasks outlive their run; clear the dangling reference first (the
            # FK also does ON DELETE SET NULL, this keeps the intent explicit).
            conn.execute(
                f"UPDATE analysis_tasks SET run_id = NULL "
                f"WHERE run_id IN ({placeholders})",
                chunk,
            )
            conn.execute(
                f"DELETE FROM analysis_runs WHERE run_id IN ({placeholders})", chunk
            )

    # -- analysis task queue (M1) ---------------------------------------------

    def create_task(self, task: TaskRecord) -> TaskRecord:
        """Insert a queued task, or return the existing record for a task key.

        ``(repo_id, task_key)`` is unique when ``task_key`` is set, so a retried
        submission (including two racing writers) keeps the first task and never
        overwrites it.
        """

        self._validate_task_record(task)
        task_key = task.task_key or None
        try:
            request_json = dump_json(dict(task.request or {}))
            config_json = dump_json(dict(task.config_json or {}))
            stages_json = dump_json(list(task.stages or []))
            diagnostics_json = dump_json(list(task.diagnostics or []))
        except (TypeError, ValueError) as exc:
            raise StorageError(f"task record is not JSON serialisable: {exc}") from exc
        row_values = (
            task.task_id,
            task.repo_id,
            task.repo_root,
            task.status,
            task.mode,
            task.base_ref,
            task.commit_ref,
            task.range_spec,
            task.parent_index,
            1 if task.judge else 0,
            1 if task.include_untracked else 0,
            request_json,
            task.config_digest,
            config_json,
            stages_json,
            diagnostics_json,
            task.error_code,
            task_key,
            task.run_id,
            task.worker_token,
            task.worker_heartbeat_at,
            task.created_at,
            task.started_at,
            task.finished_at,
        )
        existing: TaskRecord | None = None

        def action(conn: sqlite3.Connection) -> None:
            nonlocal existing
            if task_key is not None:
                row = conn.execute(
                    "SELECT * FROM analysis_tasks "
                    "WHERE repo_id = ? AND task_key = ?",
                    (task.repo_id, task_key),
                ).fetchone()
                if row is not None:
                    existing = self._task_from_row(row)
                    return
            conn.execute(
                """
                INSERT INTO analysis_tasks (
                    task_id, repo_id, repo_root, status, mode, base_ref,
                    commit_ref, range_spec, parent_index, judge,
                    include_untracked, request_json, config_digest, config_json,
                    stages_json, diagnostics_json, error_code, task_key, run_id,
                    worker_token, worker_heartbeat_at, created_at, started_at,
                    finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                row_values,
            )

        try:
            self._transaction(action, phase="task create")
        except StorageError:
            # A concurrent writer may have committed the same task key first.
            if task_key is not None:
                found = self._find_task_by_key(task.repo_id, task_key)
                if found is not None:
                    return found
            raise
        if existing is not None:
            return existing
        return task

    def get_task(self, task_id: str) -> TaskRecord | None:
        """Return one task or ``None`` when it does not exist."""

        conn = self._ensure_conn()
        self._require_schema(conn)
        try:
            row = conn.execute(
                "SELECT * FROM analysis_tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError(f"failed to read task {task_id!r}: {exc}") from exc
        return self._task_from_row(row) if row is not None else None

    def get_task_for_run(self, run_id: str) -> TaskRecord | None:
        """Return the task that produced ``run_id``, if any."""

        conn = self._ensure_conn()
        self._require_schema(conn)
        try:
            row = conn.execute(
                "SELECT * FROM analysis_tasks WHERE run_id = ? "
                "ORDER BY created_at ASC, task_id ASC LIMIT 1",
                (run_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError(
                f"failed to read task for run {run_id!r}: {exc}"
            ) from exc
        return self._task_from_row(row) if row is not None else None

    def list_tasks(
        self,
        repo_id: str,
        *,
        statuses: list[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[TaskRecord], int]:
        """List tasks of one repository (newest first) plus the total count."""

        if not repo_id:
            raise StorageError("list_tasks requires a repo_id")
        limit = max(0, int(limit))
        offset = max(0, int(offset))
        where = ["repo_id = ?"]
        params: list[Any] = [repo_id]
        if statuses is not None:
            selected = list(statuses)
            invalid = [item for item in selected if item not in TASK_STATUSES]
            if invalid:
                raise StorageError(f"invalid task status filter: {invalid[0]!r}")
            if not selected:
                return [], 0
            where.append("status IN (" + ", ".join("?" for _ in selected) + ")")
            params.extend(selected)
        where_sql = " WHERE " + " AND ".join(where)
        conn = self._ensure_conn()
        self._require_schema(conn)
        try:
            total = int(
                conn.execute(
                    "SELECT COUNT(*) FROM analysis_tasks" + where_sql, params
                ).fetchone()[0]
            )
            rows = conn.execute(
                "SELECT * FROM analysis_tasks"
                + where_sql
                + " ORDER BY created_at DESC, task_id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        except sqlite3.Error as exc:
            raise StorageError(f"failed to list tasks: {exc}") from exc
        return [self._task_from_row(row) for row in rows], total

    def claim_next_task(
        self,
        repo_id: str,
        worker_token: str,
        *,
        now: str,
        lease_seconds: int = 30,
    ) -> TaskRecord | None:
        """Atomically claim the oldest queued task of one repository.

        Returns ``None`` when the repository already has a running task or the
        queue is empty.  The database-level partial unique index on
        ``(repo_id) WHERE status = 'running'`` guarantees a single runner.
        """

        if not repo_id:
            raise StorageError("claim_next_task requires a repo_id")
        if not isinstance(worker_token, str) or not worker_token:
            raise StorageError("claim_next_task requires a worker token")
        now_dt = _parse_timestamp(now)
        if now_dt is None:
            raise StorageError(f"invalid claim timestamp: {now!r}")
        _ = max(0, int(lease_seconds))  # accepted for API symmetry
        claimed: TaskRecord | None = None

        def action(conn: sqlite3.Connection) -> None:
            nonlocal claimed
            running = conn.execute(
                "SELECT 1 FROM analysis_tasks WHERE repo_id = ? AND status = ? LIMIT 1",
                (repo_id, TASK_RUNNING),
            ).fetchone()
            if running is not None:
                return
            row = conn.execute(
                "SELECT * FROM analysis_tasks WHERE repo_id = ? AND status = ? "
                "ORDER BY created_at ASC, task_id ASC LIMIT 1",
                (repo_id, TASK_QUEUED),
            ).fetchone()
            if row is None:
                return
            cursor = conn.execute(
                """
                UPDATE analysis_tasks
                   SET status = ?, started_at = ?, worker_token = ?,
                       worker_heartbeat_at = ?
                 WHERE task_id = ? AND status = ?
                """,
                (TASK_RUNNING, now, worker_token, now, row["task_id"], TASK_QUEUED),
            )
            if cursor.rowcount != 1:  # pragma: no cover - guarded by the lock
                return
            updated = conn.execute(
                "SELECT * FROM analysis_tasks WHERE task_id = ?", (row["task_id"],)
            ).fetchone()
            if updated is not None:
                claimed = self._task_from_row(updated)

        self._transaction(action, phase="task claim")
        return claimed

    def heartbeat_task(
        self,
        task_id: str,
        worker_token: str,
        *,
        now: str,
        lease_seconds: int = 30,
    ) -> bool:
        """Refresh the heartbeat of a running task owned by ``worker_token``."""

        if _parse_timestamp(now) is None:
            raise StorageError(f"invalid heartbeat timestamp: {now!r}")
        _ = max(0, int(lease_seconds))
        updated = False

        def action(conn: sqlite3.Connection) -> None:
            nonlocal updated
            cursor = conn.execute(
                """
                UPDATE analysis_tasks SET worker_heartbeat_at = ?
                 WHERE task_id = ? AND status = ? AND worker_token = ?
                """,
                (now, task_id, TASK_RUNNING, worker_token),
            )
            updated = cursor.rowcount == 1

        self._transaction(action, phase="task heartbeat")
        return updated

    def append_task_stage(
        self, task_id: str, worker_token: str, event: dict
    ) -> bool:
        """Append one stage event to a running task owned by ``worker_token``."""

        if not isinstance(event, dict):
            raise StorageError("task stage event must be a JSON object")
        try:
            dump_json(dict(event))
        except (TypeError, ValueError) as exc:
            raise StorageError(
                f"task stage event is not JSON serialisable: {exc}"
            ) from exc
        appended = False

        def action(conn: sqlite3.Connection) -> None:
            nonlocal appended
            row = conn.execute(
                "SELECT stages_json FROM analysis_tasks "
                "WHERE task_id = ? AND status = ? AND worker_token = ?",
                (task_id, TASK_RUNNING, worker_token),
            ).fetchone()
            if row is None:
                return
            stages = load_json(row["stages_json"], [])
            if not isinstance(stages, list):
                stages = []
            stages.append(dict(event))
            conn.execute(
                "UPDATE analysis_tasks SET stages_json = ? WHERE task_id = ?",
                (dump_json(stages), task_id),
            )
            appended = True

        self._transaction(action, phase="task stage")
        return appended

    def finish_task(
        self,
        task_id: str,
        worker_token: str,
        status: str,
        *,
        now: str,
        run_id: str | None = None,
        diagnostics: list[dict] | None = None,
        error_code: str | None = None,
    ) -> bool:
        """Move a running task owned by ``worker_token`` into a terminal state."""

        if status not in _TASK_TERMINAL_STATUSES:
            raise StorageError(f"invalid terminal task status: {status!r}")
        if _parse_timestamp(now) is None:
            raise StorageError(f"invalid finish timestamp: {now!r}")
        if run_id is not None and not is_valid_run_id(run_id):
            raise StorageError(f"invalid run id: {run_id!r}")
        diagnostics_json: str | None = None
        if diagnostics is not None:
            if not isinstance(diagnostics, list):
                raise StorageError("task diagnostics must be a list")
            try:
                diagnostics_json = dump_json([dict(item) for item in diagnostics])
            except (TypeError, ValueError) as exc:
                raise StorageError(
                    f"task diagnostics are not JSON serialisable: {exc}"
                ) from exc
        finished = False

        def action(conn: sqlite3.Connection) -> None:
            nonlocal finished
            assignments = [
                "status = ?",
                "finished_at = ?",
                "worker_token = NULL",
                "worker_heartbeat_at = NULL",
                "error_code = ?",
            ]
            params: list[Any] = [status, now, error_code]
            if run_id is not None:
                assignments.append("run_id = ?")
                params.append(run_id)
            if diagnostics_json is not None:
                assignments.append("diagnostics_json = ?")
                params.append(diagnostics_json)
            params.extend([task_id, TASK_RUNNING, worker_token])
            cursor = conn.execute(
                f"UPDATE analysis_tasks SET {', '.join(assignments)} "
                "WHERE task_id = ? AND status = ? AND worker_token = ?",
                params,
            )
            finished = cursor.rowcount == 1

        self._transaction(action, phase="task finish")
        return finished

    def bind_task_run(self, task_id: str, run_id: str) -> None:
        """Attach ``run_id`` to a task (used by the analysis pipeline)."""

        if not is_valid_run_id(run_id):
            raise StorageError(f"invalid run id: {run_id!r}")

        def action(conn: sqlite3.Connection) -> None:
            cursor = conn.execute(
                "UPDATE analysis_tasks SET run_id = ? WHERE task_id = ?",
                (run_id, task_id),
            )
            if cursor.rowcount == 0:
                raise StorageError(f"task not found: {task_id}")

        self._transaction(action, phase="task bind")

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a queued task; racing claims win or lose atomically."""

        cancelled = False

        def action(conn: sqlite3.Connection) -> None:
            nonlocal cancelled
            cursor = conn.execute(
                "UPDATE analysis_tasks SET status = ?, finished_at = ? "
                "WHERE task_id = ? AND status = ?",
                (TASK_CANCELLED, utc_now(), task_id, TASK_QUEUED),
            )
            cancelled = cursor.rowcount == 1

        self._transaction(action, phase="task cancel")
        return cancelled

    def recover_stale_tasks(
        self, *, now: str, stale_seconds: int = 30, repo_id: str | None = None
    ) -> list[dict]:
        """Recover running tasks whose worker heartbeat went stale.

        When the task already produced a run that reached a terminal state the
        task mirrors that state; otherwise it becomes ``interrupted``.  Fresh
        heartbeats are left untouched.  Returns deterministic
        ``[{"task_id", "status", "run_id"}]`` entries for recovered tasks.
        """

        now_dt = _parse_timestamp(now)
        if now_dt is None:
            raise StorageError(f"invalid recovery timestamp: {now!r}")
        stale = max(0, int(stale_seconds))
        cutoff = now_dt - timedelta(seconds=stale)
        recovered: list[dict] = []

        def action(conn: sqlite3.Connection) -> None:
            nonlocal recovered
            repo_filter = " AND repo_id = ?" if repo_id is not None else ""
            filters = (TASK_RUNNING, repo_id) if repo_id is not None else (TASK_RUNNING,)
            rows = conn.execute(
                "SELECT * FROM analysis_tasks WHERE status = ?" + repo_filter + " "
                "ORDER BY created_at ASC, task_id ASC",
                filters,
            ).fetchall()
            for row in rows:
                heartbeat = _parse_timestamp(row["worker_heartbeat_at"])
                if heartbeat is not None and heartbeat >= cutoff:
                    continue
                task_id = row["task_id"]
                run_id = row["run_id"]
                target = TASK_INTERRUPTED
                finished_at = now
                if run_id is not None:
                    run_row = conn.execute(
                        "SELECT status, finished_at, diagnostics_json FROM analysis_runs WHERE run_id = ?",
                        (run_id,),
                    ).fetchone()
                    if run_row is not None:
                        mapped = _RUN_TO_TASK_STATUS.get(run_row["status"])
                        if mapped is not None:
                            target = mapped
                            finished_at = run_row["finished_at"] or now
                        elif run_row["status"] == RUN_RUNNING:
                            diagnostics = load_json(run_row["diagnostics_json"], []) or []
                            diagnostics.append(Diagnostic(
                                code="worker_interrupted",
                                message="the worker lease expired before analysis finished",
                            ).to_dict())
                            conn.execute(
                                "UPDATE analysis_runs SET status = ?, summary = ?, finished_at = ?, "
                                "diagnostics_json = ? WHERE run_id = ? AND status = ?",
                                (RUN_PARTIAL, SUMMARY_UNKNOWN, now, dump_json(diagnostics), run_id, RUN_RUNNING),
                            )
                conn.execute(
                    """
                    UPDATE analysis_tasks
                       SET status = ?, finished_at = ?, worker_token = NULL,
                           worker_heartbeat_at = NULL
                     WHERE task_id = ? AND status = ?
                    """,
                    (target, finished_at, task_id, TASK_RUNNING),
                )
                recovered.append(
                    {"task_id": task_id, "status": target, "run_id": run_id}
                )

        self._transaction(action, phase="stale task recovery")
        return recovered

    @staticmethod
    def _validate_task_record(task: TaskRecord) -> None:
        if not isinstance(task, TaskRecord):
            raise StorageError("create_task expects a TaskRecord instance")
        if not is_valid_run_id(task.task_id):
            raise StorageError(f"invalid task id: {task.task_id!r}")
        if not task.repo_id:
            raise StorageError("task repo_id must not be empty")
        if task.status not in TASK_STATUSES:
            raise StorageError(f"invalid task status: {task.status!r}")
        if not task.mode:
            raise StorageError("task mode must not be empty")
        if not task.created_at:
            raise StorageError("task created_at must not be empty")
        if task.run_id is not None and not is_valid_run_id(task.run_id):
            raise StorageError(f"invalid run id on task: {task.run_id!r}")
        if task.task_key is not None and not isinstance(task.task_key, str):
            raise StorageError("task task_key must be a string or None")
        if task.parent_index is not None and not isinstance(task.parent_index, int):
            raise StorageError("task parent_index must be an int or None")
        if not isinstance(task.request, dict):
            raise StorageError("task request must be a dict")
        if not isinstance(task.config_json, dict):
            raise StorageError("task config_json must be a dict")
        if not isinstance(task.stages, list):
            raise StorageError("task stages must be a list")
        if not isinstance(task.diagnostics, list):
            raise StorageError("task diagnostics must be a list")

    def _find_task_by_key(self, repo_id: str, task_key: str) -> TaskRecord | None:
        conn = self._ensure_conn()
        self._require_schema(conn)
        try:
            row = conn.execute(
                "SELECT * FROM analysis_tasks WHERE repo_id = ? AND task_key = ?",
                (repo_id, task_key),
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError(f"failed to read task by key: {exc}") from exc
        return self._task_from_row(row) if row is not None else None

    @staticmethod
    def _task_from_row(row: sqlite3.Row) -> TaskRecord:
        return TaskRecord(
            task_id=row["task_id"],
            repo_id=row["repo_id"],
            repo_root=row["repo_root"],
            status=row["status"],
            mode=row["mode"],
            base_ref=row["base_ref"],
            commit_ref=row["commit_ref"],
            range_spec=row["range_spec"],
            parent_index=int(row["parent_index"])
            if row["parent_index"] is not None
            else None,
            judge=bool(row["judge"]),
            include_untracked=bool(row["include_untracked"]),
            request=dict(load_json(row["request_json"], {}) or {}),
            config_digest=row["config_digest"],
            config_json=dict(load_json(row["config_json"], {}) or {}),
            stages=list(load_json(row["stages_json"], []) or []),
            diagnostics=list(load_json(row["diagnostics_json"], []) or []),
            error_code=row["error_code"],
            task_key=row["task_key"],
            run_id=row["run_id"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            worker_token=row["worker_token"],
            worker_heartbeat_at=row["worker_heartbeat_at"],
        )

    # -- reads ----------------------------------------------------------------

    def list_runs(
        self,
        repo_id: str | None = None,
        *,
        limit: int = 25,
        offset: int = 0,
        status: str | None = None,
        branch: str | None = None,
        mode: str | None = None,
    ) -> tuple[list[RunSummary], int]:
        """Return one filtered history page plus the total number of matches.

        Sorting is ``(started_at DESC, run_id DESC)`` so pagination is stable.
        All filters are optional and combined with ``AND``:

        * ``status``: one of :data:`models.RUN_STATUSES`
          (``running``/``completed``/``partial``/``failed``).
        * ``mode``: one of :data:`models.ALL_MODES`
          (``worktree-net``/``staged``/``working-tree``/``base``/``commit``/``range``).
        * ``branch``: exact branch name match.  ``None`` (or an empty/blank
          string) disables the filter.  Detached runs store ``branch = NULL``
          and therefore never match a non-empty branch filter; list without the
          branch filter to see them.

        Invalid ``status``/``mode`` values raise :class:`StorageError`; an
        unknown repository or a filter combination with no matches returns
        ``([], 0)``.  ``total`` is always the number of runs matching the
        filters, independent of ``limit``/``offset``.
        """

        status_filter = self._validate_run_status_filter(status)
        mode_filter = self._validate_run_mode_filter(mode)
        branch_filter: str | None = None
        if branch is not None:
            if not isinstance(branch, str):
                raise StorageError("branch filter must be a string or None")
            branch_filter = branch.strip() or None
        conn = self._ensure_conn()
        self._require_schema(conn)
        try:
            return self._list_runs(
                conn,
                repo_id,
                int(limit),
                int(offset),
                status=status_filter,
                branch=branch_filter,
                mode=mode_filter,
            )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to list runs: {exc}") from exc

    def list_runs_page(
        self,
        repo_id: str | None,
        *,
        limit: int = 25,
        cursor: str | None = None,
    ) -> tuple[list[RunSummary], str | None, int]:
        """Keyset pagination over history, stable under concurrent inserts.

        Ordering is ``(started_at DESC, run_id DESC)``; the opaque cursor is
        ``base64url("started_at|run_id")`` of the last returned row.  Returns
        ``(rows, next_cursor, total)``; an invalid cursor raises
        :class:`StorageError`.
        """

        conn = self._ensure_conn()
        self._require_schema(conn)
        try:
            return self._list_runs_page(conn, repo_id, int(limit), cursor)
        except sqlite3.Error as exc:
            raise StorageError(f"failed to page runs: {exc}") from exc

    def load_run(self, run_id: str) -> RunDetail:
        """Load the complete run graph; raises :class:`StorageError` if absent."""

        conn = self._ensure_conn()
        self._require_schema(conn)
        try:
            return self._load_run(conn, run_id)
        except sqlite3.Error as exc:
            raise StorageError(f"failed to read run {run_id!r}: {exc}") from exc

    def run_exists(self, run_id: str) -> bool:
        """Return whether ``run_id`` has a persisted row."""

        conn = self._ensure_conn()
        self._require_schema(conn)
        try:
            row = conn.execute(
                "SELECT 1 FROM analysis_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError(f"failed to query run {run_id!r}: {exc}") from exc
        return row is not None

    # -- bounded run queries (US-2) -------------------------------------------
    #
    # These read only what a first screen needs.  Unlike :meth:`load_run` they
    # never load the full change/symbol/edge/candidate/test lists (or hunk
    # bodies), which keeps the web run page bounded for large analyses.

    def load_run_overview(self, run_id: str) -> RunOverview:
        """Return counts/metadata for one run without loading its detail tables.

        Unknown run ids raise :class:`StorageError` (same behaviour as
        :meth:`load_run`).
        """

        conn = self._open_reader()
        try:
            row = conn.execute(
                "SELECT * FROM analysis_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                raise StorageError(f"run not found: {run_id}")
            run = self._analysis_run_from_row(row)
            metrics = run.metrics if isinstance(run.metrics, dict) else {}
            judge_attempts_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM judge_attempts WHERE run_id = ?",
                    (run_id,),
                ).fetchone()[0]
            )
            judge_verdicts_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM judge_verdicts WHERE run_id = ?",
                    (run_id,),
                ).fetchone()[0]
            )
            judge_counts = {
                str(item["verdict"]): int(item["verdict_count"])
                for item in conn.execute(
                    "SELECT verdict, COUNT(*) AS verdict_count "
                    "FROM judge_verdicts WHERE run_id = ? "
                    "GROUP BY verdict ORDER BY verdict",
                    (run_id,),
                )
            }
            judge_cache_hits = int(
                conn.execute(
                    "SELECT COUNT(*) FROM judge_attempts "
                    "WHERE run_id = ? AND cache_hit = 1",
                    (run_id,),
                ).fetchone()[0]
            )
            return RunOverview(
                run=run,
                counts=self._counts_for_run(conn, run_id),
                scope=self._snapshot_scope(conn, run_id),
                diagnostics=list(run.diagnostics),
                stages=self._overview_stages(metrics),
                stage_errors=self._overview_stage_errors(metrics),
                truncated=bool(metrics.get("truncated", False)),
                judge_attempts_count=judge_attempts_count,
                judge_verdicts_count=judge_verdicts_count,
                judge_counts=judge_counts,
                judge_cache_hits=judge_cache_hits,
                task_id=run.task_id,
            )
        except sqlite3.Error as exc:
            raise StorageError(
                f"failed to read run overview {run_id!r}: {exc}"
            ) from exc

    def list_change_summaries(self, run_id: str) -> tuple[list[ChangeSummary], int]:
        """List one row per change without loading hunk bodies or full Changes.

        Ordered by ``change_id``; ``has_hunks`` is derived inside SQL so the
        hunk JSON text never crosses the connection for summaries.  It reports
        stored hunk ranges: ``metadata_only`` runs keep ranges but no line text
        (signalled by ``diff_truncated``), so use the detail API for the body.
        """

        conn = self._open_reader()
        try:
            self._require_run_conn(conn, run_id)
            rows = conn.execute(
                """
                SELECT change_id, old_path, new_path, kind, analysis_status,
                       old_changed_lines_json, new_changed_lines_json,
                       diff_truncated,
                       CASE WHEN hunks_json IS NULL OR hunks_json IN ('', '[]')
                            THEN 0 ELSE 1 END AS has_hunks,
                       (SELECT COUNT(*) FROM symbol_changes sc
                         WHERE sc.run_id = changes.run_id
                           AND sc.change_id = changes.change_id
                       ) AS symbol_change_count
                  FROM changes
                 WHERE run_id = ?
                 ORDER BY change_id ASC
                """,
                (run_id,),
            ).fetchall()
            summaries = [
                ChangeSummary(
                    change_id=row["change_id"],
                    old_path=row["old_path"],
                    new_path=row["new_path"],
                    kind=row["kind"],
                    analysis_status=row["analysis_status"],
                    old_changed_lines=len(
                        load_json(row["old_changed_lines_json"], []) or []
                    ),
                    new_changed_lines=len(
                        load_json(row["new_changed_lines_json"], []) or []
                    ),
                    diff_truncated=bool(row["diff_truncated"]),
                    has_hunks=bool(row["has_hunks"]),
                    symbol_change_count=int(row["symbol_change_count"]),
                )
                for row in rows
            ]
            return summaries, len(summaries)
        except sqlite3.Error as exc:
            raise StorageError(
                f"failed to list change summaries for {run_id!r}: {exc}"
            ) from exc

    def get_change(self, run_id: str, change_id: str) -> Change | None:
        """Load one change (with hunks) that belongs to ``run_id``.

        Returns ``None`` when the change does not exist *or* belongs to another
        run, so a cross-run id can never leak data; an unknown run raises
        :class:`StorageError`.
        """

        conn = self._open_reader()
        try:
            self._require_run_conn(conn, run_id)
            row = conn.execute(
                "SELECT * FROM changes WHERE run_id = ? AND change_id = ?",
                (run_id, change_id),
            ).fetchone()
            return self._change_from_row(row) if row is not None else None
        except sqlite3.Error as exc:
            raise StorageError(
                f"failed to read change {change_id!r} of run {run_id!r}: {exc}"
            ) from exc

    def get_change_hunks_page(
        self,
        run_id: str,
        change_id: str,
        *,
        limit: int = 10,
        offset: int = 0,
    ) -> tuple[list[Hunk], int]:
        """One bounded page of a change's stored hunks plus the total count.

        The page renderer uses this so a long file never sends all of its diff
        blocks in one response.  ``limit`` is capped at 200; an unknown run
        raises :class:`StorageError`, while an unknown/cross-run change returns
        ``([], 0)`` (the caller already validated existence with
        :meth:`get_change`).
        """

        page_limit, page_offset = self._normalise_page(limit, offset)
        conn = self._open_reader()
        try:
            self._require_run_conn(conn, run_id)
            row = conn.execute(
                "SELECT hunks_json FROM changes WHERE run_id = ? AND change_id = ?",
                (run_id, change_id),
            ).fetchone()
            if row is None:
                return [], 0
            data = load_json(row["hunks_json"], [])
            if not isinstance(data, list):
                return [], 0
            hunks: list[Hunk] = []
            for item in data[page_offset : page_offset + page_limit]:
                if not isinstance(item, dict):
                    continue
                hunks.append(
                    Hunk(
                        old_start=int(item.get("old_start", 0) or 0),
                        old_count=int(item.get("old_count", 0) or 0),
                        new_start=int(item.get("new_start", 0) or 0),
                        new_count=int(item.get("new_count", 0) or 0),
                        lines=[str(line) for line in item.get("lines", []) or []],
                    )
                )
            return hunks, len(data)
        except sqlite3.Error as exc:
            raise StorageError(
                f"failed to read hunk page of change {change_id!r} "
                f"of run {run_id!r}: {exc}"
            ) from exc

    def load_symbols(self, run_id: str) -> dict[str, Symbol]:
        """Load the symbol table of one run (no edges/call graph)."""

        conn = self._open_reader()
        try:
            self._require_run_conn(conn, run_id)
            rows = conn.execute(
                "SELECT * FROM symbols WHERE run_id = ? ORDER BY rowid",
                (run_id,),
            ).fetchall()
            return {
                row["symbol_id"]: self._symbol_from_row(row) for row in rows
            }
        except sqlite3.Error as exc:
            raise StorageError(
                f"failed to read symbols of run {run_id!r}: {exc}"
            ) from exc

    def load_symbol_changes(self, run_id: str) -> list[SymbolChange]:
        """Load the symbol change list of one run in its stored order."""

        conn = self._open_reader()
        try:
            self._require_run_conn(conn, run_id)
            return [
                self._symbol_change_from_row(row)
                for row in conn.execute(
                    "SELECT * FROM symbol_changes WHERE run_id = ? ORDER BY rowid",
                    (run_id,),
                )
            ]
        except sqlite3.Error as exc:
            raise StorageError(
                f"failed to read symbol changes of run {run_id!r}: {exc}"
            ) from exc

    def list_candidates_page(
        self,
        run_id: str,
        *,
        limit: int = 25,
        offset: int = 0,
        symbol_change_id: str | None = None,
        side: str | None = None,
        evidence: str | None = None,
    ) -> tuple[list[ImpactCandidate], int]:
        """One stable page of impact candidates plus the filtered total.

        ``limit`` is capped at 200.  Ordering is ``(symbol_change_id,
        candidate_id)`` so pages never repeat or skip rows.
        """

        page_limit, page_offset = self._normalise_page(limit, offset)
        self._require_side(side, what="side")
        conn = self._open_reader()
        try:
            self._require_run_conn(conn, run_id)
            where = ["run_id = ?"]
            params: list[Any] = [run_id]
            if symbol_change_id is not None:
                where.append("symbol_change_id = ?")
                params.append(symbol_change_id)
            if side is not None:
                where.append("side = ?")
                params.append(side)
            if evidence is not None:
                where.append("evidence = ?")
                params.append(evidence)
            where_sql = " WHERE " + " AND ".join(where)
            total = int(
                conn.execute(
                    "SELECT COUNT(*) FROM impact_candidates" + where_sql, params
                ).fetchone()[0]
            )
            rows = conn.execute(
                "SELECT * FROM impact_candidates"
                + where_sql
                + " ORDER BY symbol_change_id ASC, candidate_id ASC"
                " LIMIT ? OFFSET ?",
                [*params, page_limit, page_offset],
            ).fetchall()
            return [self._candidate_from_row(row) for row in rows], total
        except sqlite3.Error as exc:
            raise StorageError(
                f"failed to list candidates of run {run_id!r}: {exc}"
            ) from exc

    def list_tests_page(
        self,
        run_id: str,
        *,
        limit: int = 25,
        offset: int = 0,
        strength: str | None = None,
        side: str | None = None,
    ) -> tuple[list[TestRecommendation], int]:
        """One stable page of test recommendations plus the filtered total.

        ``limit`` is capped at 200.  Ordering is strong associations first, then
        ``min_depth`` (distance) and the test reference (path/name).
        """

        page_limit, page_offset = self._normalise_page(limit, offset)
        self._require_side(side, what="side")
        if strength is not None and strength not in (
            TEST_STRENGTH_STRONG,
            TEST_STRENGTH_WEAK,
        ):
            raise StorageError(f"invalid strength filter: {strength!r}")
        conn = self._open_reader()
        try:
            self._require_run_conn(conn, run_id)
            where = ["run_id = ?"]
            params: list[Any] = [run_id]
            if strength is not None:
                where.append("strength = ?")
                params.append(strength)
            if side is not None:
                where.append("side = ?")
                params.append(side)
            where_sql = " WHERE " + " AND ".join(where)
            total = int(
                conn.execute(
                    "SELECT COUNT(*) FROM test_recommendations" + where_sql, params
                ).fetchone()[0]
            )
            rows = conn.execute(
                "SELECT * FROM test_recommendations"
                + where_sql
                + """
                 ORDER BY CASE strength WHEN 'strong' THEN 0 ELSE 1 END ASC,
                          min_depth ASC, test_path ASC, qualified_name ASC,
                          side ASC
                 LIMIT ? OFFSET ?
                """,
                [*params, page_limit, page_offset],
            ).fetchall()
            return [self._recommendation_from_row(row) for row in rows], total
        except sqlite3.Error as exc:
            raise StorageError(
                f"failed to list test recommendations of run {run_id!r}: {exc}"
            ) from exc

    def list_judge_verdicts_page(
        self,
        run_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[JudgeVerdict], int]:
        """One stable page of stored Judge verdicts plus the total count.

        Judge rows are only rendered as a folded detail on the Run page; the full
        report/JSON API keeps using :meth:`load_run`.
        """

        page_limit, page_offset = self._normalise_page(limit, offset)
        conn = self._open_reader()
        try:
            self._require_run_conn(conn, run_id)
            total = int(
                conn.execute(
                    "SELECT COUNT(*) FROM judge_verdicts WHERE run_id = ?",
                    (run_id,),
                ).fetchone()[0]
            )
            rows = conn.execute(
                "SELECT * FROM judge_verdicts WHERE run_id = ? "
                "ORDER BY candidate_id ASC, rowid ASC LIMIT ? OFFSET ?",
                (run_id, page_limit, page_offset),
            ).fetchall()
            return [self._judge_verdict_from_row(row) for row in rows], total
        except sqlite3.Error as exc:
            raise StorageError(
                f"failed to list judge verdicts of run {run_id!r}: {exc}"
            ) from exc

    def list_judge_attempts_page(
        self,
        run_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[JudgeAttempt], int]:
        """One stable page of stored Judge attempts plus the total count."""

        page_limit, page_offset = self._normalise_page(limit, offset)
        conn = self._open_reader()
        try:
            self._require_run_conn(conn, run_id)
            total = int(
                conn.execute(
                    "SELECT COUNT(*) FROM judge_attempts WHERE run_id = ?",
                    (run_id,),
                ).fetchone()[0]
            )
            rows = conn.execute(
                "SELECT * FROM judge_attempts WHERE run_id = ? "
                "ORDER BY candidate_id ASC, attempt_no ASC, rowid ASC "
                "LIMIT ? OFFSET ?",
                (run_id, page_limit, page_offset),
            ).fetchall()
            return [self._judge_attempt_from_row(row) for row in rows], total
        except sqlite3.Error as exc:
            raise StorageError(
                f"failed to list judge attempts of run {run_id!r}: {exc}"
            ) from exc

    def list_diagnostics(
        self, run_id: str, *, limit: int = 200
    ) -> list[tuple[Diagnostic, str]]:
        """Run/change/symbol-change diagnostics, deduplicated and bounded.

        The Run page shows these in a folded section and uses them for the
        coverage-gap summary; comparison and evidence rows are not loaded.
        """

        page_limit, _offset = self._normalise_page(limit, 0)
        conn = self._open_reader()
        try:
            self._require_run_conn(conn, run_id)
            collected: list[tuple[Diagnostic, str]] = []
            seen: set[tuple[Any, ...]] = set()

            def add(raw: Any, source: str) -> None:
                if isinstance(raw, dict):
                    diagnostic = Diagnostic.from_dict(raw)
                elif isinstance(raw, Diagnostic):
                    diagnostic = raw
                else:
                    return
                key = (
                    diagnostic.severity,
                    diagnostic.code,
                    diagnostic.message,
                    diagnostic.path,
                    diagnostic.line,
                )
                if key in seen:
                    return
                seen.add(key)
                collected.append((diagnostic, source))

            run_row = conn.execute(
                "SELECT diagnostics_json FROM analysis_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            for raw in load_json(run_row["diagnostics_json"] if run_row else None, []):
                add(raw, "运行级")
            for row in conn.execute(
                "SELECT change_id, diagnostics_json FROM changes WHERE run_id = ? "
                "ORDER BY change_id",
                (run_id,),
            ):
                for raw in load_json(row["diagnostics_json"], []):
                    add(raw, f"变更 {row['change_id']}")
            for row in conn.execute(
                "SELECT symbol_change_id, diagnostics_json FROM symbol_changes "
                "WHERE run_id = ? ORDER BY symbol_change_id",
                (run_id,),
            ):
                for raw in load_json(row["diagnostics_json"], []):
                    add(raw, f"符号变更 {row['symbol_change_id']}")
            return collected[:page_limit]
        except sqlite3.Error as exc:
            raise StorageError(
                f"failed to list diagnostics of run {run_id!r}: {exc}"
            ) from exc

    # -- write helpers --------------------------------------------------------

    @staticmethod
    def _require_valid_run_id(run_id: str) -> None:
        if not is_valid_run_id(run_id):
            raise StorageError(f"invalid run id: {run_id!r}")

    @staticmethod
    def _snapshot_entry_rows(
        run_id: str, snapshot: Snapshot
    ) -> list[tuple[Any, ...]]:
        rows: list[tuple[Any, ...]] = []
        sides = {"before": snapshot.before, "after": snapshot.after}
        for side_name in SIDES:
            side = sides.get(side_name)
            entries = getattr(side, "entries", None) or {}
            for path in sorted(entries):
                entry = entries[path]
                if entry.side != side_name:
                    raise StorageError(
                        f"snapshot entry {path!r} declares side {entry.side!r} "
                        f"but belongs to {side_name!r}"
                    )
                rows.append(
                    (
                        run_id,
                        entry.side,
                        entry.path,
                        entry.status,
                        entry.content_sha256,
                        entry.git_oid,
                        entry.size,
                        1 if entry.is_python else 0,
                        entry.detail,
                    )
                )
        return rows

    @staticmethod
    def _index_symbols(index: Any) -> list[Any]:
        mapping = getattr(index, "symbols", None)
        if mapping is None:
            return []
        if hasattr(mapping, "values"):
            return list(mapping.values())
        return list(mapping)

    @staticmethod
    def _stored_evidence_bytes(conn: sqlite3.Connection, run_id: str) -> int:
        """Bytes of hunk lines already stored for this run (retry safety)."""

        used = 0
        for row in conn.execute(
            "SELECT hunks_json FROM changes WHERE run_id = ?", (run_id,)
        ):
            for hunk in load_json(row[0], []) or []:
                for line in hunk.get("lines") or []:
                    used += len(str(line).encode("utf-8"))
        return used

    def _apply_evidence_policy(
        self, change: Change, used_bytes: int
    ) -> tuple[list[Hunk], list[dict[str, Any]], bool, bool]:
        """Return ``(hunks, diagnostics, diff_truncated, budget_exhausted)``.

        ``metadata_only`` drops all hunk lines but keeps ranges and counts.
        Otherwise the cumulative UTF-8 budget is enforced by keeping a line
        prefix that still fits; once a change does not fit the remaining budget
        the run is treated as exhausted, so later changes are flagged too.  Every
        change that loses evidence is flagged with ``diff_truncated`` and a
        diagnostic.
        """

        diagnostics = [item.to_dict() for item in change.diagnostics or []]
        hunks = list(change.hunks or [])
        truncated = bool(change.diff_truncated)
        if not hunks:
            return hunks, diagnostics, truncated, False
        if self.evidence_mode == "metadata_only":
            stripped = [
                Hunk(
                    old_start=hunk.old_start,
                    old_count=hunk.old_count,
                    new_start=hunk.new_start,
                    new_count=hunk.new_count,
                    lines=[],
                )
                for hunk in hunks
            ]
            diagnostics.append(
                Diagnostic(
                    code="metadata_only",
                    message=(
                        "hunk lines were not stored because "
                        "storage.evidence_mode is metadata_only"
                    ),
                    severity="info",
                    path=change.display_path or None,
                ).to_dict()
            )
            return stripped, diagnostics, True, False
        budget = self.max_evidence_bytes_per_run
        remaining = max(0, budget - used_bytes)
        hunk_bytes = sum(
            len(line.encode("utf-8")) for hunk in hunks for line in hunk.lines
        )
        if hunk_bytes <= remaining:
            return hunks, diagnostics, truncated, False
        kept_hunks: list[Hunk] = []
        left = remaining
        for hunk in hunks:
            kept_lines: list[str] = []
            for line in hunk.lines:
                size = len(line.encode("utf-8"))
                if size <= left:
                    kept_lines.append(line)
                    left -= size
                else:
                    left = 0
                    break
            kept_hunks.append(
                Hunk(
                    old_start=hunk.old_start,
                    old_count=hunk.old_count,
                    new_start=hunk.new_start,
                    new_count=hunk.new_count,
                    lines=kept_lines,
                )
            )
        diagnostics.append(
            Diagnostic(
                code="evidence_truncated",
                message=(
                    "hunk text for this change exceeded "
                    f"max_evidence_bytes_per_run ({budget} bytes)"
                ),
                severity="warning",
                path=change.display_path or None,
                details={"limit": budget},
            ).to_dict()
        )
        return kept_hunks, diagnostics, True, True

    # -- read helpers ---------------------------------------------------------

    def _list_runs(
        self,
        conn: sqlite3.Connection,
        repo_id: str | None,
        limit: int,
        offset: int,
        *,
        status: str | None = None,
        branch: str | None = None,
        mode: str | None = None,
    ) -> tuple[list[RunSummary], int]:
        limit = max(0, limit)
        offset = max(0, offset)
        where: list[str] = []
        params: list[Any] = []
        if repo_id is not None:
            where.append("r.repo_id = ?")
            params.append(repo_id)
        if status is not None:
            where.append("r.status = ?")
            params.append(status)
        if branch is not None:
            where.append("r.branch = ?")
            params.append(branch)
        if mode is not None:
            where.append("r.mode = ?")
            params.append(mode)
        where_sql = (" WHERE " + " AND ".join(where)) if where else ""
        total = int(
            conn.execute(
                "SELECT COUNT(*) FROM analysis_runs r" + where_sql, params
            ).fetchone()[0]
        )
        rows = conn.execute(
            """
            SELECT r.run_id, r.repo_id, r.display_name, r.repo_root, r.branch,
                   r.detached, r.mode, r.endpoint_before, r.endpoint_after,
                   r.started_at, r.finished_at, r.status, r.summary,
                   (SELECT COUNT(*) FROM changes c
                     WHERE c.run_id = r.run_id) AS changes_count,
                   (SELECT COUNT(*) FROM symbol_changes sc
                     WHERE sc.run_id = r.run_id) AS symbol_changes_count,
                   (SELECT COUNT(*) FROM impact_candidates ic
                     WHERE ic.run_id = r.run_id) AS candidates_count,
                   (SELECT COUNT(*) FROM test_recommendations tr
                     WHERE tr.run_id = r.run_id) AS tests_count
              FROM analysis_runs r
            """
            + where_sql
            + " ORDER BY r.started_at DESC, r.run_id DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
        summaries = [self._summary_from_row(row) for row in rows]
        return summaries, total

    def _list_runs_page(
        self,
        conn: sqlite3.Connection,
        repo_id: str | None,
        limit: int,
        cursor: str | None,
    ) -> tuple[list[RunSummary], str | None, int]:
        limit = max(0, int(limit))
        where: list[str] = []
        params: list[Any] = []
        if repo_id is not None:
            where.append("r.repo_id = ?")
            params.append(repo_id)
        where_sql = (" WHERE " + " AND ".join(where)) if where else ""
        total = int(
            conn.execute(
                "SELECT COUNT(*) FROM analysis_runs r" + where_sql, params
            ).fetchone()[0]
        )
        if limit == 0:
            return [], None, total
        if cursor is not None:
            cursor_started_at, cursor_run_id = self._decode_run_cursor(cursor)
            where.append(
                "(r.started_at < ? OR (r.started_at = ? AND r.run_id < ?))"
            )
            params.extend([cursor_started_at, cursor_started_at, cursor_run_id])
            where_sql = " WHERE " + " AND ".join(where)
        rows = conn.execute(
            """
            SELECT r.run_id, r.repo_id, r.display_name, r.repo_root, r.branch,
                   r.detached, r.mode, r.endpoint_before, r.endpoint_after,
                   r.started_at, r.finished_at, r.status, r.summary,
                   (SELECT COUNT(*) FROM changes c
                     WHERE c.run_id = r.run_id) AS changes_count,
                   (SELECT COUNT(*) FROM symbol_changes sc
                     WHERE sc.run_id = r.run_id) AS symbol_changes_count,
                   (SELECT COUNT(*) FROM impact_candidates ic
                     WHERE ic.run_id = r.run_id) AS candidates_count,
                   (SELECT COUNT(*) FROM test_recommendations tr
                     WHERE tr.run_id = r.run_id) AS tests_count
              FROM analysis_runs r
            """
            + where_sql
            + " ORDER BY r.started_at DESC, r.run_id DESC LIMIT ?",
            [*params, limit + 1],
        ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        summaries = [self._summary_from_row(row) for row in rows]
        next_cursor: str | None = None
        if has_more and rows:
            last = rows[-1]
            next_cursor = self._encode_run_cursor(last["started_at"], last["run_id"])
        return summaries, next_cursor, total

    @staticmethod
    def _encode_run_cursor(started_at: str, run_id: str) -> str:
        raw = f"{started_at}|{run_id}".encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii")

    @staticmethod
    def _decode_run_cursor(cursor: str) -> tuple[str, str]:
        if not isinstance(cursor, str) or not cursor:
            raise StorageError("invalid cursor")
        try:
            padded = cursor + "=" * (-len(cursor) % 4)
            raw = base64.b64decode(
                padded.encode("ascii"), altchars=b"-_", validate=True
            )
            text = raw.decode("utf-8")
        except (ValueError, TypeError, UnicodeDecodeError) as exc:
            raise StorageError("invalid cursor") from exc
        started_at, separator, run_id = text.partition("|")
        if not separator or not started_at or not run_id or "|" in run_id:
            raise StorageError("invalid cursor")
        if _parse_timestamp(started_at) is None or not is_valid_run_id(run_id):
            raise StorageError("invalid cursor")
        return started_at, run_id

    # -- bounded-query helpers (US-2) -----------------------------------------

    def _open_reader(self) -> sqlite3.Connection:
        conn = self._ensure_conn()
        self._require_schema(conn)
        return conn

    @staticmethod
    def _require_run_conn(conn: sqlite3.Connection, run_id: str) -> None:
        row = conn.execute(
            "SELECT 1 FROM analysis_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            raise StorageError(f"run not found: {run_id}")

    @staticmethod
    def _normalise_page(limit: Any, offset: Any) -> tuple[int, int]:
        try:
            page_size = int(limit)
            start = int(offset)
        except (TypeError, ValueError) as exc:
            raise StorageError("limit and offset must be integers") from exc
        return max(0, min(page_size, _MAX_PAGE_LIMIT)), max(0, start)

    @staticmethod
    def _require_side(value: str | None, *, what: str) -> None:
        if value is not None and value not in SIDES:
            raise StorageError(
                f"invalid {what} filter: {value!r} (expected 'before' or 'after')"
            )

    @staticmethod
    def _validate_run_status_filter(status: str | None) -> str | None:
        if status is None:
            return None
        if not isinstance(status, str) or status not in RUN_STATUSES:
            raise StorageError(
                f"invalid run status filter: {status!r} "
                f"(expected one of {', '.join(RUN_STATUSES)})"
            )
        return status

    @staticmethod
    def _validate_run_mode_filter(mode: str | None) -> str | None:
        if mode is None:
            return None
        if not isinstance(mode, str) or mode not in ALL_MODES:
            raise StorageError(
                f"invalid run mode filter: {mode!r} "
                f"(expected one of {', '.join(ALL_MODES)})"
            )
        return mode

    @staticmethod
    def _counts_for_run(conn: sqlite3.Connection, run_id: str) -> dict[str, int]:
        row = conn.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM changes c
                WHERE c.run_id = ?) AS changes_count,
              (SELECT COUNT(*) FROM symbol_changes sc
                WHERE sc.run_id = ?) AS symbol_changes_count,
              (SELECT COUNT(*) FROM impact_candidates ic
                WHERE ic.run_id = ?) AS candidates_count,
              (SELECT COUNT(*) FROM test_recommendations tr
                WHERE tr.run_id = ?) AS tests_count
            """,
            (run_id, run_id, run_id, run_id),
        ).fetchone()
        return {
            "changes": int(row["changes_count"]),
            "symbol_changes": int(row["symbol_changes_count"]),
            "candidates": int(row["candidates_count"]),
            "tests": int(row["tests_count"]),
        }

    @staticmethod
    def _snapshot_scope(
        conn: sqlite3.Connection, run_id: str
    ) -> dict[str, int]:
        scope = {
            "before_files": 0,
            "after_files": 0,
            "before_python": 0,
            "after_python": 0,
        }
        rows = conn.execute(
            "SELECT side, is_python, COUNT(*) AS entry_count "
            "FROM snapshot_entries WHERE run_id = ? "
            "GROUP BY side, is_python",
            (run_id,),
        ).fetchall()
        for row in rows:
            side = row["side"]
            if side not in SIDES:
                continue
            count = int(row["entry_count"])
            scope[f"{side}_files"] += count
            if bool(row["is_python"]):
                scope[f"{side}_python"] += count
        return scope

    @staticmethod
    def _overview_stages(metrics: dict[str, Any]) -> dict[str, int]:
        raw = metrics.get("stages") if isinstance(metrics, dict) else None
        if not isinstance(raw, dict):
            return {}
        return {
            str(name): int(value)
            for name, value in raw.items()
            if isinstance(value, int) and not isinstance(value, bool)
        }

    @staticmethod
    def _overview_stage_errors(metrics: dict[str, Any]) -> list[str]:
        raw = metrics.get("stage_errors") if isinstance(metrics, dict) else None
        if not isinstance(raw, list):
            return []
        return [str(item) for item in raw]

    @staticmethod
    def _summary_from_row(row: sqlite3.Row) -> RunSummary:
        return RunSummary(
            run_id=row["run_id"],
            repo_id=row["repo_id"],
            display_name=row["display_name"],
            repo_root=row["repo_root"],
            branch=row["branch"],
            detached=bool(row["detached"]),
            mode=row["mode"],
            endpoint_before=row["endpoint_before"],
            endpoint_after=row["endpoint_after"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            status=row["status"],
            summary=row["summary"],
            counts={
                "changes": int(row["changes_count"]),
                "symbol_changes": int(row["symbol_changes_count"]),
                "candidates": int(row["candidates_count"]),
                "tests": int(row["tests_count"]),
            },
        )

    def _load_run(self, conn: sqlite3.Connection, run_id: str) -> RunDetail:
        row = conn.execute(
            "SELECT * FROM analysis_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            raise StorageError(f"run not found: {run_id}")
        run = self._analysis_run_from_row(row)
        changes = [
            self._change_from_row(item)
            for item in conn.execute(
                "SELECT * FROM changes WHERE run_id = ? ORDER BY rowid", (run_id,)
            )
        ]
        symbols = {
            item["symbol_id"]: self._symbol_from_row(item)
            for item in conn.execute(
                "SELECT * FROM symbols WHERE run_id = ? ORDER BY rowid", (run_id,)
            )
        }
        edges = [
            self._edge_from_row(item)
            for item in conn.execute(
                "SELECT * FROM call_edges WHERE run_id = ? ORDER BY rowid", (run_id,)
            )
        ]
        symbol_changes = [
            self._symbol_change_from_row(item)
            for item in conn.execute(
                "SELECT * FROM symbol_changes WHERE run_id = ? ORDER BY rowid",
                (run_id,),
            )
        ]
        candidates = [
            self._candidate_from_row(item)
            for item in conn.execute(
                "SELECT * FROM impact_candidates WHERE run_id = ? ORDER BY rowid",
                (run_id,),
            )
        ]
        recommendations = [
            self._recommendation_from_row(item)
            for item in conn.execute(
                "SELECT * FROM test_recommendations WHERE run_id = ? ORDER BY rowid",
                (run_id,),
            )
        ]
        snapshot_entries = [
            self._snapshot_entry_from_row(item)
            for item in conn.execute(
                """
                SELECT * FROM snapshot_entries
                 WHERE run_id = ?
                 ORDER BY CASE side WHEN 'before' THEN 0 ELSE 1 END, path
                """,
                (run_id,),
            )
        ]
        judge_attempts = [
            self._judge_attempt_from_row(item)
            for item in conn.execute(
                "SELECT * FROM judge_attempts WHERE run_id = ? ORDER BY rowid",
                (run_id,),
            )
        ]
        judge_verdicts = [
            self._judge_verdict_from_row(item)
            for item in conn.execute(
                "SELECT * FROM judge_verdicts WHERE run_id = ? ORDER BY rowid",
                (run_id,),
            )
        ]
        return RunDetail(
            run=run,
            changes=changes,
            symbols=symbols,
            edges=edges,
            symbol_changes=symbol_changes,
            candidates=candidates,
            test_recommendations=recommendations,
            snapshot_entries=snapshot_entries,
            judge_attempts=judge_attempts,
            judge_verdicts=judge_verdicts,
        )

    @staticmethod
    def _analysis_run_from_row(row: sqlite3.Row) -> AnalysisRun:
        return AnalysisRun(
            run_id=row["run_id"],
            repo_id=row["repo_id"],
            display_name=row["display_name"],
            repo_root=row["repo_root"],
            branch=row["branch"],
            detached=bool(row["detached"]),
            mode=row["mode"],
            endpoint_before=row["endpoint_before"],
            endpoint_after=row["endpoint_after"],
            started_at=row["started_at"],
            status=row["status"],
            summary=row["summary"],
            finished_at=row["finished_at"],
            config_digest=row["config_digest"],
            analyzer_version=row["analyzer_version"],
            snapshot_format_version=int(row["snapshot_format_version"]),
            schema_version=int(row["schema_version"]),
            task_id=row["task_id"],
            metrics=load_json(row["metrics_json"], {}) or {},
            diagnostics=[
                Diagnostic.from_dict(item)
                for item in load_json(row["diagnostics_json"], []) or []
            ],
        )

    @staticmethod
    def _change_from_row(row: sqlite3.Row) -> Change:
        return Change(
            change_id=row["change_id"],
            kind=row["kind"],
            old_path=row["old_path"],
            new_path=row["new_path"],
            old_sha256=row["old_sha256"],
            new_sha256=row["new_sha256"],
            rename_basis=row["rename_basis"],
            analysis_status=row["analysis_status"],
            old_changed_lines=list(load_json(row["old_changed_lines_json"], []) or []),
            new_changed_lines=list(load_json(row["new_changed_lines_json"], []) or []),
            hunks=[
                dataclass_from_dict(Hunk, item)
                for item in load_json(row["hunks_json"], []) or []
            ],
            diff_truncated=bool(row["diff_truncated"]),
            diagnostics=[
                Diagnostic.from_dict(item)
                for item in load_json(row["diagnostics_json"], []) or []
            ],
        )

    @staticmethod
    def _symbol_from_row(row: sqlite3.Row) -> Symbol:
        return Symbol(
            symbol_id=row["symbol_id"],
            side=row["side"],
            path=row["path"],
            module=row["module"],
            qualified_name=row["qualified_name"],
            kind=row["kind"],
            parent_id=row["parent_id"],
            start_line=int(row["start_line"]),
            end_line=int(row["end_line"]),
            def_line=int(row["def_line"]),
            decorator_start=row["decorator_start"],
            is_test=bool(row["is_test"]),
        )

    @staticmethod
    def _edge_from_row(row: sqlite3.Row) -> CallEdge:
        return CallEdge(
            edge_id=row["edge_id"],
            side=row["side"],
            caller_id=row["caller_id"],
            callee_id=row["callee_id"],
            path=row["path"],
            line=int(row["line"]),
            col=int(row["col"]),
            edge_kind=row["edge_kind"],
            resolution=row["resolution"],
            reason=row["reason"],
            target=row["target"],
            callee_module=row["callee_module"],
        )

    @staticmethod
    def _symbol_change_from_row(row: sqlite3.Row) -> SymbolChange:
        return SymbolChange(
            symbol_change_id=row["symbol_change_id"],
            change_id=row["change_id"],
            kind=row["kind"],
            reason=row["reason"],
            old_symbol_id=row["old_symbol_id"],
            new_symbol_id=row["new_symbol_id"],
            structure_changed=bool(row["structure_changed"]),
            old_changed_lines=list(load_json(row["old_changed_lines_json"], []) or []),
            new_changed_lines=list(load_json(row["new_changed_lines_json"], []) or []),
            diagnostics=[
                Diagnostic.from_dict(item)
                for item in load_json(row["diagnostics_json"], []) or []
            ],
            details=dict(load_json(row["details_json"], {}) or {}),
        )

    @staticmethod
    def _judge_attempt_from_row(row: sqlite3.Row) -> JudgeAttempt:
        return JudgeAttempt(
            attempt_id=row["attempt_id"],
            candidate_id=row["candidate_id"],
            attempt_no=int(row["attempt_no"]),
            adapter=row["adapter"],
            model=row["model"],
            started_at=row["started_at"],
            duration_ms=int(row["duration_ms"]),
            context_digest=row["context_digest"],
            context_bytes=int(row["context_bytes"]),
            context_tokens_estimate=int(row["context_tokens_estimate"]),
            cache_hit=bool(row["cache_hit"]),
            valid=bool(row["valid"]),
            error_category=row["error_category"],
            fallback_reason=row["fallback_reason"],
            request_id=row["request_id"],
            context_summary=dict(load_json(row["context_summary_json"], {}) or {}),
            usage=dict(load_json(row["usage_json"], {}) or {}),
        )

    @staticmethod
    def _judge_verdict_from_row(row: sqlite3.Row) -> JudgeVerdict:
        evidence = load_json(row["evidence_json"], [])
        conditions = load_json(row["conditions_json"], [])
        return JudgeVerdict(
            candidate_id=row["candidate_id"],
            attempt_no=int(row["attempt_no"]),
            verdict=row["verdict"],
            reason=row["reason"],
            adapter=row["adapter"],
            model=row["model"],
            evidence=list(evidence) if isinstance(evidence, list) else [],
            conditions=[str(item) for item in conditions]
            if isinstance(conditions, list)
            else [],
            uncertainty=row["uncertainty"],
            schema_version=int(row["schema_version"]),
            validated_at=row["validated_at"],
        )

    @staticmethod
    def _candidate_from_row(row: sqlite3.Row) -> ImpactCandidate:
        return ImpactCandidate(
            candidate_id=row["candidate_id"],
            symbol_change_id=row["symbol_change_id"],
            seed_symbol_id=row["seed_symbol_id"],
            candidate_symbol_id=row["candidate_symbol_id"],
            side=row["side"],
            min_depth=int(row["min_depth"]),
            edge_ids=list(load_json(row["edge_ids_json"], []) or []),
            evidence=row["evidence"],
            truncated=bool(row["truncated"]),
        )

    @staticmethod
    def _recommendation_from_row(row: sqlite3.Row) -> TestRecommendation:
        stored_name = row["qualified_name"]
        return TestRecommendation(
            test_path=row["test_path"],
            qualified_name=stored_name if stored_name else None,
            side=row["side"],
            candidate_ids=list(load_json(row["candidate_ids_json"], []) or []),
            min_depth=int(row["min_depth"]),
            strength=row["strength"],
            evidence=row["evidence"],
            exists_in_after=bool(row["exists_in_after"]),
            test_symbol_id=row["test_symbol_id"],
        )

    @staticmethod
    def _snapshot_entry_from_row(row: sqlite3.Row) -> SnapshotEntry:
        return SnapshotEntry(
            side=row["side"],
            path=row["path"],
            status=row["status"],
            content_sha256=row["content_sha256"],
            git_oid=row["git_oid"],
            size=row["size"],
            is_python=bool(row["is_python"]),
            detail=row["detail"],
        )
