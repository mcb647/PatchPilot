"""Domain models shared by every PatchPilot stage.

This module is intentionally dependency free (standard library only).  All
other modules -- snapshot capture, diffing, AST indexing, impact tracing,
storage, reporting and the web UI -- speak in terms of these dataclasses.

Persisted representation is plain JSON-friendly dictionaries; the objects held
in memory during one analysis additionally keep transient fields (file text,
resolved index objects, ...) which never cross the persistence boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 3
SNAPSHOT_FORMAT_VERSION = 1
ANALYZER_VERSION = "0.2.0"

SIDE_BEFORE = "before"
SIDE_AFTER = "after"
SIDES = (SIDE_BEFORE, SIDE_AFTER)

# Git comparison entry points (P0 + P1).
MODE_WORKTREE_NET = "worktree-net"
MODE_STAGED = "staged"
MODE_WORKING_TREE = "working-tree"
MODE_BASE = "base"
MODE_COMMIT = "commit"
MODE_RANGE = "range"
P0_MODES = (MODE_WORKTREE_NET, MODE_STAGED, MODE_WORKING_TREE, MODE_BASE)
P1_MODES = (MODE_COMMIT, MODE_RANGE)
ALL_MODES = P0_MODES + P1_MODES

# Run lifecycle.
RUN_RUNNING = "running"
RUN_COMPLETED = "completed"
RUN_PARTIAL = "partial"
RUN_FAILED = "failed"
RUN_STATUSES = (RUN_RUNNING, RUN_COMPLETED, RUN_PARTIAL, RUN_FAILED)

# Business summary (independent from lifecycle).
SUMMARY_NO_CHANGES = "no_changes"
SUMMARY_NO_CANDIDATES = "no_candidates"
SUMMARY_CANDIDATES_FOUND = "candidates_found"
SUMMARY_UNKNOWN = "unknown"

CHANGE_ADDED = "added"
CHANGE_REMOVED = "removed"
CHANGE_MODIFIED = "modified"
CHANGE_RENAMED = "renamed"

SYMBOL_MODULE = "module"
SYMBOL_FUNCTION = "function"
SYMBOL_ASYNC_FUNCTION = "async_function"
SYMBOL_CLASS = "class"
SYMBOL_METHOD = "method"
SYMBOL_NESTED_FUNCTION = "nested_function"

SYMCHANGE_ADDED = "added"
SYMCHANGE_REMOVED = "removed"
SYMCHANGE_MODIFIED = "modified"
SYMCHANGE_RENAMED = "renamed"

EDGE_CALL = "call"
EDGE_IMPORT = "import"
# P1: a function reads a module-level variable of the same module.  The edge
# points at the module pseudo symbol as callee and carries the variable name in
# ``target`` (used by impact tracing to match module-level symbol changes).
EDGE_GLOBAL_READ = "global_read"

EVIDENCE_CALL = "call_path"
EVIDENCE_IMPORT = "imports_module"
EVIDENCE_GLOBAL_READ = "global_read"

TEST_STRENGTH_STRONG = "strong"
TEST_STRENGTH_WEAK = "weak"

# P1 M1: local analysis task queue.
TASK_QUEUED = "queued"
TASK_RUNNING = "running"
TASK_COMPLETED = "completed"
TASK_PARTIAL = "partial"
TASK_FAILED = "failed"
TASK_CANCELLED = "cancelled"
TASK_INTERRUPTED = "interrupted"
TASK_STATUSES = (
    TASK_QUEUED,
    TASK_RUNNING,
    TASK_COMPLETED,
    TASK_PARTIAL,
    TASK_FAILED,
    TASK_CANCELLED,
    TASK_INTERRUPTED,
)
TASK_STAGE_EVENT_KINDS = ("start", "done", "failed", "info")

# P1 Judge domain values.
JUDGE_DISABLED = "disabled"
JUDGE_PENDING = "pending"
JUDGE_COMPLETED = "completed"
JUDGE_PARTIAL = "partial"
JUDGE_FAILED = "failed"
JUDGE_STATUSES = (JUDGE_DISABLED, JUDGE_PENDING, JUDGE_COMPLETED, JUDGE_PARTIAL, JUDGE_FAILED)

VERDICT_AFFECTED = "affected"
VERDICT_UNAFFECTED = "unaffected"
VERDICT_UNCERTAIN = "uncertain"
VERDICTS = (VERDICT_AFFECTED, VERDICT_UNAFFECTED, VERDICT_UNCERTAIN)

# Normalized adapter error categories (used by Judge fallback and diagnostics).
JUDGE_ERROR_UNAVAILABLE = "unavailable"
JUDGE_ERROR_TIMEOUT = "timeout"
JUDGE_ERROR_INVALID_OUTPUT = "invalid_output"
JUDGE_ERROR_RATE_LIMITED = "rate_limited"
JUDGE_ERROR_AUTH = "auth"
JUDGE_ERROR_BUDGET_EXHAUSTED = "budget_exhausted"
JUDGE_ERROR_NOT_CONFIGURED = "not_configured"
JUDGE_ERROR_CONTEXT_INSUFFICIENT = "context_insufficient"
JUDGE_ERROR_SECRET_REDACTED = "secret_redacted"
JUDGE_ERROR_CACHE_MISS = "cache_miss"
JUDGE_ERRORS = (
    JUDGE_ERROR_UNAVAILABLE,
    JUDGE_ERROR_TIMEOUT,
    JUDGE_ERROR_INVALID_OUTPUT,
    JUDGE_ERROR_RATE_LIMITED,
    JUDGE_ERROR_AUTH,
    JUDGE_ERROR_BUDGET_EXHAUSTED,
    JUDGE_ERROR_NOT_CONFIGURED,
    JUDGE_ERROR_CONTEXT_INSUFFICIENT,
    JUDGE_ERROR_SECRET_REDACTED,
    JUDGE_ERROR_CACHE_MISS,
)

# Fallback triggers accepted by ``judge.fallback_on``.
JUDGE_FALLBACK_TRIGGERS = (
    JUDGE_ERROR_UNAVAILABLE,
    JUDGE_ERROR_TIMEOUT,
    JUDGE_ERROR_INVALID_OUTPUT,
    JUDGE_ERROR_RATE_LIMITED,
    JUDGE_ERROR_AUTH,
    JUDGE_ERROR_CONTEXT_INSUFFICIENT,
    VERDICT_UNCERTAIN,
)

JUDGE_SCHEMA_VERSION = 1
JUDGE_PROMPT_VERSION = "p1-1"

_SAFE_RUN_ID = re.compile(r"^[0-9A-Za-z][0-9A-Za-z_.-]{0,127}$")


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def utc_now() -> str:
    """Return the current UTC time as ``YYYY-MM-DDTHH:MM:SS.sssZ``."""

    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:8]}"


def is_valid_run_id(value: str) -> bool:
    return bool(_SAFE_RUN_ID.match(value or ""))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", "replace"))


def source_lines(text: str) -> list[str]:
    """Split LF-normalized source using the same physical lines as Python's AST."""
    return text.removesuffix("\n").split("\n") if text else []


def canonical_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_of(data: Any) -> str:
    return sha256_text(canonical_json(data))


def repo_id_for(root: Path) -> str:
    """Stable identity of a working tree, used to isolate local databases."""

    resolved = os.path.realpath(str(root))
    if os.name == "nt":
        resolved = resolved.casefold()
    return sha256_text("patchpilot-repo:" + resolved)


def repo_display_name(root: Path) -> str:
    return Path(root).resolve().name or str(root)


def module_symbol_id(side: str, path: str) -> str:
    return f"sym:{side}:{path}:<module>"


def symbol_id(side: str, path: str, qualified_name: str, def_line: int) -> str:
    if not qualified_name:
        return module_symbol_id(side, path)
    return f"sym:{side}:{path}:{qualified_name}:{def_line}"


def edge_id(side: str, caller_id: str, to_text: str, line: int, col: int, kind: str) -> str:
    raw = f"{side}|{caller_id}|{to_text}|{line}|{col}|{kind}"
    return "edge:" + hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]


# --------------------------------------------------------------------------
# diagnostics
# --------------------------------------------------------------------------


@dataclass
class Diagnostic:
    code: str
    message: str
    severity: str = "warning"  # info | warning | error
    path: str | None = None
    line: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Diagnostic":
        return cls(
            code=data.get("code", "unknown"),
            message=data.get("message", ""),
            severity=data.get("severity", "warning"),
            path=data.get("path"),
            line=data.get("line"),
            details=dict(data.get("details") or {}),
        )


def diag(code: str, message: str, severity: str = "warning", **kwargs: Any) -> Diagnostic:
    return Diagnostic(code=code, message=message, severity=severity, **kwargs)


# --------------------------------------------------------------------------
# snapshot
# --------------------------------------------------------------------------


@dataclass
class SnapshotEntry:
    """One path on one comparison endpoint.

    ``status`` is one of ``present``, ``missing``, ``unreadable``,
    ``decode_error``, ``too_large`` or ``excluded``.  A missing path is not an
    empty file: an empty file is ``present`` with size 0.
    """

    side: str
    path: str
    status: str = "present"
    content_sha256: str | None = None
    git_oid: str | None = None
    size: int | None = None
    is_python: bool = False
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SnapshotSide:
    side: str
    entries: dict[str, SnapshotEntry] = field(default_factory=dict)
    # Text content of analysis-eligible Python files (path -> text).
    contents: dict[str, str] = field(default_factory=dict)
    manifest_digest: str = ""
    # Worktree paths whose captured bytes match the other side after Git EOL conversion.
    eol_equivalent_paths: set[str] = field(default_factory=set)

    def entry(self, path: str) -> SnapshotEntry | None:
        return self.entries.get(path)

    def text(self, path: str) -> str | None:
        return self.contents.get(path)


@dataclass
class Snapshot:
    mode: str
    repo_root: str
    repo_id: str
    display_name: str
    branch: str | None
    detached: bool
    endpoint_before: str
    endpoint_after: str
    before: SnapshotSide
    after: SnapshotSide
    config_digest: str
    captured_at: str = field(default_factory=utc_now)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    snapshot_format_version: int = SNAPSHOT_FORMAT_VERSION


# --------------------------------------------------------------------------
# changes
# --------------------------------------------------------------------------


@dataclass
class Hunk:
    """One rendered unified-diff hunk.

    ``lines`` contains display lines prefixed with space, ``+`` or ``-``.
    ``old_start``/``new_start`` are 1-based start positions of the hunk
    region; when the corresponding count is zero the start is the line after
    which the insertion/deletion happens (0 for "before the first line"),
    mirroring the unified diff convention.
    """

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[str] = field(default_factory=list)


@dataclass
class Change:
    change_id: str
    kind: str
    old_path: str | None
    new_path: str | None
    old_sha256: str | None = None
    new_sha256: str | None = None
    rename_basis: str | None = None
    analysis_status: str = "analyzed"  # analyzed | not_analyzed | failed
    old_changed_lines: list[int] = field(default_factory=list)
    new_changed_lines: list[int] = field(default_factory=list)
    hunks: list[Hunk] = field(default_factory=list)
    diff_truncated: bool = False
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def display_path(self) -> str:
        if self.old_path and self.new_path and self.old_path != self.new_path:
            return f"{self.old_path} -> {self.new_path}"
        return self.new_path or self.old_path or ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["display_path"] = self.display_path
        return data


# --------------------------------------------------------------------------
# symbols and calls
# --------------------------------------------------------------------------


@dataclass
class Symbol:
    symbol_id: str
    side: str
    path: str
    module: str
    qualified_name: str  # "" for a module pseudo symbol
    kind: str
    parent_id: str | None
    start_line: int
    end_line: int
    def_line: int
    decorator_start: int | None = None
    is_test: bool = False

    @property
    def is_module(self) -> bool:
        return self.kind == SYMBOL_MODULE

    @property
    def display_name(self) -> str:
        return self.qualified_name or "<module>"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["display_name"] = self.display_name
        return data


@dataclass
class CallEdge:
    edge_id: str
    side: str
    caller_id: str
    callee_id: str | None
    path: str
    line: int
    col: int
    edge_kind: str  # call | import
    resolution: str  # resolved | unresolved
    reason: str | None = None
    target: str | None = None  # rendered callee/import expression
    callee_module: str | None = None


def persistent_edge_target(edge: CallEdge) -> str | None:
    """Keep import and name labels. Computed targets can contain source literals."""
    target = edge.target
    if target and (edge.edge_kind == EDGE_IMPORT or all(
        part.isidentifier() for part in target.split(".")
    )):
        return target
    return None


@dataclass
class SymbolChange:
    symbol_change_id: str
    change_id: str
    kind: str
    reason: str
    old_symbol_id: str | None = None
    new_symbol_id: str | None = None
    structure_changed: bool = True
    old_changed_lines: list[int] = field(default_factory=list)
    new_changed_lines: list[int] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    # P1: extra, JSON-friendly facts about the change (for example
    # ``{"global_names": ["CACHE"]}`` for a module-level assignment).
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def side(self) -> str:
        if self.old_symbol_id and self.new_symbol_id:
            return "both"
        return SIDE_BEFORE if self.old_symbol_id else SIDE_AFTER

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["side"] = self.side
        return data


# --------------------------------------------------------------------------
# impact and test recommendations
# --------------------------------------------------------------------------


@dataclass
class ImpactCandidate:
    candidate_id: str
    symbol_change_id: str
    seed_symbol_id: str
    candidate_symbol_id: str
    side: str
    min_depth: int
    edge_ids: list[str] = field(default_factory=list)
    evidence: str = EVIDENCE_CALL
    truncated: bool = False


@dataclass
class TestRecommendation:
    test_path: str
    qualified_name: str | None
    side: str
    candidate_ids: list[str] = field(default_factory=list)
    min_depth: int = 1
    strength: str = TEST_STRENGTH_STRONG
    evidence: str = ""
    exists_in_after: bool = True
    test_symbol_id: str | None = None


# --------------------------------------------------------------------------
# Judge (P1)
# --------------------------------------------------------------------------


@dataclass
class JudgeEvidenceRef:
    """One piece of source evidence sent to a Judge adapter.

    ``evidence_id`` is referenced by a verdict; validation requires every
    verdict reference to match a sent evidence range exactly (path + side + a
    contained line span), so a model cannot cite data it never received.
    """

    evidence_id: str
    path: str
    side: str
    start_line: int
    end_line: int
    kind: str = "source"  # hunk | symbol | call_site | test
    text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class JudgeAttempt:
    attempt_id: str
    candidate_id: str
    attempt_no: int
    adapter: str  # jev | llm | cache
    model: str | None
    started_at: str
    duration_ms: int
    context_digest: str
    context_bytes: int
    context_tokens_estimate: int
    cache_hit: bool = False
    valid: bool = False
    error_category: str | None = None
    fallback_reason: str | None = None
    request_id: str | None = None
    context_summary: dict[str, Any] = field(default_factory=dict)
    usage: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class JudgeVerdict:
    candidate_id: str
    attempt_no: int
    verdict: str  # affected | unaffected | uncertain
    reason: str
    adapter: str
    model: str | None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)
    uncertainty: str | None = None
    schema_version: int = JUDGE_SCHEMA_VERSION
    validated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------


@dataclass
class AnalysisRun:
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
    status: str = RUN_RUNNING
    summary: str = SUMMARY_UNKNOWN
    finished_at: str | None = None
    config_digest: str = ""
    analyzer_version: str = ANALYZER_VERSION
    snapshot_format_version: int = SNAPSHOT_FORMAT_VERSION
    schema_version: int = SCHEMA_VERSION
    task_id: str | None = None
    metrics: dict[str, Any] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["schema_version"] = SCHEMA_VERSION
        return data


# --------------------------------------------------------------------------
# analysis context container
# --------------------------------------------------------------------------


@dataclass
class AnalysisResult:
    """In-memory bundle produced by ``analyze.run_analysis``."""

    run: AnalysisRun
    snapshot: Snapshot
    changes: list[Change] = field(default_factory=list)
    before_index: Any = None
    after_index: Any = None
    symbol_changes: list[SymbolChange] = field(default_factory=list)
    candidates: list[ImpactCandidate] = field(default_factory=list)
    test_recommendations: list[TestRecommendation] = field(default_factory=list)
    judge_status: str = JUDGE_DISABLED
    judge_attempts: list[JudgeAttempt] = field(default_factory=list)
    judge_verdicts: list[JudgeVerdict] = field(default_factory=list)


# --------------------------------------------------------------------------
# generic (de)serialization helpers used by storage
# --------------------------------------------------------------------------


def dataclass_from_dict(cls: type, data: dict[str, Any]) -> Any:
    """Build a dataclass from a dict, ignoring unknown keys."""

    fields = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    return cls(**{k: v for k, v in data.items() if k in fields})


def dump_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False)


def load_json(text: str | None, default: Any = None) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def stable_sorted_paths(paths: Iterable[str]) -> list[str]:
    return sorted(paths)
