"""Line level change detection and symbol mapping for captured snapshots.

``compute_changes`` turns the two snapshot endpoints into ``Change`` objects:
new/removed/modified files, exact renames, unified hunks with changed line
lists and stable IDs.  ``map_symbol_changes`` maps those line ranges onto the
before/after AST indexes.  ``render_hunks_text`` renders hunks for the
Markdown/Web layers.

The module works purely on already captured snapshots: it never touches the
working tree, Git or the network.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from .config import Config
from .models import (
    CHANGE_ADDED,
    CHANGE_MODIFIED,
    CHANGE_REMOVED,
    CHANGE_RENAMED,
    SYMBOL_CLASS,
    SYMBOL_MODULE,
    SYMCHANGE_ADDED,
    SYMCHANGE_MODIFIED,
    SYMCHANGE_REMOVED,
    SYMCHANGE_RENAMED,
    Change,
    Diagnostic,
    Hunk,
    Snapshot,
    SnapshotEntry,
    SnapshotSide,
    SymbolChange,
    diag,
    source_lines,
)

_NO_NEWLINE_MARKER = "\\ No newline at end of file"
_UNAVAILABLE_STATUSES = ("decode_error", "too_large", "unreadable")
_SIDE_RANK = {"before": 0, "both": 1, "after": 2}
_UNIFIED_CONTEXT = 3


# ---------------------------------------------------------------------------
# entry helpers
# ---------------------------------------------------------------------------


def _entry_present(entry: SnapshotEntry | None) -> bool:
    return entry is not None and entry.status != "missing"


def _entries_equal(old: SnapshotEntry | None, new: SnapshotEntry | None) -> bool:
    """Return True when two present entries hold the same content.

    Raw SHA-256 is authoritative.  When content could not be read (for example
    a symbolic link) only the identity metadata is compared, so a persistent
    unreadable entry does not look modified on every run.  Submodule gitlinks
    keep their object id on both endpoints, so a gitlink change is still
    detected.
    """

    if old is None or new is None:
        return False
    if old.content_sha256 is not None and new.content_sha256 is not None:
        return old.content_sha256 == new.content_sha256
    if old.status != new.status or old.detail != new.detail:
        return False
    if old.detail == "gitlink":
        return old.git_oid == new.git_oid
    return old.size == new.size


# ---------------------------------------------------------------------------
# compute_changes
# ---------------------------------------------------------------------------


@dataclass
class _Draft:
    kind: str
    old_path: str | None
    new_path: str | None
    old_entry: SnapshotEntry | None = None
    new_entry: SnapshotEntry | None = None
    diagnostics: list[Diagnostic] = field(default_factory=list)
    rename_basis: str = "exact"


def _draft_sort_key(draft: _Draft) -> tuple[str, str]:
    return (draft.new_path or draft.old_path or "", draft.old_path or "")


def _merge_exact_renames(drafts: list[_Draft]) -> list[_Draft]:
    """Merge unambiguous same-content added/removed pairs into renames."""

    added_by_sha: dict[str, list[_Draft]] = {}
    removed_by_sha: dict[str, list[_Draft]] = {}
    for draft in drafts:
        sha = None
        if draft.kind == CHANGE_ADDED and draft.new_entry is not None:
            sha = draft.new_entry.content_sha256
        elif draft.kind == CHANGE_REMOVED and draft.old_entry is not None:
            sha = draft.old_entry.content_sha256
        if sha is None:
            continue
        bucket = added_by_sha if draft.kind == CHANGE_ADDED else removed_by_sha
        bucket.setdefault(sha, []).append(draft)

    consumed: set[int] = set()
    merged: list[_Draft] = []
    for sha in sorted(set(added_by_sha) & set(removed_by_sha)):
        added = added_by_sha[sha]
        removed = removed_by_sha[sha]
        if len(added) == 1 and len(removed) == 1:
            rename = _Draft(
                kind=CHANGE_RENAMED,
                old_path=removed[0].old_path,
                new_path=added[0].new_path,
                old_entry=removed[0].old_entry,
                new_entry=added[0].new_entry,
            )
            merged.append(rename)
            consumed.add(id(added[0]))
            consumed.add(id(removed[0]))
            continue
        diagnostic = diag(
            "rename_ambiguous",
            "could not pair added and removed files by exact content",
            severity="info",
            details={
                "sha256": sha,
                "added": sorted(draft.new_path or "" for draft in added),
                "removed": sorted(draft.old_path or "" for draft in removed),
            },
        )
        for draft in added + removed:
            draft.diagnostics.append(diagnostic)

    result = [draft for draft in drafts if id(draft) not in consumed]
    result.extend(merged)
    return result


def _similarity_text(
    side: SnapshotSide, path: str | None, entry: SnapshotEntry | None
) -> str | None:
    """Text usable for similarity pairing: present, Python and decodable."""

    if path is None or entry is None or not entry.is_python:
        return None
    if entry.status != "present":
        return None
    return side.contents.get(path)


def _similarity_candidates(
    drafts: list[_Draft], snapshot: Snapshot
) -> tuple[list[_Draft], list[_Draft]]:
    added: list[_Draft] = []
    removed: list[_Draft] = []
    for draft in drafts:
        if draft.kind == CHANGE_ADDED:
            if _similarity_text(snapshot.after, draft.new_path, draft.new_entry) is not None:
                added.append(draft)
        elif draft.kind == CHANGE_REMOVED:
            if _similarity_text(snapshot.before, draft.old_path, draft.old_entry) is not None:
                removed.append(draft)
    return added, removed


def _similarity_pairs(
    removed: list[_Draft],
    added: list[_Draft],
    snapshot: Snapshot,
    threshold: float,
) -> list[tuple[float, _Draft, _Draft]]:
    """Return all (removed, added) pairs whose line similarity clears ``threshold``."""

    old_sequences = {
        id(draft): source_lines(snapshot.before.contents[draft.old_path or ""])
        for draft in removed
    }
    new_sequences = {
        id(draft): source_lines(snapshot.after.contents[draft.new_path or ""])
        for draft in added
    }
    pairs: list[tuple[float, _Draft, _Draft]] = []
    for old_draft in removed:
        old_lines = old_sequences[id(old_draft)]
        for new_draft in added:
            new_lines = new_sequences[id(new_draft)]
            if old_lines or new_lines:
                # The line count alone bounds the ratio: skip hopeless pairs
                # without running the quadratic matcher over large files.
                upper_bound = 2 * min(len(old_lines), len(new_lines)) / (
                    len(old_lines) + len(new_lines)
                )
                if upper_bound < threshold:
                    continue
            ratio = difflib.SequenceMatcher(
                None, old_lines, new_lines, autojunk=False
            ).ratio()
            if ratio >= threshold:
                pairs.append((ratio, old_draft, new_draft))
    return pairs


def _record_best(
    best: dict[int, tuple[float, list[_Draft]]],
    subject: _Draft,
    candidate: _Draft,
    ratio: float,
) -> None:
    """Track the highest similarity candidate(s) of one file, ties included."""

    entry = best.get(id(subject))
    if entry is None or ratio > entry[0]:
        best[id(subject)] = (ratio, [candidate])
    elif ratio == entry[0]:
        entry[1].append(candidate)


def _report_ambiguous_similarity(
    ambiguous: Sequence[tuple[float, _Draft, _Draft, str]],
) -> None:
    """Write one info diagnostic per ambiguous similarity edge."""

    seen: set[tuple[int, int, str]] = set()
    for ratio, old_draft, new_draft, reason in ambiguous:
        key = (id(old_draft), id(new_draft), reason)
        if key in seen:
            continue
        seen.add(key)
        if reason == "tied_best":
            message = (
                "similarity rename pairing is ambiguous: the best match is tied "
                "between several candidates"
            )
        else:
            message = (
                "similarity rename pair was rejected: the two files are not each "
                "other's unique best match"
            )
        diagnostic = diag(
            "rename_ambiguous_similarity",
            message,
            severity="info",
            details={
                "reason": reason,
                "ratio": round(ratio, 4),
                "old_path": old_draft.old_path,
                "new_path": new_draft.new_path,
            },
        )
        old_draft.diagnostics.append(diagnostic)
        new_draft.diagnostics.append(diagnostic)


def _merge_similarity_renames(
    drafts: list[_Draft], snapshot: Snapshot, config: Config
) -> list[_Draft]:
    """Pair remaining added/removed Python files by bounded content similarity."""

    added, removed = _similarity_candidates(drafts, snapshot)
    if not added or not removed:
        return drafts
    limit = config.analysis.max_rename_candidates
    if len(added) > limit or len(removed) > limit:
        diagnostic = diag(
            "rename_limit",
            "similarity rename pairing was skipped: too many added/removed candidates",
            severity="warning",
            details={
                "limit": limit,
                "added": len(added),
                "removed": len(removed),
            },
        )
        for draft in added + removed:
            draft.diagnostics.append(diagnostic)
        return drafts

    threshold = config.analysis.rename_similarity_threshold
    pairs = _similarity_pairs(removed, added, snapshot, threshold)
    if not pairs:
        return drafts

    # Pairing rule: both sides must be each other's unique best match.  A tie
    # for the best ratio (on either side) or a one-sided best is ambiguous and
    # is never guessed; such files stay added/removed with an info diagnostic.
    best_for_removed: dict[int, tuple[float, list[_Draft]]] = {}
    best_for_added: dict[int, tuple[float, list[_Draft]]] = {}
    for ratio, old_draft, new_draft in pairs:
        _record_best(best_for_removed, old_draft, new_draft, ratio)
        _record_best(best_for_added, new_draft, old_draft, ratio)

    accepted: list[tuple[float, _Draft, _Draft]] = []
    ambiguous: list[tuple[float, _Draft, _Draft, str]] = []
    for old_draft in removed:
        best = best_for_removed.get(id(old_draft))
        if best is None:
            continue
        ratio, targets = best
        if len(targets) > 1:
            for target in sorted(targets, key=lambda draft: draft.new_path or ""):
                ambiguous.append((ratio, old_draft, target, "tied_best"))
            continue
        new_draft = targets[0]
        reverse = best_for_added.get(id(new_draft))
        if reverse is None:  # pragma: no cover - every recorded pair is symmetric
            continue
        reverse_ratio, sources = reverse
        if len(sources) > 1:
            for source in sorted(sources, key=lambda draft: draft.old_path or ""):
                ambiguous.append((reverse_ratio, source, new_draft, "tied_best"))
            continue
        if sources[0] is not old_draft:
            ambiguous.append((ratio, old_draft, new_draft, "not_mutual_best"))
            continue
        accepted.append((ratio, old_draft, new_draft))
    _report_ambiguous_similarity(ambiguous)

    if not accepted:
        return drafts
    consumed: set[int] = set()
    merged: list[_Draft] = []
    for ratio, old_draft, new_draft in accepted:
        consumed.add(id(old_draft))
        consumed.add(id(new_draft))
        merged.append(
            _Draft(
                kind=CHANGE_RENAMED,
                old_path=old_draft.old_path,
                new_path=new_draft.new_path,
                old_entry=old_draft.old_entry,
                new_entry=new_draft.new_entry,
                rename_basis=f"similarity:{ratio:.2f}",
            )
        )
    result = [draft for draft in drafts if id(draft) not in consumed]
    result.extend(merged)
    return result


def compute_changes(snapshot: Snapshot, config: Config) -> list[Change]:
    """Compute the deterministic change list between the two endpoints."""

    before = snapshot.before
    after = snapshot.after
    drafts: list[_Draft] = []
    for path in sorted(set(before.entries) | set(after.entries)):
        old_entry = before.entry(path)
        new_entry = after.entry(path)
        old_present = _entry_present(old_entry)
        new_present = _entry_present(new_entry)
        if not old_present and not new_present:
            continue
        if old_present and not new_present:
            drafts.append(_Draft(CHANGE_REMOVED, path, None, old_entry, None))
        elif new_present and not old_present:
            drafts.append(_Draft(CHANGE_ADDED, None, path, None, new_entry))
        else:
            if _entries_equal(old_entry, new_entry) or path in after.eol_equivalent_paths:
                continue
            drafts.append(
                _Draft(
                    CHANGE_MODIFIED,
                    old_path=path,
                    new_path=path,
                    old_entry=old_entry,
                    new_entry=new_entry,
                )
            )

    drafts = _merge_exact_renames(drafts)
    drafts = _merge_similarity_renames(drafts, snapshot, config)
    drafts.sort(key=_draft_sort_key)

    changes: list[Change] = []
    for sequence, draft in enumerate(drafts, start=1):
        changes.append(_build_change(f"chg-{sequence:04d}", draft, snapshot, config))
    return changes


def _build_change(
    change_id: str,
    draft: _Draft,
    snapshot: Snapshot,
    config: Config,
) -> Change:
    old_entry = draft.old_entry
    new_entry = draft.new_entry
    change = Change(
        change_id=change_id,
        kind=draft.kind,
        old_path=draft.old_path,
        new_path=draft.new_path,
        old_sha256=old_entry.content_sha256 if old_entry is not None else None,
        new_sha256=new_entry.content_sha256 if new_entry is not None else None,
        diagnostics=list(draft.diagnostics),
    )
    is_python = bool(
        (old_entry is not None and old_entry.is_python)
        or (new_entry is not None and new_entry.is_python)
    )
    if draft.kind == CHANGE_RENAMED:
        change.rename_basis = draft.rename_basis
        if draft.rename_basis == "exact":
            # An exact rename carries identical content, so no line diff (and
            # no hunks) is necessary.
            change.analysis_status = "analyzed" if is_python else "not_analyzed"
            return change
        # A similarity rename changed content as well: diff it like a modified
        # Python file so hunks and changed line lists are available.
    if not is_python:
        change.analysis_status = "not_analyzed"
        return change

    old_text, old_problem = _diff_side_text(snapshot.before, draft.old_path, old_entry)
    new_text, new_problem = _diff_side_text(snapshot.after, draft.new_path, new_entry)
    if old_problem is not None or new_problem is not None:
        change.analysis_status = "not_analyzed"
        for side, problem in (("before", old_problem), ("after", new_problem)):
            if problem is None:
                continue
            status, reason, detail = problem
            path = draft.old_path if side == "before" else draft.new_path
            if status in _UNAVAILABLE_STATUSES:
                change.diagnostics.append(
                    diag(
                        status,
                        f"{side} side content is not available for {path}",
                        severity="warning",
                        path=path,
                        details={"side": side, "status": status, "detail": detail},
                    )
                )
            change.diagnostics.append(
                diag(
                    "side_unavailable",
                    f"cannot diff {path}: the {side} side was not analysed",
                    severity="warning",
                    path=path,
                    details={"side": side, "status": status, "reason": reason},
                )
            )
        return change

    assert old_text is not None and new_text is not None
    old_lines = source_lines(old_text)
    new_lines = source_lines(new_text)
    max_lines = config.analysis.max_diff_lines_per_side
    max_product = config.analysis.max_diff_line_product
    if len(old_lines) > max_lines or len(new_lines) > max_lines:
        change.analysis_status = "not_analyzed"
        change.diff_truncated = True
        change.diagnostics.append(
            diag(
                "diff_limit",
                "line diff was skipped because one side exceeds the line limit",
                severity="warning",
                path=draft.new_path or draft.old_path,
                details={
                    "limit": "max_diff_lines_per_side",
                    "max": max_lines,
                    "old_lines": len(old_lines),
                    "new_lines": len(new_lines),
                },
            )
        )
        return change
    if len(old_lines) * len(new_lines) > max_product:
        change.analysis_status = "not_analyzed"
        change.diff_truncated = True
        change.diagnostics.append(
            diag(
                "diff_limit",
                "line diff was skipped because the line product exceeds the limit",
                severity="warning",
                path=draft.new_path or draft.old_path,
                details={
                    "limit": "max_diff_line_product",
                    "max": max_product,
                    "product": len(old_lines) * len(new_lines),
                },
            )
        )
        return change

    hunks, old_changed, new_changed = _diff_lines(
        old_lines, new_lines, old_text.endswith("\n"), new_text.endswith("\n")
    )
    change.analysis_status = "analyzed"
    change.hunks = hunks
    change.old_changed_lines = old_changed
    change.new_changed_lines = new_changed
    return change


def _diff_side_text(
    side: SnapshotSide,
    path: str | None,
    entry: SnapshotEntry | None,
) -> tuple[str | None, tuple[str, str, str | None] | None]:
    """Return ``(text, problem)``; a missing side is legitimately empty text."""

    if path is None or entry is None or entry.status == "missing":
        return "", None
    if entry.status in _UNAVAILABLE_STATUSES:
        return None, (entry.status, "unavailable", entry.detail)
    text = side.contents.get(path)
    if text is None:
        return None, ("present", "content_not_collected", None)
    return text, None


# ---------------------------------------------------------------------------
# line diff
# ---------------------------------------------------------------------------


def _diff_lines(
    old_lines: list[str],
    new_lines: list[str],
    old_ends_with_newline: bool,
    new_ends_with_newline: bool,
) -> tuple[list[Hunk], list[int], list[int]]:
    """Build unified hunks and changed line numbers from two text files."""

    old_no_newline = bool(old_lines) and not old_ends_with_newline
    new_no_newline = bool(new_lines) and not new_ends_with_newline
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False)
    opcodes = matcher.get_opcodes()
    differing = [opcode for opcode in opcodes if opcode[0] != "equal"]

    old_changed: set[int] = set()
    new_changed: set[int] = set()
    for tag, i1, i2, j1, j2 in differing:
        if tag in ("replace", "delete"):
            old_changed.update(range(i1 + 1, i2 + 1))
        if tag in ("replace", "insert"):
            new_changed.update(range(j1 + 1, j2 + 1))

    if not differing:
        if old_no_newline == new_no_newline or not old_lines:
            return [], [], []
        # Identical line sequences, different trailing-newline state: express it
        # as a one-line replacement so the marker line has a home.
        last = len(old_lines)
        lines: list[str] = ["-" + old_lines[-1]]
        if old_no_newline:
            lines.append(_NO_NEWLINE_MARKER)
        lines.append("+" + new_lines[-1])
        if new_no_newline:
            lines.append(_NO_NEWLINE_MARKER)
        hunk = Hunk(
            old_start=last,
            old_count=1,
            new_start=len(new_lines),
            new_count=1,
            lines=lines,
        )
        return [hunk], [last], [len(new_lines)]

    hunks: list[Hunk] = []
    for group in matcher.get_grouped_opcodes(_UNIFIED_CONTEXT):
        first, last = group[0], group[-1]
        old_begin, old_end = first[1], last[2]
        new_begin, new_end = first[3], last[4]
        old_count = old_end - old_begin
        new_count = new_end - new_begin
        old_start = old_begin + 1 if old_count else old_begin
        new_start = new_begin + 1 if new_count else new_begin
        lines: list[str] = []
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                for offset in range(i2 - i1):
                    old_index = i1 + offset
                    new_index = j1 + offset
                    lines.append(" " + old_lines[old_index])
                    old_is_last = old_no_newline and old_index == len(old_lines) - 1
                    new_is_last = new_no_newline and new_index == len(new_lines) - 1
                    if old_is_last or new_is_last:
                        lines.append(_NO_NEWLINE_MARKER)
            elif tag == "delete":
                for index in range(i1, i2):
                    lines.append("-" + old_lines[index])
                    if old_no_newline and index == len(old_lines) - 1:
                        lines.append(_NO_NEWLINE_MARKER)
            elif tag == "insert":
                for index in range(j1, j2):
                    lines.append("+" + new_lines[index])
                    if new_no_newline and index == len(new_lines) - 1:
                        lines.append(_NO_NEWLINE_MARKER)
            else:  # replace
                for index in range(i1, i2):
                    lines.append("-" + old_lines[index])
                    if old_no_newline and index == len(old_lines) - 1:
                        lines.append(_NO_NEWLINE_MARKER)
                for index in range(j1, j2):
                    lines.append("+" + new_lines[index])
                    if new_no_newline and index == len(new_lines) - 1:
                        lines.append(_NO_NEWLINE_MARKER)
        hunks.append(
            Hunk(
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                lines=lines,
            )
        )
    return hunks, sorted(old_changed), sorted(new_changed)


# ---------------------------------------------------------------------------
# hunk rendering
# ---------------------------------------------------------------------------


def _format_range(start: int, count: int) -> str:
    if count == 1:
        return str(start)
    return f"{start},{count}"


def render_hunks_text(change: Change) -> str:
    """Render ``change.hunks`` as unified diff text (``""`` when empty)."""

    if not change.hunks:
        return ""
    lines: list[str] = []
    for hunk in change.hunks:
        lines.append(
            f"@@ -{_format_range(hunk.old_start, hunk.old_count)} "
            f"+{_format_range(hunk.new_start, hunk.new_count)} @@"
        )
        lines.extend(hunk.lines)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# map_symbol_changes
# ---------------------------------------------------------------------------


def _parse_error(index: Any, path: str | None) -> bool:
    if not path:
        return False
    errors = getattr(index, "parse_errors", None) or {}
    return path in errors


def _indexed(index: Any, path: str | None) -> bool:
    if not path:
        return False
    try:
        symbols = index.symbols_for_path(path)
    except (AttributeError, TypeError):  # pragma: no cover - defensive
        symbols = None
    if symbols:
        return True
    modules = getattr(index, "path_modules", None) or {}
    return path in modules


def _module_symbol(index: Any, path: str | None):
    if not path:
        return None
    getter = getattr(index, "module_symbol", None)
    if callable(getter):
        symbol = getter(path)
        if symbol is not None:
            return symbol
    for symbol in index.symbols_for_path(path):
        if symbol.kind == SYMBOL_MODULE:
            return symbol
    return None


def _notify_unknown(
    change: Change,
    path: str | None,
    side: str,
    reason: str,
) -> None:
    change.diagnostics.append(
        diag(
            "symbol_mapping_unknown",
            f"cannot map symbols for {path or change.display_path} ({reason} on the {side} side)",
            severity="warning",
            path=path,
            details={
                "change_id": change.change_id,
                "path": path,
                "side": side,
                "reason": reason,
            },
        )
    )


def _content_differs(change: Change) -> bool:
    """True when a renamed file also changed its line content.

    Raw byte digests may differ without any line level change (for example a
    pure CRLF/flavor rewrite); such a rename is semantically pure and keeps the
    single ``module_renamed`` symbol change.
    """

    return bool(change.hunks or change.old_changed_lines or change.new_changed_lines)


def _map_change(
    change: Change,
    before_index: Any,
    after_index: Any,
    result: list[SymbolChange],
) -> None:
    checks: list[tuple[str, Any, str | None]] = []
    if change.old_path:
        checks.append(("before", before_index, change.old_path))
    if change.new_path:
        checks.append(("after", after_index, change.new_path))
    for side, index, path in checks:
        if _parse_error(index, path):
            _notify_unknown(change, path, side, "parse_error")
            return
        if not _indexed(index, path):
            _notify_unknown(change, path, side, "not_indexed")
            return

    if change.kind == CHANGE_RENAMED:
        if _content_differs(change):
            # A rename that also changed content pairs symbols across the old
            # and the new path with exactly the same rules as a modified file.
            entries = _map_modified(change, before_index, after_index)
        else:
            entries = _map_renamed(change, before_index, after_index)
            if not entries:
                _notify_unknown(
                    change,
                    change.new_path,
                    "after",
                    "module_symbol_missing",
                )
                return
    elif change.kind == CHANGE_ADDED:
        entries = _map_file_symbols(
            change, after_index, change.new_path, "after", SYMCHANGE_ADDED, "file_added"
        )
    elif change.kind == CHANGE_REMOVED:
        entries = _map_file_symbols(
            change, before_index, change.old_path, "before", SYMCHANGE_REMOVED, "file_removed"
        )
    elif change.kind == CHANGE_MODIFIED:
        entries = _map_modified(change, before_index, after_index)
    else:  # pragma: no cover - defensive
        entries = []
    entries.sort(key=lambda item: (item[0], _SIDE_RANK[item[1]], item[2].old_symbol_id or ""))
    for sequence, (_start, _side, symbol_change) in enumerate(entries, start=1):
        symbol_change.symbol_change_id = f"sc:{change.change_id}:{sequence:03d}"
        result.append(symbol_change)


def _map_renamed(
    change: Change,
    before_index: Any,
    after_index: Any,
) -> list[tuple[int, str, SymbolChange]]:
    old_module = _module_symbol(before_index, change.old_path)
    new_module = _module_symbol(after_index, change.new_path)
    if old_module is None or new_module is None:
        return []
    symbol_change = SymbolChange(
        symbol_change_id="",
        change_id=change.change_id,
        kind=SYMCHANGE_RENAMED,
        reason="module_renamed",
        old_symbol_id=old_module.symbol_id,
        new_symbol_id=new_module.symbol_id,
        structure_changed=(
            before_index.structure_digest(old_module.symbol_id)
            != after_index.structure_digest(new_module.symbol_id)
        ),
    )
    return [(old_module.start_line, "both", symbol_change)]


def _map_file_symbols(
    change: Change,
    index: Any,
    path: str | None,
    side: str,
    kind: str,
    reason: str,
) -> list[tuple[int, str, SymbolChange]]:
    if not path:
        return []
    entries: list[tuple[int, str, SymbolChange]] = []
    for symbol in index.symbols_for_path(path):
        if side == "after":
            symbol_change = SymbolChange(
                symbol_change_id="",
                change_id=change.change_id,
                kind=kind,
                reason=reason,
                new_symbol_id=symbol.symbol_id,
            )
        else:
            symbol_change = SymbolChange(
                symbol_change_id="",
                change_id=change.change_id,
                kind=kind,
                reason=reason,
                old_symbol_id=symbol.symbol_id,
            )
        entries.append((symbol.start_line, side, symbol_change))
    return entries


def _hit_lines(index: Any, path: str, lines: Iterable[int]) -> dict[str, list[int]]:
    hits: dict[str, list[int]] = {}
    for line in sorted(set(lines)):
        symbol = index.symbol_at(path, line)
        if symbol is None:
            continue
        hits.setdefault(symbol.symbol_id, []).append(line)
    return {symbol_id: sorted(values) for symbol_id, values in hits.items()}


def _symbol_key(symbol: Any) -> tuple[str, str]:
    return (symbol.qualified_name, symbol.kind)


def _reason_for(symbol: Any, lines: Sequence[int]) -> str:
    if symbol.kind == SYMBOL_MODULE:
        return "module_statement"
    header_start = symbol.decorator_start or symbol.def_line
    in_header = any(header_start <= line <= symbol.def_line for line in lines)
    if symbol.kind == SYMBOL_CLASS:
        return "class_header" if in_header else "class_body"
    return "signature" if in_header else "body"


def _global_names(index: Any, path: str | None, lines: Sequence[int]) -> list[str]:
    """Module-level variable names whose assignment range touches ``lines``.

    The P1 AST index exposes :meth:`Index.global_names_at`; the lookup is
    optional so a P0 index (or a test fake) simply yields no extra facts.
    """

    getter = getattr(index, "global_names_at", None)
    if not callable(getter) or not path or not lines:
        return []
    try:
        names = getter(path, sorted(set(lines)))
    except (AttributeError, TypeError, ValueError):  # pragma: no cover - defensive
        return []
    if not names:
        return []
    return sorted({str(name) for name in names})


def _map_modified(
    change: Change,
    before_index: Any,
    after_index: Any,
) -> list[tuple[int, str, SymbolChange]]:
    old_path = change.old_path or ""
    new_path = change.new_path or ""
    old_hits = _hit_lines(before_index, old_path, change.old_changed_lines)
    new_hits = _hit_lines(after_index, new_path, change.new_changed_lines)
    old_by_key: dict[tuple[str, str], Any] = {}
    for symbol in before_index.symbols_for_path(old_path):
        old_by_key.setdefault(_symbol_key(symbol), symbol)
    new_by_key: dict[tuple[str, str], Any] = {}
    for symbol in after_index.symbols_for_path(new_path):
        new_by_key.setdefault(_symbol_key(symbol), symbol)

    def order_key(key: tuple[str, str]) -> tuple[int, str, str]:
        symbol = old_by_key.get(key) or new_by_key[key]
        return (symbol.start_line, key[0], key[1])

    entries: list[tuple[int, str, SymbolChange]] = []
    for key in sorted(set(old_by_key) | set(new_by_key), key=order_key):
        old_symbol = old_by_key.get(key)
        new_symbol = new_by_key.get(key)
        if old_symbol is not None and new_symbol is not None:
            old_lines = old_hits.get(old_symbol.symbol_id, [])
            new_lines = new_hits.get(new_symbol.symbol_id, [])
            if not old_lines and not new_lines:
                continue
            if old_lines:
                reason = _reason_for(old_symbol, old_lines)
            else:
                reason = _reason_for(new_symbol, new_lines)
            details: dict[str, Any] = {}
            if old_symbol.kind == SYMBOL_MODULE or new_symbol.kind == SYMBOL_MODULE:
                global_names = sorted(
                    set(_global_names(before_index, old_path, old_lines))
                    | set(_global_names(after_index, new_path, new_lines))
                )
                if global_names:
                    details["global_names"] = global_names
            symbol_change = SymbolChange(
                symbol_change_id="",
                change_id=change.change_id,
                kind=SYMCHANGE_MODIFIED,
                reason=reason,
                old_symbol_id=old_symbol.symbol_id,
                new_symbol_id=new_symbol.symbol_id,
                structure_changed=(
                    before_index.structure_digest(old_symbol.symbol_id)
                    != after_index.structure_digest(new_symbol.symbol_id)
                ),
                old_changed_lines=old_lines,
                new_changed_lines=new_lines,
                details=details,
            )
            entries.append((old_symbol.start_line, "both", symbol_change))
        elif old_symbol is not None:
            old_lines = old_hits.get(old_symbol.symbol_id, [])
            if not old_lines:
                continue
            entries.append(
                (
                    old_symbol.start_line,
                    "before",
                    SymbolChange(
                        symbol_change_id="",
                        change_id=change.change_id,
                        kind=SYMCHANGE_REMOVED,
                        reason="symbol_removed",
                        old_symbol_id=old_symbol.symbol_id,
                        old_changed_lines=old_lines,
                    ),
                )
            )
        else:
            assert new_symbol is not None
            new_lines = new_hits.get(new_symbol.symbol_id, [])
            if not new_lines:
                continue
            entries.append(
                (
                    new_symbol.start_line,
                    "after",
                    SymbolChange(
                        symbol_change_id="",
                        change_id=change.change_id,
                        kind=SYMCHANGE_ADDED,
                        reason="symbol_added",
                        new_symbol_id=new_symbol.symbol_id,
                        new_changed_lines=new_lines,
                    ),
                )
            )
    return entries


def map_symbol_changes(
    changes: list[Change],
    before_index: Any,
    after_index: Any,
) -> list[SymbolChange]:
    """Map analysed Python changes onto symbol level changes.

    Both indexes are expected to implement the ``ast_index.Index`` contract.
    A side that failed to parse or was not indexed never yields deletions:
    the change is skipped with a ``symbol_mapping_unknown`` diagnostic.
    """

    result: list[SymbolChange] = []
    for change in changes:
        if change.analysis_status != "analyzed":
            continue
        _map_change(change, before_index, after_index, result)
    return result
