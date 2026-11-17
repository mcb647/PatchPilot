"""Build minimal, budgeted Judge contexts from impact candidates and snapshots.

One context is produced per ``(SymbolChange, ImpactCandidate)`` pair, in the
candidate order supplied by the caller.  A context contains only:

* the changed symbol's diff hunks (the side being judged),
* the changed symbol's signature / definition line,
* the source line of each call site on the candidate path,
* the caller's signature,
* a short path summary.

Evidence is numbered ``ev-001`` in send order and the digest is a SHA-256 of
the rendered text plus those ids, so a cached verdict is bound to exactly the
text that was sent.  Evidence that matches a secret pattern or lives in a
sensitive path is never sent; if the changed symbol's own evidence cannot be
sent (secret redaction, missing source, or token budget) the context is marked
``context_insufficient`` and the runner must not call an adapter.
"""

from __future__ import annotations

import itertools
import json
import re
from dataclasses import dataclass
from typing import Any

from .. import models
from .contract import JudgeContext

# Per-block limits keep the "minimal evidence" promise even when a hunk is long.
_MAX_HUNK_LINES = 12
_MAX_HUNKS = 4
_MAX_CALL_SITE_CHARS = 400
_MAX_DEFINITION_LINES = 6

_SECRET_LINE_RE = re.compile(
    r"(?:api[_-]?key|secret|password|passwd|token|access[_-]?key|private[_-]?key|"
    r"client[_-]?secret)"
    r"\s*[:=]\s*['\"]?[^\s'\"]{6,}",
    re.IGNORECASE,
)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN[^\n]*PRIVATE KEY-----")
_LONG_TOKEN_RE = re.compile(
    r"(?<![\w-])(?:"
    r"sk-[A-Za-z0-9_-]{16,}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|gho_[A-Za-z0-9]{20,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|[A-Fa-f0-9]{40,}"
    r"|[A-Za-z0-9+/=_-]{48,}"
    r")(?![\w-])"
)
_SENSITIVE_PATH_RE = re.compile(
    r"(?:^|/)(?:"
    r"\.env(?:\.[^/]*)?"
    r"|[^/]*\.pem"
    r"|id_(?:rsa|dsa|ecdsa|ed25519)[^/]*"
    r"|credentials[^/]*"
    r"|secrets[^/]*"
    r")$",
    re.IGNORECASE,
)


def estimate_tokens(text: str) -> int:
    """Conservative estimate: UTF-8 bytes / 3, rounded up."""

    return (len(text.encode("utf-8", "replace")) + 2) // 3


def is_sensitive_path(path: str | None) -> bool:
    return bool(path) and bool(_SENSITIVE_PATH_RE.search(path or ""))


def contains_secret(text: str | None) -> bool:
    if not text:
        return False
    return bool(
        _SECRET_LINE_RE.search(text)
        or _PRIVATE_KEY_RE.search(text)
        or _LONG_TOKEN_RE.search(text)
    )


def _dedupe(items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for item in items:
        seen.setdefault(item, None)
    return list(seen)


@dataclass
class _Planned:
    """One candidate piece of evidence plus the range it would send."""

    priority: int
    order: int
    kind: str
    path: str
    side: str
    start_line: int
    end_line: int
    snippet: str


def _display(symbol: models.Symbol | None, fallback: str = "?") -> str:
    if symbol is None:
        return fallback
    if symbol.is_module:
        return symbol.module or symbol.path
    return symbol.display_name


def _symbol_anchor(symbol: models.Symbol) -> str:
    return f"{_display(symbol)} [{symbol.kind}] {symbol.path}:{symbol.def_line}"


def _definition_snippet(
    symbol: models.Symbol, contents: dict[str, str]
) -> tuple[int, int, str] | None:
    if symbol.is_module:
        return None
    lines = models.source_lines(contents.get(symbol.path, ""))
    if not lines:
        return None
    start = symbol.decorator_start or symbol.def_line or symbol.start_line
    end = symbol.def_line or start
    start = max(1, start)
    end = max(start, min(end, len(lines)))
    if start > len(lines):
        return None
    snippet_lines = lines[start - 1 : end]
    if len(snippet_lines) > _MAX_DEFINITION_LINES:
        snippet_lines = snippet_lines[:_MAX_DEFINITION_LINES]
        end = start + len(snippet_lines) - 1
    return start, end, "\n".join(snippet_lines)


def _line_snippet(
    path: str, line: int, contents: dict[str, str]
) -> tuple[int, int, str] | None:
    lines = models.source_lines(contents.get(path, ""))
    if not (1 <= line <= len(lines)):
        return None
    text = lines[line - 1]
    if len(text) > _MAX_CALL_SITE_CHARS:
        text = text[:_MAX_CALL_SITE_CHARS] + "..."
    return line, line, text


def _hunk_line_numbers(hunk: models.Hunk, side: str) -> tuple[int, int]:
    if side == models.SIDE_BEFORE:
        return hunk.old_start, hunk.old_count
    return hunk.new_start, hunk.new_count


def _display_hunk_lines(hunk: models.Hunk, side: str) -> list[str]:
    keep = (" ", "-") if side == models.SIDE_BEFORE else (" ", "+")
    return [line for line in hunk.lines if line[:1] in keep]


def _plan_hunks(
    change: models.Change,
    symbol_change: models.SymbolChange,
    side: str,
    seed: models.Symbol | None,
) -> tuple[list[_Planned], list[str]]:
    """Return the changed hunks for one side and omission reasons."""

    omitted: list[str] = []
    planned: list[_Planned] = []
    if not change.hunks:
        return planned, ["hunk_unavailable"]
    path = change.old_path if side == models.SIDE_BEFORE else change.new_path
    if not path:
        return planned, ["hunk_unavailable"]

    changed = set(
        symbol_change.old_changed_lines
        if side == models.SIDE_BEFORE
        else symbol_change.new_changed_lines
    )
    span: set[int] = set()
    if seed is not None:
        span = set(range(seed.start_line, seed.end_line + 1))

    def intersects(hunk: models.Hunk) -> bool:
        start, count = _hunk_line_numbers(hunk, side)
        if count <= 0:
            return False
        numbers = set(range(start, start + count))
        if changed:
            return bool(numbers & changed)
        return bool(numbers & span)

    matching = [hunk for hunk in change.hunks if intersects(hunk)]
    if not matching and not changed:
        matching = list(change.hunks[:_MAX_HUNKS])
    if len(matching) > _MAX_HUNKS:
        omitted.append("hunk_truncated")
        matching = matching[:_MAX_HUNKS]
    for order, hunk in enumerate(matching):
        start, count = _hunk_line_numbers(hunk, side)
        body = _display_hunk_lines(hunk, side)
        if count <= 0 or not body:
            continue
        if len(body) > _MAX_HUNK_LINES:
            body = body[:_MAX_HUNK_LINES]
            if "hunk_truncated" not in omitted:
                omitted.append("hunk_truncated")
        planned.append(
            _Planned(
                priority=0,
                order=order,
                kind="hunk",
                path=path,
                side=side,
                start_line=max(1, start),
                end_line=max(1, start + count - 1),
                snippet="\n".join(body),
            )
        )
    if not planned and "hunk_unavailable" not in omitted:
        omitted.append("hunk_unavailable")
    return planned, omitted


def _render_block(planned: _Planned, evidence_id: str) -> str:
    location = f"{planned.path}:{planned.start_line}"
    if planned.end_line != planned.start_line:
        location = f"{planned.path}:{planned.start_line}-{planned.end_line}"
    return f"[{evidence_id}] {planned.kind} {planned.side} {location}\n{planned.snippet}"


def _chain_names(
    candidate: models.ImpactCandidate,
    symbols: dict[str, models.Symbol],
    edges: dict[str, models.CallEdge],
    seed: models.Symbol | None,
) -> list[str]:
    names: list[str] = []
    for edge_id in reversed(candidate.edge_ids):
        edge = edges.get(edge_id)
        caller = symbols.get(edge.caller_id) if edge is not None else None
        names.append(_display(caller, (edge.target or "?") if edge is not None else "?"))
    names.append(_display(seed))
    return names


def _render_header(
    symbol_change: models.SymbolChange,
    candidate: models.ImpactCandidate,
    change: models.Change | None,
    seed: models.Symbol | None,
    caller: models.Symbol | None,
    names: list[str],
) -> str:
    lines = [
        "JUDGE CONTEXT v1",
        f"schema_version: {models.JUDGE_SCHEMA_VERSION}",
        f"prompt_version: {models.JUDGE_PROMPT_VERSION}",
        "task: decide whether the changed symbol can affect the caller; "
        "answer affected | unaffected | uncertain and cite only sent evidence ids.",
        f"candidate_id: {candidate.candidate_id}",
        f"symbol_change_id: {symbol_change.symbol_change_id}",
    ]
    if change is not None:
        lines.append(
            "change: "
            f"kind={change.kind} reason={symbol_change.reason} "
            f"structure_changed={str(symbol_change.structure_changed).lower()} "
            f"side={candidate.side}"
        )
    else:
        lines.append(f"change: side={candidate.side} (no diff record)")
    lines.append(f"seed: {_symbol_anchor(seed)}" if seed is not None else "seed: <unknown>")
    if caller is not None:
        lines.append(f"caller: {_symbol_anchor(caller)}")
    lines.append(
        f"path: {' -> '.join(names)} "
        f"(evidence={candidate.evidence}, depth={candidate.min_depth}, "
        f"edges={len(candidate.edge_ids)})"
    )
    if symbol_change.details:
        lines.append(
            "facts: " + json.dumps(symbol_change.details, ensure_ascii=False, sort_keys=True)
        )
    return "\n".join(lines)


def _insufficient(
    candidate: models.ImpactCandidate,
    symbol_change: models.SymbolChange,
    omitted: list[str],
) -> JudgeContext:
    reasons = _dedupe(list(omitted) + ["context_insufficient"])
    return JudgeContext(
        candidate_id=candidate.candidate_id,
        symbol_change_id=symbol_change.symbol_change_id,
        seed_symbol_id=candidate.seed_symbol_id,
        candidate_symbol_id=candidate.candidate_symbol_id,
        side=candidate.side,
        evidence=[],
        omitted=reasons,
        text="",
        digest=models.sha256_text("|"),
        estimated_tokens=0,
    )


def _build_one(
    symbol_change: models.SymbolChange,
    candidate: models.ImpactCandidate,
    change: models.Change | None,
    index: Any,
    side_snapshot: Any,
    max_tokens: int,
) -> JudgeContext:
    side = candidate.side
    symbols: dict[str, models.Symbol] = getattr(index, "symbols", None) or {}
    edges = {edge.edge_id: edge for edge in (getattr(index, "edges", None) or ())}
    contents: dict[str, str] = getattr(side_snapshot, "contents", None) or {}

    seed = symbols.get(candidate.seed_symbol_id)
    caller = symbols.get(candidate.candidate_symbol_id)
    omitted: list[str] = []
    planned: list[_Planned] = []
    order = itertools.count()

    if change is None:
        omitted.append("change_missing")
    else:
        hunk_plans, hunk_omitted = _plan_hunks(change, symbol_change, side, seed)
        planned.extend(hunk_plans)
        omitted.extend(hunk_omitted)

    if seed is None:
        omitted.append("seed_symbol_unavailable")
    elif not seed.is_module:
        definition = _definition_snippet(seed, contents)
        if definition is None:
            omitted.append("definition_unavailable")
        else:
            start, end, snippet = definition
            planned.append(
                _Planned(1, next(order), "symbol", seed.path, side, start, end, snippet)
            )

    for edge_id in candidate.edge_ids:
        edge = edges.get(edge_id)
        if edge is None:
            omitted.append("edge_missing")
            continue
        if edge.side != side:
            omitted.append("edge_side_mismatch")
            continue
        snippet = _line_snippet(edge.path, edge.line, contents)
        if snippet is None:
            omitted.append("call_site_unavailable")
            continue
        start, end, text = snippet
        planned.append(
            _Planned(2, next(order), "call_site", edge.path, side, start, end, text)
        )

    if caller is not None and not caller.is_module:
        definition = _definition_snippet(caller, contents)
        if definition is None:
            omitted.append("caller_definition_unavailable")
        else:
            start, end, snippet = definition
            planned.append(
                _Planned(
                    10,
                    next(order),
                    "test" if caller.is_test else "symbol",
                    caller.path,
                    side,
                    start,
                    end,
                    snippet,
                )
            )

    header = _render_header(
        symbol_change,
        candidate,
        change,
        seed,
        caller,
        _chain_names(candidate, symbols, edges, seed),
    )
    header_tokens = estimate_tokens(header)
    if header_tokens >= max_tokens:
        return _insufficient(candidate, symbol_change, omitted + ["token_budget"])

    planned.sort(key=lambda item: (item.priority, item.order))
    selected: list[_Planned] = []
    used_tokens = header_tokens
    for item in planned:
        if is_sensitive_path(item.path):
            omitted.append("sensitive_path")
            continue
        if contains_secret(item.path) or contains_secret(item.snippet):
            omitted.append("secret_redacted")
            continue
        placeholder = "[ev-###]"
        block = _render_block(item, placeholder)
        block_tokens = estimate_tokens(block) + 1  # blank line separator
        if used_tokens + block_tokens > max_tokens:
            omitted.append("token_budget")
            continue
        selected.append(item)
        used_tokens += block_tokens

    # Core evidence is the changed symbol's own hunk or definition.  Without it
    # the model would have to guess, so the adapter is not called at all.
    core_ok = any(item.priority <= 1 for item in selected)
    if not core_ok:
        return _insufficient(candidate, symbol_change, omitted)

    evidence: list[models.JudgeEvidenceRef] = []
    blocks: list[str] = []
    for sequence, item in enumerate(selected, start=1):
        evidence_id = f"ev-{sequence:03d}"
        evidence.append(
            models.JudgeEvidenceRef(
                evidence_id=evidence_id,
                path=item.path,
                side=item.side,
                start_line=item.start_line,
                end_line=item.end_line,
                kind=item.kind,
                text=item.snippet,
            )
        )
        blocks.append(_render_block(item, evidence_id))

    omitted = _dedupe(omitted)
    text_parts = [header]
    if blocks:
        text_parts.append("\n\n".join(blocks))
    if omitted:
        text_parts.append("omitted: " + ", ".join(omitted))
    text = "\n\n".join(text_parts)

    ids = [ref.evidence_id for ref in evidence]
    return JudgeContext(
        candidate_id=candidate.candidate_id,
        symbol_change_id=symbol_change.symbol_change_id,
        seed_symbol_id=candidate.seed_symbol_id,
        candidate_symbol_id=candidate.candidate_symbol_id,
        side=side,
        evidence=evidence,
        omitted=omitted,
        text=text,
        digest=models.sha256_text(text + "|" + ",".join(ids)),
        estimated_tokens=estimate_tokens(text),
    )


def build_contexts(
    symbol_changes: list[models.SymbolChange],
    candidates: list[models.ImpactCandidate],
    changes: list[models.Change],
    before_index: Any,
    after_index: Any,
    snapshot: Any,
    config: Any,
) -> list[JudgeContext]:
    """Build one minimal evidence context per (symbol change, candidate) pair."""

    symbol_changes_by_id: dict[str, models.SymbolChange] = {}
    for symbol_change in symbol_changes or ():
        symbol_changes_by_id.setdefault(symbol_change.symbol_change_id, symbol_change)
    changes_by_id: dict[str, models.Change] = {}
    for change in changes or ():
        changes_by_id.setdefault(change.change_id, change)

    before_side = getattr(snapshot, "before", None) if snapshot is not None else None
    after_side = getattr(snapshot, "after", None) if snapshot is not None else None
    max_tokens = int(config.judge.max_input_tokens_per_attempt)

    contexts: list[JudgeContext] = []
    for candidate in candidates or ():
        symbol_change = symbol_changes_by_id.get(candidate.symbol_change_id)
        if symbol_change is None:
            continue
        index = before_index if candidate.side == models.SIDE_BEFORE else after_index
        side_snapshot = before_side if candidate.side == models.SIDE_BEFORE else after_side
        if index is None:
            contexts.append(_insufficient(candidate, symbol_change, ["side_unavailable"]))
            continue
        change = changes_by_id.get(symbol_change.change_id)
        contexts.append(
            _build_one(symbol_change, candidate, change, index, side_snapshot, max_tokens)
        )
    return contexts
