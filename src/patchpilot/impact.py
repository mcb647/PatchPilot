"""Reverse impact tracing: find the callers affected by a changed symbol.

The tracer walks caller edges backwards from every changed symbol, one snapshot
side at a time.  Only statically resolved edges are followed; unresolved calls
and dynamic dispatch are deliberately ignored, so the result never invents a
caller.  Module pseudo symbols are special: they only surface the modules that
import them (``imports_module`` evidence), because importing a module does not
by itself call any function in it.

Determinism matters because runs are persisted and compared across history:
adjacency lists are sorted, shortest paths are kept, and the final candidate
list is sorted by contract key before ``candidate_id`` values are assigned.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any

from .config import Config
from .models import (
    EDGE_CALL,
    EDGE_GLOBAL_READ,
    EDGE_IMPORT,
    EVIDENCE_CALL,
    EVIDENCE_GLOBAL_READ,
    EVIDENCE_IMPORT,
    SIDE_AFTER,
    SIDE_BEFORE,
    SIDES,
    CallEdge,
    ImpactCandidate,
    SymbolChange,
)

# Search budget bounds from the contract: enough work for wide real repositories
# without letting a pathological graph stall the analysis.
_MAX_SEARCH_BUDGET = 20000
_MIN_SEARCH_BUDGET = 2000
_BUDGET_PER_CANDIDATE = 50

# Canonical side order (before, after) so the returned list starts with the
# removed call chains and continues with the added ones.
_SIDE_ORDER = {side: index for index, side in enumerate(SIDES)}


def _side_rank(side: str) -> int:
    return _SIDE_ORDER.get(side, len(SIDES))


@dataclass
class _PathHit:
    """One candidate reached on one snapshot side."""

    depth: int
    edge_ids: list[str]
    evidence: str


def search_budget(config: Config) -> int:
    """Return the per-change, per-side edge/node expansion budget."""

    per_change = config.analysis.max_candidates_per_change
    return min(_MAX_SEARCH_BUDGET, max(_MIN_SEARCH_BUDGET, per_change * _BUDGET_PER_CANDIDATE))


def _edge_order(edge: CallEdge) -> tuple[Any, ...]:
    return (edge.path, edge.line, edge.col, edge.caller_id, edge.edge_id or "")


def _reverse_edges(index: Any, edge_kind: str) -> dict[str, list[CallEdge]]:
    """Group resolved edges of ``edge_kind`` by ``callee_id``, deterministically."""

    index_side = getattr(index, "side", None)
    buckets: dict[str, list[CallEdge]] = {}
    for edge in getattr(index, "edges", None) or ():
        if edge.edge_kind != edge_kind or edge.resolution != "resolved":
            continue
        if index_side and edge.side and edge.side != index_side:
            continue
        callee_id = edge.callee_id
        if not callee_id:
            continue
        buckets.setdefault(callee_id, []).append(edge)
    for edges in buckets.values():
        edges.sort(key=_edge_order)
    return buckets


def _buckets_for(
    index: Any, edge_kind: str, cache: dict[tuple[int, str], dict[str, list[CallEdge]]]
) -> dict[str, list[CallEdge]]:
    # Index objects are per side and shared by every SymbolChange; reuse the
    # reverse adjacency across the whole trace instead of rebuilding it.
    key = (id(index), edge_kind)
    buckets = cache.get(key)
    if buckets is None:
        buckets = _reverse_edges(index, edge_kind)
        cache[key] = buckets
    return buckets


def _trace_side(
    index: Any,
    seed_id: str,
    *,
    max_depth: int,
    max_candidates: int,
    budget: int,
    cache: dict[tuple[int, str], dict[str, list[CallEdge]]],
    global_names: tuple[str, ...] = (),
) -> tuple[list[tuple[str, _PathHit]], bool]:
    """Trace one seed on one side.

    Returns ``(hits, truncated)`` where ``hits`` is ``[(candidate_symbol_id,
    _PathHit), ...]`` sorted by ``(min_depth, path, candidate_symbol_id)`` and
    capped at ``max_candidates``.  ``truncated`` is ``True`` when either the
    search budget or the candidate cap dropped results, so the caller can mark
    the surviving rows as incomplete.
    """

    symbols = getattr(index, "symbols", None) or {}
    seed = symbols.get(seed_id)
    seed_is_module = bool(seed is not None and seed.is_module)
    hits: dict[str, _PathHit] = {}
    truncated = False
    expansions = 0

    if seed_is_module:
        # A module pseudo symbol is only "reached" by the modules importing it;
        # those importers are candidates themselves but are not expanded further.
        imports = _buckets_for(index, EDGE_IMPORT, cache)
        for edge in imports.get(seed_id, ()):
            expansions += 1
            if expansions > budget:
                truncated = True
                break
            caller = symbols.get(edge.caller_id)
            if caller is None or caller.symbol_id == seed_id:
                continue
            if caller.symbol_id in hits:
                continue
            hits[caller.symbol_id] = _PathHit(1, [edge.edge_id], EVIDENCE_IMPORT)
        # P1: a changed module-level assignment reaches the functions that read
        # the changed global in this module.  The symbol change carries the
        # variable names; only resolved same-module read edges are considered.
        if global_names:
            reads = _buckets_for(index, EDGE_GLOBAL_READ, cache)
            for edge in reads.get(seed_id, ()):
                if edge.target not in global_names:
                    continue
                expansions += 1
                if expansions > budget:
                    truncated = True
                    break
                caller = symbols.get(edge.caller_id)
                if caller is None or caller.symbol_id == seed_id:
                    continue
                if caller.symbol_id in hits:
                    continue
                hits[caller.symbol_id] = _PathHit(1, [edge.edge_id], EVIDENCE_GLOBAL_READ)
    else:
        calls = _buckets_for(index, EDGE_CALL, cache)
        visited = {seed_id}
        queue: deque[tuple[str, list[str]]] = deque([(seed_id, [])])
        while queue:
            current_id, path = queue.popleft()
            expansions += 1
            if expansions > budget:
                truncated = True
                break
            if len(path) >= max_depth:
                continue
            for edge in calls.get(current_id, ()):
                caller = symbols.get(edge.caller_id)
                if caller is None or caller.symbol_id in visited:
                    continue
                visited.add(caller.symbol_id)
                child_path = path + [edge.edge_id]
                hits[caller.symbol_id] = _PathHit(
                    len(child_path), child_path, EVIDENCE_CALL
                )
                queue.append((caller.symbol_id, child_path))

    ordered: list[tuple[int, str, str, _PathHit]] = []
    for candidate_symbol_id, hit in hits.items():
        symbol = symbols[candidate_symbol_id]
        ordered.append((hit.depth, symbol.path, candidate_symbol_id, hit))
    ordered.sort(key=lambda row: (row[0], row[1], row[2]))
    if len(ordered) > max_candidates:
        ordered = ordered[:max_candidates]
        truncated = True
    return [(row[2], row[3]) for row in ordered], truncated


def trace_impacts(
    symbol_changes: list[SymbolChange],
    before_index: Any,
    after_index: Any,
    config: Config,
) -> list[ImpactCandidate]:
    """Return the deterministic reverse-impact candidates for all symbol changes."""

    changes = list(symbol_changes or ())
    if not changes:
        return []

    max_depth = config.analysis.max_depth
    max_candidates = config.analysis.max_candidates_per_change
    budget = search_budget(config)
    cache: dict[tuple[int, str], dict[str, list[CallEdge]]] = {}
    candidates: list[ImpactCandidate] = []

    for symbol_change in changes:
        sides: list[tuple[str, Any, str]] = []
        if symbol_change.old_symbol_id:
            sides.append((SIDE_BEFORE, before_index, symbol_change.old_symbol_id))
        if symbol_change.new_symbol_id:
            sides.append((SIDE_AFTER, after_index, symbol_change.new_symbol_id))

        rows: list[tuple[str, int, str, str, list[str], str, bool]] = []
        global_names = tuple(
            sorted(
                {
                    str(name)
                    for name in (symbol_change.details or {}).get("global_names", [])
                    if name
                }
            )
        )
        for side, index, seed_id in sides:
            if index is None:
                continue
            hits, truncated = _trace_side(
                index,
                seed_id,
                max_depth=max_depth,
                max_candidates=max_candidates,
                budget=budget,
                cache=cache,
                global_names=global_names,
            )
            symbols = getattr(index, "symbols", None) or {}
            for candidate_symbol_id, hit in hits:
                symbol = symbols.get(candidate_symbol_id)
                if symbol is None:  # pragma: no cover - defensive
                    continue
                rows.append(
                    (
                        side,
                        hit.depth,
                        symbol.path,
                        candidate_symbol_id,
                        list(hit.edge_ids),
                        hit.evidence,
                        truncated,
                    )
                )

        # Sort across both sides of this change, then number the candidates
        # deterministically.  Sequence numbers are per symbol change (1-based).
        rows.sort(key=lambda row: (_side_rank(row[0]), row[1], row[2], row[3]))
        for seq, row in enumerate(rows, start=1):
            side, depth, _path, candidate_symbol_id, edge_ids, evidence, truncated = row
            seed_id = (
                symbol_change.old_symbol_id
                if side == SIDE_BEFORE
                else symbol_change.new_symbol_id
            )
            candidates.append(
                ImpactCandidate(
                    candidate_id=f"cand:{symbol_change.symbol_change_id}:{side}:{seq:03d}",
                    symbol_change_id=symbol_change.symbol_change_id,
                    seed_symbol_id=seed_id or "",
                    candidate_symbol_id=candidate_symbol_id,
                    side=side,
                    min_depth=depth,
                    edge_ids=edge_ids,
                    evidence=evidence,
                    truncated=truncated,
                )
            )

    candidates.sort(
        key=lambda candidate: (
            candidate.symbol_change_id,
            _side_rank(candidate.side),
            candidate.min_depth,
            candidate.candidate_symbol_id,
        )
    )
    return candidates
