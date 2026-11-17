"""Test recommendation built from reverse-impact candidates.

Strong recommendations are only made when an impact candidate is itself a test
function (``is_test`` on the symbol) reachable from the changed symbol through
statically resolved calls.  That keeps P0 conservative: no naming heuristics,
no coverage guessing.  Every recommendation carries the exact candidate path
that produced it so the CLI/web layer can show the evidence chain.

P1 adds *weak* associations on top of the strong ones (only when the caller
passes the optional ``changes`` argument, so old calls are unaffected):

* import relation -- a test file imports a module whose file changed on the
  after side (``import_relation:<module>``); all top-level ``test_*``
  functions of that file are recommended;
* naming heuristic -- a test function name contains the simple name of a
  changed symbol and that identifier is at least four characters long
  (``name_match:<name>``).

Weak recommendations never replace a strong one for the same
``(side, path, qualified_name)`` tuple, carry ``min_depth=0`` and no candidate
ids, and are capped deterministically at :data:`_MAX_WEAK_RECOMMENDATIONS`.

Optional imported Coverage evidence (``coverage=...``) only appends
``coverage_context:<ctx>`` to the evidence of already recommended after-side
tests; it never creates recommendations or changes their strength, depth or
ordering.
"""

from __future__ import annotations

from typing import Any

from .models import (
    EDGE_IMPORT,
    SIDE_AFTER,
    SIDE_BEFORE,
    SIDES,
    TEST_STRENGTH_STRONG,
    TEST_STRENGTH_WEAK,
    Change,
    ImpactCandidate,
    Symbol,
    SymbolChange,
    TestRecommendation,
)

# Qualifier for the dedupe key and sorting when a test has no qualified name
# (never the case for a real test function, but keeps the code total).
_NO_NAME = ""

# Canonical side order, matching ``trace_impacts``.
_SIDE_ORDER = {side: index for index, side in enumerate(SIDES)}

# P1 weak-association limits and evidence prefixes.
_MAX_WEAK_RECOMMENDATIONS = 50
_WEAK_EVIDENCE_IMPORT = "import_relation"
_WEAK_EVIDENCE_NAME = "name_match"
_MIN_NAME_MATCH_LENGTH = 4


def _side_rank(side: str) -> int:
    return _SIDE_ORDER.get(side, len(SIDES))


def _side_symbols(index: Any) -> dict[str, Symbol]:
    return getattr(index, "symbols", None) or {}


def _edge_lookup(index: Any) -> dict[str, Any]:
    return {edge.edge_id: edge for edge in (getattr(index, "edges", None) or ())}


def _display(symbol: Symbol | None) -> str:
    if symbol is None:
        return "?"
    if symbol.is_module:
        return symbol.module or symbol.path
    return symbol.display_name


def _is_path_prefix(prefix: list[str], path: list[str]) -> bool:
    """Whether ``prefix`` is a (non-empty) prefix of ``path``, or equal to it."""

    if not prefix:
        return False
    return len(prefix) <= len(path) and path[: len(prefix)] == list(prefix)


def _evidence(candidate: ImpactCandidate, symbols: dict[str, Symbol], edges: dict[str, Any]) -> str:
    """Render a human readable call chain, outermost caller first."""

    if not candidate.edge_ids:
        seed = symbols.get(candidate.seed_symbol_id)
        return f"{_display(seed)} (direct)"

    names: list[str] = []
    for edge_id in reversed(candidate.edge_ids):
        edge = edges.get(edge_id)
        if edge is None:  # pragma: no cover - defensive, edges belong to the same side
            names.append("?")
            continue
        names.append(_display(symbols.get(edge.caller_id)))

    seed = symbols.get(candidate.seed_symbol_id)
    if seed is not None:
        names.append(_display(seed))
    else:
        first_edge = edges.get(candidate.edge_ids[0])
        callee = symbols.get(first_edge.callee_id) if first_edge is not None else None
        names.append(_display(callee))

    first_edge = edges.get(candidate.edge_ids[0])
    if first_edge is not None and first_edge.edge_kind == EDGE_IMPORT:
        return " -> ".join(names) + " (import)"
    count = len(candidate.edge_ids)
    return " -> ".join(names) + f" ({count} {'call' if count == 1 else 'calls'})"


# --------------------------------------------------------------------------
# P1 weak association helpers
# --------------------------------------------------------------------------


def _after_test_symbols(after_index: Any) -> dict[str, list[Symbol]]:
    """Top-level test functions of the after index, grouped by file path."""

    grouped: dict[str, list[Symbol]] = {}
    for symbol in _side_symbols(after_index).values():
        if not symbol.is_test:
            continue
        grouped.setdefault(symbol.path, []).append(symbol)
    for symbols in grouped.values():
        symbols.sort(key=lambda symbol: (symbol.start_line, symbol.qualified_name, symbol.symbol_id))
    return grouped


def _module_name_for_path(index: Any, path: str) -> str | None:
    """Module name of one indexed file, preferring the index's module table."""

    info = (getattr(index, "path_modules", None) or {}).get(path)
    name = getattr(info, "name", None)
    if name:
        return str(name)
    for symbol in _side_symbols(index).values():
        if symbol.path == path and symbol.is_module and symbol.module:
            return symbol.module
    return None


def _after_module_targets(after_index: Any, changes: list[Change]) -> tuple[set[str], set[str]]:
    """After-side modules of the changed files.

    Returns ``(module_names, module_symbol_ids)``; removed files have no after
    side and are therefore skipped (their imports are unresolved in the after
    index anyway).
    """

    names: set[str] = set()
    symbol_ids: set[str] = set()
    for change in changes or ():
        after_path = getattr(change, "new_path", None)
        if not after_path:
            continue
        name = _module_name_for_path(after_index, after_path)
        if name:
            names.add(name)
        for symbol in _side_symbols(after_index).values():
            if symbol.path == after_path and symbol.is_module:
                symbol_ids.add(symbol.symbol_id)
    return names, symbol_ids


def _changed_simple_names(
    symbol_changes: list[SymbolChange],
    before_index: Any,
    after_index: Any,
) -> list[str]:
    """Sorted unique simple names of the changed symbols (both sides)."""

    symbols = {
        **_side_symbols(before_index),
        **_side_symbols(after_index),
    }
    names: set[str] = set()
    for change in symbol_changes or ():
        for symbol_id in (change.new_symbol_id, change.old_symbol_id):
            if not symbol_id:
                continue
            symbol = symbols.get(symbol_id)
            if symbol is None or symbol.is_module or not symbol.qualified_name:
                continue
            name = symbol.qualified_name.rsplit(".", 1)[-1]
            if len(name) >= _MIN_NAME_MATCH_LENGTH:
                names.add(name)
    return sorted(names)


def _weak_evidence(
    after_index: Any,
    changes: list[Change],
    symbol_changes: list[SymbolChange],
    before_index: Any,
) -> dict[tuple[str, str, str], tuple[Symbol, str]]:
    """Map dedupe key -> (test symbol, evidence) for every weak association.

    Import relations win over name matches when both point at the same test
    function; ties inside one evidence family are broken by the sorted evidence
    string so the result is deterministic for shuffled inputs.
    """

    tests_by_path = _after_test_symbols(after_index)
    module_names, module_symbol_ids = _after_module_targets(after_index, changes)

    # Priority 0 (import) beats priority 1 (name); smaller evidence breaks ties.
    found: dict[tuple[str, str, str], tuple[int, Symbol, str]] = {}

    def remember(symbol: Symbol, priority: int, evidence: str) -> None:
        key = (SIDE_AFTER, symbol.path, symbol.qualified_name or _NO_NAME)
        current = found.get(key)
        candidate = (priority, symbol, evidence)
        if current is None:
            found[key] = candidate
            return
        if (priority, evidence) < (current[0], current[2]):
            found[key] = candidate

    for edge in _edge_lookup(after_index).values():
        if edge.edge_kind != EDGE_IMPORT or edge.resolution != "resolved":
            continue
        callee_id = getattr(edge, "callee_id", None)
        callee_module = getattr(edge, "callee_module", None)
        if not (callee_module in module_names or (callee_id and callee_id in module_symbol_ids)):
            continue
        module = callee_module
        if not module and callee_id:
            callee = _side_symbols(after_index).get(callee_id)
            module = callee.module if callee is not None else None
        if not module:
            continue
        evidence = f"{_WEAK_EVIDENCE_IMPORT}:{module}"
        for symbol in tests_by_path.get(edge.path, ()):
            remember(symbol, 0, evidence)

    names = _changed_simple_names(symbol_changes, before_index, after_index)
    if names:
        for path in sorted(tests_by_path):
            for symbol in tests_by_path[path]:
                test_name = symbol.qualified_name.rsplit(".", 1)[-1]
                matching = [name for name in names if name in test_name]
                if not matching:
                    continue
                remember(symbol, 1, f"{_WEAK_EVIDENCE_NAME}:{matching[0]}")

    return {key: (value[1], value[2]) for key, value in found.items()}


def _weak_recommendations(
    after_index: Any,
    after_tests: set[tuple[str, str]],
    changes: list[Change],
    symbol_changes: list[SymbolChange],
    before_index: Any,
    strong_keys: set[tuple[str, str, str]],
) -> list[TestRecommendation]:
    associations = _weak_evidence(after_index, changes, symbol_changes, before_index)
    ordered = sorted(
        associations.items(),
        key=lambda item: (
            item[1][0].path,
            item[1][0].qualified_name or _NO_NAME,
            _side_rank(item[0][0]),
            item[1][1],
        ),
    )
    recommendations: list[TestRecommendation] = []
    for key, (symbol, evidence) in ordered:
        if key in strong_keys:
            continue
        recommendations.append(
            TestRecommendation(
                test_path=symbol.path,
                qualified_name=symbol.qualified_name or None,
                side=key[0],
                candidate_ids=[],
                min_depth=0,
                strength=TEST_STRENGTH_WEAK,
                evidence=evidence,
                exists_in_after=(symbol.path, symbol.qualified_name) in after_tests,
                test_symbol_id=symbol.symbol_id,
            )
        )
        if len(recommendations) >= _MAX_WEAK_RECOMMENDATIONS:
            break
    return recommendations


def _annotate_coverage(
    recommendations: list[TestRecommendation],
    coverage: Any,
) -> None:
    """Append ``coverage_context:<ctx>`` evidence to after-side recommendations.

    Coverage is external, imported evidence: it must never create a
    recommendation, change a strength/depth, mark a test as executed in the
    current run, or reorder the result.  The object is duck-typed against
    :class:`patchpilot.coverage_data.CoverageEvidence`; anything without the
    matching accessors is ignored defensively.
    """

    if coverage is None:
        return
    matcher = getattr(coverage, "test_contexts_for", None)
    if not callable(matcher):
        return
    for recommendation in recommendations:
        if recommendation.side != SIDE_AFTER:
            continue
        contexts = matcher(
            recommendation.test_path,
            recommendation.qualified_name or "",
        )
        if not contexts:
            continue
        addition = " ".join(f"coverage_context:{context}" for context in contexts)
        if recommendation.evidence:
            recommendation.evidence = f"{recommendation.evidence} {addition}"
        else:  # pragma: no cover - every real recommendation has evidence
            recommendation.evidence = addition


def recommend_tests(
    candidates: list[ImpactCandidate],
    symbol_changes: list[SymbolChange],
    before_index: Any,
    after_index: Any,
    changes: list[Change] | None = None,
    coverage: Any = None,
) -> list[TestRecommendation]:
    """Return the deterministically sorted test recommendations.

    Strong recommendations are derived solely from the impact ``candidates``;
    the optional ``changes`` argument additionally enables the P1 weak
    associations (import relation + naming heuristic) described in the module
    docstring.  Omitting it keeps the P0 behaviour exactly.

    The optional ``coverage`` object (a
    :class:`patchpilot.coverage_data.CoverageEvidence`) only *annotates* already
    recommended after-side tests whose names match an imported coverage context:
    ``coverage_context:<ctx>`` is appended to :attr:`TestRecommendation.evidence`.
    It never adds recommendations, changes ``strength``/``min_depth`` or claims
    the test ran in the current run.  ``None`` keeps the old behaviour.

    ``symbol_changes`` is accepted for interface symmetry with
    :func:`patchpilot.impact.trace_impacts`; the seed symbol is already part of
    every candidate.  It is only consulted for the weak naming heuristic.
    """

    all_candidates = list(candidates or ())
    symbols_by_side = {SIDE_BEFORE: _side_symbols(before_index), SIDE_AFTER: _side_symbols(after_index)}
    edges_by_side = {SIDE_BEFORE: _edge_lookup(before_index), SIDE_AFTER: _edge_lookup(after_index)}
    after_tests = {
        (symbol.path, symbol.qualified_name)
        for symbol in symbols_by_side[SIDE_AFTER].values()
        if symbol.is_test
    }

    # Group candidates that name the same test symbol on the same side; the
    # contract dedupes by (side, test_path, qualified_name) and merges paths.
    groups: dict[tuple[str, str, str], list[tuple[ImpactCandidate, Symbol]]] = {}
    for candidate in all_candidates:
        side_symbols = symbols_by_side.get(candidate.side)
        if side_symbols is None:
            continue
        symbol = side_symbols.get(candidate.candidate_symbol_id)
        if symbol is None or not symbol.is_test:
            continue
        key = (candidate.side, symbol.path, symbol.qualified_name or _NO_NAME)
        groups.setdefault(key, []).append((candidate, symbol))

    strong_recommendations: list[TestRecommendation] = []
    for (side, test_path, _ignore), members in groups.items():
        members.sort(key=lambda item: (item[0].min_depth, item[0].candidate_id))
        primary_candidate, primary_symbol = members[0]

        related: dict[str, ImpactCandidate] = {}
        for candidate, _symbol in members:
            for other in all_candidates:
                if other.side != side:
                    continue
                if _is_path_prefix(other.edge_ids, candidate.edge_ids):
                    related[other.candidate_id] = other
        candidate_ids = [
            candidate.candidate_id
            for candidate in sorted(
                related.values(), key=lambda item: (item.min_depth, item.candidate_id)
            )
        ]

        strong_recommendations.append(
            TestRecommendation(
                test_path=test_path,
                qualified_name=primary_symbol.qualified_name or None,
                side=side,
                candidate_ids=candidate_ids,
                min_depth=min(member[0].min_depth for member in members),
                strength=TEST_STRENGTH_STRONG,
                evidence=_evidence(
                    primary_candidate,
                    symbols_by_side[side],
                    edges_by_side[side],
                ),
                exists_in_after=(test_path, primary_symbol.qualified_name) in after_tests,
                test_symbol_id=primary_symbol.symbol_id,
            )
        )

    recommendations: list[TestRecommendation] = list(strong_recommendations)
    if changes is not None:
        strong_keys = {
            (rec.side, rec.test_path, rec.qualified_name or _NO_NAME)
            for rec in strong_recommendations
        }
        recommendations.extend(
            _weak_recommendations(
                after_index,
                after_tests,
                changes,
                symbol_changes,
                before_index,
                strong_keys,
            )
        )

    recommendations.sort(
        key=lambda rec: (
            rec.min_depth,
            rec.test_path,
            rec.qualified_name or _NO_NAME,
            _side_rank(rec.side),
        )
    )
    _annotate_coverage(recommendations, coverage)
    return recommendations
