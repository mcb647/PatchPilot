"""Report view models shared by the CLI and the web dashboard.

Reports are built exclusively from persisted rows (``storage.RunDetail``), so
``show`` and ``analyze --format json`` cannot drift, and later edits to the
working tree can never change a stored report.
"""

from __future__ import annotations

from typing import Any

from . import models
from .changes import render_hunks_text

MAX_DIAGNOSTICS_IN_SUMMARY = 8


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------


def _symbol_ref(symbol: models.Symbol | None) -> dict[str, Any] | None:
    if symbol is None:
        return None
    return {
        "symbol_id": symbol.symbol_id,
        "side": symbol.side,
        "path": symbol.path,
        "module": symbol.module,
        "qualified_name": symbol.qualified_name,
        "display_name": symbol.display_name,
        "kind": symbol.kind,
        "start_line": symbol.start_line,
        "end_line": symbol.end_line,
        "def_line": symbol.def_line,
    }


def _change_dict(change: models.Change) -> dict[str, Any]:
    return {
        "change_id": change.change_id,
        "kind": change.kind,
        "old_path": change.old_path,
        "new_path": change.new_path,
        "display_path": change.display_path,
        "old_sha256": change.old_sha256,
        "new_sha256": change.new_sha256,
        "rename_basis": change.rename_basis,
        "analysis_status": change.analysis_status,
        "diff_truncated": change.diff_truncated,
        "old_changed_lines": list(change.old_changed_lines),
        "new_changed_lines": list(change.new_changed_lines),
        "hunks": [
            {
                "old_start": hunk.old_start,
                "old_count": hunk.old_count,
                "new_start": hunk.new_start,
                "new_count": hunk.new_count,
                "lines": list(hunk.lines),
            }
            for hunk in change.hunks
        ],
        "diff": render_hunks_text(change),
        "diagnostics": [d.to_dict() for d in change.diagnostics],
    }


def _symbol_change_dict(
    symbol_change: models.SymbolChange,
    symbols: dict[str, models.Symbol],
) -> dict[str, Any]:
    return {
        "symbol_change_id": symbol_change.symbol_change_id,
        "change_id": symbol_change.change_id,
        "kind": symbol_change.kind,
        "reason": symbol_change.reason,
        "side": symbol_change.side,
        "structure_changed": symbol_change.structure_changed,
        "old_symbol": _symbol_ref(symbols.get(symbol_change.old_symbol_id or "")),
        "new_symbol": _symbol_ref(symbols.get(symbol_change.new_symbol_id or "")),
        "old_changed_lines": list(symbol_change.old_changed_lines),
        "new_changed_lines": list(symbol_change.new_changed_lines),
        "details": dict(symbol_change.details or {}),
        "diagnostics": [d.to_dict() for d in symbol_change.diagnostics],
    }


def _edge_dict(edge: models.CallEdge, symbols: dict[str, models.Symbol]) -> dict[str, Any]:
    caller = symbols.get(edge.caller_id)
    return {
        "edge_id": edge.edge_id,
        "side": edge.side,
        "edge_kind": edge.edge_kind,
        "caller": _symbol_ref(caller),
        "callee": _symbol_ref(symbols.get(edge.callee_id or "")),
        "path": edge.path,
        "line": edge.line,
        "col": edge.col,
        "decision": edge.resolution,
        "target": edge.target,
    }


def _candidate_dict(
    candidate: models.ImpactCandidate,
    symbols: dict[str, models.Symbol],
    edges: dict[str, models.CallEdge],
) -> dict[str, Any]:
    path_edges = [edges[eid] for eid in candidate.edge_ids if eid in edges]
    return {
        "candidate_id": candidate.candidate_id,
        "symbol_change_id": candidate.symbol_change_id,
        "side": candidate.side,
        "evidence": candidate.evidence,
        "min_depth": candidate.min_depth,
        "truncated": candidate.truncated,
        "seed": _symbol_ref(symbols.get(candidate.seed_symbol_id)),
        "candidate": _symbol_ref(symbols.get(candidate.candidate_symbol_id)),
        "edge_ids": list(candidate.edge_ids),
        "path": [_edge_dict(edge, symbols) for edge in path_edges],
    }


def _test_dict(
    recommendation: models.TestRecommendation,
    symbols: dict[str, models.Symbol],
) -> dict[str, Any]:
    return {
        "test_path": recommendation.test_path,
        "qualified_name": recommendation.qualified_name,
        "side": recommendation.side,
        "strength": recommendation.strength,
        "min_depth": recommendation.min_depth,
        "evidence": recommendation.evidence,
        "candidate_ids": list(recommendation.candidate_ids),
        "exists_in_after": recommendation.exists_in_after,
        "test_symbol": _symbol_ref(symbols.get(recommendation.test_symbol_id or "")),
    }


def _scope(detail: Any) -> dict[str, Any]:
    run: models.AnalysisRun = detail.run
    entries = list(detail.snapshot_entries)
    before = [e for e in entries if e.side == models.SIDE_BEFORE]
    after = [e for e in entries if e.side == models.SIDE_AFTER]
    before_present = [e for e in before if e.status == "present"]
    after_present = [e for e in after if e.status == "present"]
    metrics = run.metrics or {}
    return {
        "mode": run.mode,
        "endpoint_before": run.endpoint_before,
        "endpoint_after": run.endpoint_after,
        "repository": run.display_name,
        "repo_root": run.repo_root,
        "branch": run.branch,
        "detached": run.detached,
        "files": {"before": len(before_present), "after": len(after_present)},
        "entries": {"before": len(before), "after": len(after)},
        "python_files": {
            "before": sum(1 for e in before_present if e.is_python),
            "after": sum(1 for e in after_present if e.is_python),
        },
        "limits": metrics.get("analysis", {}),
        "before_stats": metrics.get("before", {}),
        "after_stats": metrics.get("after", {}),
    }


def _judge_dict(detail: Any) -> dict[str, Any]:
    run: models.AnalysisRun = detail.run
    metrics = run.metrics if isinstance(run.metrics, dict) else {}
    judge_metrics = metrics.get("judge") if isinstance(metrics.get("judge"), dict) else {}
    attempts = list(getattr(detail, "judge_attempts", []) or [])
    verdicts = list(getattr(detail, "judge_verdicts", []) or [])
    verdict_counts = {code: 0 for code in models.VERDICTS}
    for verdict in verdicts:
        if verdict.verdict in verdict_counts:
            verdict_counts[verdict.verdict] += 1
    requested = bool(judge_metrics.get("requested"))
    status = str(judge_metrics.get("status") or (models.JUDGE_DISABLED if not verdicts else models.JUDGE_COMPLETED))
    return {
        "enabled": requested,
        "status": status,
        "summary": {
            "attempts": len(attempts),
            "verdicts": len(verdicts),
            "affected": verdict_counts[models.VERDICT_AFFECTED],
            "unaffected": verdict_counts[models.VERDICT_UNAFFECTED],
            "uncertain": verdict_counts[models.VERDICT_UNCERTAIN],
            "cache_hits": int(judge_metrics.get("cache_hits", 0)),
            "failed": int(judge_metrics.get("failed", 0)),
        },
        "metrics": judge_metrics,
        "attempts": [
            {
                "attempt_id": attempt.attempt_id,
                "candidate_id": attempt.candidate_id,
                "attempt_no": attempt.attempt_no,
                "adapter": attempt.adapter,
                "model": attempt.model,
                "started_at": attempt.started_at,
                "duration_ms": attempt.duration_ms,
                "context_digest": attempt.context_digest,
                "context_tokens_estimate": attempt.context_tokens_estimate,
                "cache_hit": attempt.cache_hit,
                "valid": attempt.valid,
                "error_category": attempt.error_category,
                "fallback_reason": attempt.fallback_reason,
                "request_id": attempt.request_id,
            }
            for attempt in attempts
        ],
        "verdicts": [
            {
                "candidate_id": verdict.candidate_id,
                "attempt_no": verdict.attempt_no,
                "verdict": verdict.verdict,
                "reason": verdict.reason,
                "adapter": verdict.adapter,
                "model": verdict.model,
                "evidence": list(verdict.evidence),
                "conditions": list(verdict.conditions),
                "uncertainty": verdict.uncertainty,
                "schema_version": verdict.schema_version,
                "validated_at": verdict.validated_at,
            }
            for verdict in verdicts
        ],
        "note": (
            "Judge is opt-in (--judge) and only sends trimmed evidence to configured adapters."
            if requested
            else "Judge was not enabled for this run."
        ),
    }


def build_json_report(detail: Any) -> dict[str, Any]:
    run: models.AnalysisRun = detail.run
    symbols: dict[str, models.Symbol] = dict(getattr(detail, "symbols", {}) or {})
    edges = {edge.edge_id: edge for edge in getattr(detail, "edges", []) or []}
    diagnostics: list[models.Diagnostic] = list(run.diagnostics)
    for change in getattr(detail, "changes", []) or []:
        diagnostics.extend(change.diagnostics)
    for symbol_change in getattr(detail, "symbol_changes", []) or []:
        diagnostics.extend(symbol_change.diagnostics)
    return {
        "schema_version": models.SCHEMA_VERSION,
        "run": run.to_dict(),
        "scope": _scope(detail),
        "changes": [_change_dict(c) for c in getattr(detail, "changes", []) or []],
        "symbol_changes": [
            _symbol_change_dict(sc, symbols)
            for sc in getattr(detail, "symbol_changes", []) or []
        ],
        "impacts": [
            _candidate_dict(candidate, symbols, edges)
            for candidate in getattr(detail, "candidates", []) or []
        ],
        "judge": _judge_dict(detail),
        "test_recommendations": [
            _test_dict(rec, symbols)
            for rec in getattr(detail, "test_recommendations", []) or []
        ],
        "diagnostics": [d.to_dict() for d in diagnostics],
    }


# --------------------------------------------------------------------------
# Markdown and terminal summary
# --------------------------------------------------------------------------


def _fence(text: str, language: str = "") -> str:
    marker = "~~~"
    while marker in text:
        marker += "~"
    return f"{marker}{language}\n{text}\n{marker}"


def _inline(value: str | None) -> str:
    if value is None:
        return "-"
    return "`" + value.replace("`", "\\`") + "`"


def _status_line(detail: Any) -> str:
    run: models.AnalysisRun = detail.run
    bits = [
        f"status={run.status}",
        f"summary={run.summary}",
        f"mode={run.mode}",
        f"endpoints={run.endpoint_before} -> {run.endpoint_after}",
    ]
    return " | ".join(bits)


def render_markdown(detail: Any) -> str:
    report = build_json_report(detail)
    run = report["run"]
    lines: list[str] = []
    lines.append(f"# PatchPilot Run {run['run_id']}")
    lines.append("")
    lines.append(f"- Repository: {report['scope']['repository']} (`{run['repo_root']}`)")
    branch = run.get("branch") or "(detached)" if run.get("detached") else (run.get("branch") or "-")
    lines.append(f"- Branch: {branch}")
    lines.append(f"- Mode: {run['mode']} ({run['endpoint_before']} -> {run['endpoint_after']})")
    lines.append(f"- Started: {run['started_at']}  Finished: {run.get('finished_at') or '-'}")
    lines.append(f"- Status: {run['status']}  Summary: {run['summary']}")
    lines.append("")
    lines.append("## Counts")
    lines.append("")
    lines.append("| changes | symbol changes | candidates | tests |")
    lines.append("|---|---|---|---|")
    lines.append(
        f"| {len(report['changes'])} | {len(report['symbol_changes'])} | "
        f"{len(report['impacts'])} | {len(report['test_recommendations'])} |"
    )
    lines.append("")

    if report["changes"]:
        lines.append("## Changes")
        lines.append("")
        for change in report["changes"]:
            header = f"### {_inline(change['display_path'])} ({change['kind']})"
            lines.append(header)
            lines.append("")
            lines.append(
                f"- analysis status: `{change['analysis_status']}`"
                + (" (diff truncated)" if change["diff_truncated"] else "")
            )
            if change["diff"]:
                lines.append(_fence(change["diff"], "diff"))
            elif change["analysis_status"] != "analyzed":
                lines.append("- no line diff retained for this change")
            lines.append("")
    else:
        lines.append("## Changes")
        lines.append("")
        lines.append("No file changes were detected for these endpoints.")
        lines.append("")

    if report["symbol_changes"]:
        lines.append("## Symbol changes")
        lines.append("")
        for symbol_change in report["symbol_changes"]:
            old = symbol_change["old_symbol"]
            new = symbol_change["new_symbol"]
            name = (new or old or {}).get("display_name", "?")
            side_note = f" [{symbol_change['side']}]" if symbol_change["side"] else ""
            structure = "structure changed" if symbol_change["structure_changed"] else "text-only"
            lines.append(
                f"- {_inline(name)} {symbol_change['kind']} ({symbol_change['reason']}, "
                f"{structure}){side_note}"
            )
        lines.append("")

    if report["impacts"]:
        lines.append("## Impact paths")
        lines.append("")
        for candidate in report["impacts"]:
            seed = (candidate["seed"] or {}).get("display_name", "?")
            target = (candidate["candidate"] or {}).get("display_name", "?")
            path_names = [seed] + [
                ((edge.get("caller") or {}).get("display_name", "?")) for edge in candidate["path"]
            ]
            suffix = " (truncated)" if candidate["truncated"] else ""
            lines.append(
                f"- {_inline(target)} depth={candidate['min_depth']} "
                f"side={candidate['side']} via={candidate['evidence']}{suffix}"
            )
            lines.append(f"  - path: {' <- '.join(path_names)}")
        lines.append("")

    if report["test_recommendations"]:
        lines.append("## Recommended tests")
        lines.append("")
        for rec in report["test_recommendations"]:
            qualifier = f"::{rec['qualified_name']}" if rec["qualified_name"] else ""
            exists = "" if rec["exists_in_after"] else " (no longer present in the new snapshot)"
            lines.append(
                f"- {_inline(rec['test_path'] + qualifier)} strength={rec['strength']} "
                f"distance={rec['min_depth']} side={rec['side']}{exists}"
            )
            if rec["evidence"]:
                lines.append(f"  - {rec['evidence']}")
        lines.append("")

    if report["judge"]["enabled"]:
        judge = report["judge"]
        lines.append("## Judge")
        lines.append("")
        lines.append(
            f"- status: `{judge['status']}` · attempts: {judge['summary']['attempts']} · "
            f"verdicts: {judge['summary']['verdicts']} · cache hits: {judge['summary']['cache_hits']}"
        )
        for verdict in judge["verdicts"]:
            lines.append(
                f"- `{verdict['candidate_id']}` **{verdict['verdict']}** "
                f"(attempt {verdict['attempt_no']}, {verdict['adapter']}"
                f"{'/' + verdict['model'] if verdict.get('model') else ''}): {verdict['reason']}"
            )
            if verdict.get("conditions"):
                lines.append(f"  - conditions: {'; '.join(verdict['conditions'])}")
            if verdict.get("uncertainty"):
                lines.append(f"  - uncertainty: {verdict['uncertainty']}")
        for attempt in judge["attempts"]:
            if attempt.get("error_category"):
                lines.append(
                    f"- attempt {attempt['attempt_no']} `{attempt['candidate_id']}` "
                    f"{attempt['adapter']} failed: `{attempt['error_category']}`"
                )
        lines.append("")

    if report["diagnostics"]:
        lines.append("## Diagnostics")
        lines.append("")
        for diagnostic in report["diagnostics"]:
            location = ""
            if diagnostic.get("path"):
                location = f" ({diagnostic['path']}"
                if diagnostic.get("line"):
                    location += f":{diagnostic['line']}"
                location += ")"
            lines.append(
                f"- [{diagnostic.get('severity', 'warning')}] "
                f"`{diagnostic.get('code', 'unknown')}` {diagnostic.get('message', '')}{location}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_summary(detail: Any) -> str:
    run: models.AnalysisRun = detail.run
    change_count = len(getattr(detail, "changes", []) or [])
    symbol_change_count = len(getattr(detail, "symbol_changes", []) or [])
    candidates = getattr(detail, "candidates", []) or []
    tests = getattr(detail, "test_recommendations", []) or []
    symbols: dict[str, models.Symbol] = dict(getattr(detail, "symbols", {}) or {})
    lines: list[str] = []
    lines.append(f"Run {run.run_id}  [{run.status}/{run.summary}]")
    lines.append(
        f"Repo: {run.display_name}  Branch: {run.branch or ('detached' if run.detached else '-')}"
    )
    lines.append(f"Mode: {run.mode}  {run.endpoint_before} -> {run.endpoint_after}")
    lines.append(
        f"Changes: {change_count} file(s), {symbol_change_count} symbol change(s)  "
        f"Candidates: {len(candidates)}  Tests: {len(tests)}"
    )

    if not change_count:
        lines.append("No changes detected between these endpoints.")
    elif not candidates:
        lines.append("No statically traceable impact candidates for the changed symbols.")
    else:
        lines.append("")
        lines.append("Impact candidates:")
        for candidate in candidates[:12]:
            target = symbols.get(candidate.candidate_symbol_id)
            seed = symbols.get(candidate.seed_symbol_id)
            target_name = target.display_name if target else candidate.candidate_symbol_id
            seed_name = seed.display_name if seed else candidate.seed_symbol_id
            kind = "import" if candidate.evidence == models.EVIDENCE_IMPORT else "call"
            lines.append(
                f"  - {target_name} <- {seed_name}  (depth {candidate.min_depth}, "
                f"{candidate.side} side, {kind})"
            )
        if len(candidates) > 12:
            lines.append(f"  ... {len(candidates) - 12} more candidates")

    if tests:
        lines.append("")
        lines.append("Recommended tests:")
        for rec in tests[:12]:
            qualifier = f"::{rec.qualified_name}" if rec.qualified_name else ""
            lines.append(
                f"  - {rec.test_path}{qualifier}  (distance {rec.min_depth}, {rec.side} side)"
            )

    judge = _judge_dict(detail)
    if judge["enabled"]:
        lines.append("")
        lines.append(
            f"Judge: {judge['status']}  verdicts={judge['summary']['verdicts']} "
            f"(affected={judge['summary']['affected']}, "
            f"unaffected={judge['summary']['unaffected']}, "
            f"uncertain={judge['summary']['uncertain']})  "
            f"cache_hits={judge['summary']['cache_hits']}"
        )

    diagnostics = list(run.diagnostics)
    if diagnostics:
        lines.append("")
        lines.append(f"Diagnostics: {len(diagnostics)}")
        for diagnostic in diagnostics[:MAX_DIAGNOSTICS_IN_SUMMARY]:
            lines.append(f"  - [{diagnostic.severity}] {diagnostic.code}: {diagnostic.message}")
        if len(diagnostics) > MAX_DIAGNOSTICS_IN_SUMMARY:
            lines.append(f"  ... {len(diagnostics) - MAX_DIAGNOSTICS_IN_SUMMARY} more")

    lines.append("")
    lines.append(f"Run ID: {run.run_id}")
    lines.append(f"Inspect: patchpilot show {run.run_id} --format markdown")
    lines.append("Dashboard: patchpilot web")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# bounded impact API (P1 web / automation)
# --------------------------------------------------------------------------


def _impact_graph_payload(
    detail: Any,
    symbols: dict[str, models.Symbol],
    kept_paths: list[tuple[models.ImpactCandidate, list[models.CallEdge]]],
    *,
    max_nodes: int,
    max_depth: int | None,
    truncated: bool,
) -> dict[str, Any]:
    """Build the graph extension for ``build_impact_api`` (Cytoscape friendly).

    Nodes are keyed by ``symbol_id`` (side-local unique), duplicate caller→callee
    relationships are merged into one edge with a ``positions`` set (``path:line``)
    and cycle/back edges are kept as ordinary directed edges so the renderer can
    draw them (and mark them) without losing evidence.
    """

    graph_truncated = bool(truncated)
    max_edges = max(1, max_nodes * 4)
    nodes: dict[str, dict[str, Any]] = {}
    depths: dict[str, int] = {}
    seed_ids: dict[str, set[str]] = {}
    candidate_ids: dict[str, set[str]] = {}
    edge_groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    def _note(node_id: str, symbol_change_id: str, candidate_id: str) -> None:
        seed_ids.setdefault(node_id, set()).add(symbol_change_id)
        candidate_ids.setdefault(node_id, set()).add(candidate_id)

    def add_node(
        node_id: str,
        *,
        depth: int,
        fallback_path: str = "",
        fallback_line: int = 0,
        fallback_side: str = "",
    ) -> bool:
        nonlocal graph_truncated
        if node_id in nodes:
            depths[node_id] = min(depths.get(node_id, depth), max(0, depth))
            return True
        if len(nodes) >= max_nodes:
            graph_truncated = True
            return False
        symbol = symbols.get(node_id)
        missing = symbol is None
        nodes[node_id] = {
            "id": node_id,
            "label": (
                symbol.display_name if symbol is not None else node_id
            ),
            "path": symbol.path if symbol is not None else fallback_path,
            "line": symbol.def_line if symbol is not None else fallback_line,
            "side": symbol.side if symbol is not None else fallback_side,
            "depth": max(0, depth),
            "kind": symbol.kind if symbol is not None else "target",
            "seed_ids": [],
            "candidate_ids": [],
            "truncated": False,
            "missing": missing,
        }
        depths[node_id] = max(0, depth)
        return True

    for candidate, path_edges in kept_paths:
        seed_node_id = candidate.seed_symbol_id
        if not add_node(seed_node_id, depth=0, fallback_side=candidate.side):
            continue
        _note(seed_node_id, candidate.symbol_change_id, candidate.candidate_id)
        visited_nodes: set[str] = {seed_node_id}
        for position, edge in enumerate(path_edges, start=1):
            if len(edge_groups) >= max_edges:
                graph_truncated = True
                break
            caller_id = edge.caller_id
            if not add_node(
                caller_id,
                depth=position,
                fallback_path=edge.path,
                fallback_line=edge.line,
                fallback_side=edge.side,
            ):
                break
            _note(caller_id, candidate.symbol_change_id, candidate.candidate_id)

            if edge.callee_id:
                target_id = edge.callee_id
                add_node(
                    target_id,
                    depth=max(0, position - 1),
                    fallback_path=edge.path,
                    fallback_line=edge.line,
                    fallback_side=edge.side,
                )
                target_label = (
                    symbols[target_id].display_name
                    if target_id in symbols
                    else (edge.target or target_id)
                )
            else:
                target_label = edge.target or "(未知目标)"
                target_id = f"target:{edge.side}:{target_label}"
                add_node(
                    target_id,
                    depth=max(0, position - 1),
                    fallback_path=edge.path,
                    fallback_line=edge.line,
                    fallback_side=edge.side,
                )
            _note(target_id, candidate.symbol_change_id, candidate.candidate_id)

            # A target that already appeared earlier in the chain is a back
            # edge (cycle); the first edge's target is the seed itself.
            edge_cycle = position > 1 and target_id in visited_nodes
            visited_nodes.add(caller_id)
            visited_nodes.add(target_id)

            key = (caller_id, target_id, edge.edge_kind, edge.side)
            group = edge_groups.get(key)
            if group is None:
                group = {
                    "source": caller_id,
                    "target": target_id,
                    "edge_kind": edge.edge_kind,
                    "side": edge.side,
                    "resolution": edge.resolution,
                    "reason": edge.reason,
                    "path": edge.path,
                    "line": edge.line,
                    "positions": set(),
                    "candidate_ids": set(),
                    "edge_ids": set(),
                    "cycle": False,
                    "caller_label": (
                        symbols[caller_id].display_name
                        if caller_id in symbols
                        else caller_id
                    ),
                    "callee_label": (
                        symbols[target_id].display_name
                        if target_id in symbols
                        else target_label
                    ),
                    "target_label": edge.target or "",
                }
                edge_groups[key] = group
            elif edge.resolution == "resolved":
                group["resolution"] = "resolved"
                group["reason"] = None
            group["cycle"] = group["cycle"] or edge_cycle
            group["positions"].add(f"{edge.path}:{edge.line}")
            group["candidate_ids"].add(candidate.candidate_id)
            group["edge_ids"].add(edge.edge_id)

        candidate_symbol_id = candidate.candidate_symbol_id
        if candidate_symbol_id and add_node(
            candidate_symbol_id, depth=max(1, int(candidate.min_depth)), fallback_side=candidate.side
        ):
            _note(candidate_symbol_id, candidate.symbol_change_id, candidate.candidate_id)

    # Deterministic node order: depth first, then stable symbol id.
    node_list = sorted(
        nodes.values(), key=lambda item: (item["depth"], item["id"])
    )
    for node in node_list:
        node_id = node["id"]
        node["seed_ids"] = sorted(seed_ids.get(node_id, set()))
        node["candidate_ids"] = sorted(candidate_ids.get(node_id, set()))

    layer_counts: dict[int, int] = {}
    positions: dict[str, dict[str, int]] = {}
    for node in node_list:
        layer = int(node["depth"])
        order = layer_counts.get(layer, 0)
        positions[node["id"]] = {"layer": layer, "order": order}
        layer_counts[layer] = order + 1

    edge_list: list[dict[str, Any]] = []
    for key in sorted(edge_groups):
        group = edge_groups[key]
        positions_list = sorted(group["positions"])
        edge_id = "ge-" + models.sha256_text(
            f"{group['source']}|{group['target']}|{group['edge_kind']}|{group['side']}"
        )[:16]
        edge_list.append(
            {
                "id": edge_id,
                "source": group["source"],
                "target": group["target"],
                "edge_kind": group["edge_kind"],
                "side": group["side"],
                "resolution": group["resolution"],
                "reason": group["reason"],
                "path": group["path"],
                "line": group["line"],
                "positions": positions_list,
                "caller_label": group["caller_label"],
                "callee_label": group["callee_label"],
                "target_label": group["target_label"],
                "candidate_ids": sorted(group["candidate_ids"]),
                "edge_ids": sorted(group["edge_ids"]),
                "cycle": bool(group["cycle"]),
            }
        )
    if len(edge_list) > max_edges:
        edge_list = edge_list[:max_edges]
        graph_truncated = True

    by_kind = {
        models.EDGE_CALL: 0,
        models.EDGE_IMPORT: 0,
        models.EDGE_GLOBAL_READ: 0,
    }
    for edge in edge_list:
        by_kind[edge["edge_kind"]] = by_kind.get(edge["edge_kind"], 0) + 1

    candidate_list = list(getattr(detail, "candidates", []) or [])
    kept_candidate_ids = {candidate.candidate_id for candidate, _ in kept_paths}
    direct = sum(
        1
        for candidate in candidate_list
        if candidate.candidate_id in kept_candidate_ids
        and int(candidate.min_depth) <= 1
    )
    indirect = sum(
        1
        for candidate in candidate_list
        if candidate.candidate_id in kept_candidate_ids
        and int(candidate.min_depth) > 1
    )

    candidate_tests: dict[str, list[dict[str, Any]]] = {}
    for recommendation in getattr(detail, "test_recommendations", []) or []:
        for candidate_id in getattr(recommendation, "candidate_ids", None) or []:
            if candidate_id not in kept_candidate_ids:
                continue
            candidate_tests.setdefault(candidate_id, []).append(
                {
                    "test_path": recommendation.test_path,
                    "qualified_name": recommendation.qualified_name,
                    "strength": recommendation.strength,
                    "min_depth": recommendation.min_depth,
                    "side": recommendation.side,
                    "exists_in_after": recommendation.exists_in_after,
                    "evidence": recommendation.evidence,
                }
            )
    for items in candidate_tests.values():
        items.sort(key=lambda item: (item["test_path"], item["qualified_name"] or ""))
    candidate_judge: dict[str, dict[str, Any]] = {}
    for verdict in getattr(detail, "judge_verdicts", []) or []:
        if verdict.candidate_id not in kept_candidate_ids:
            continue
        candidate_judge[verdict.candidate_id] = {
            "verdict": verdict.verdict,
            "reason": verdict.reason,
            "adapter": verdict.adapter,
            "model": verdict.model,
            "conditions": list(verdict.conditions),
            "uncertainty": verdict.uncertainty,
            "schema_version": verdict.schema_version,
        }

    depth_limit = max_depth
    if depth_limit is None:
        depth_limit = max((node["depth"] for node in node_list), default=0)
    return {
        "nodes": node_list,
        "edges": edge_list,
        "positions": positions,
        "stats": {
            "nodes": len(node_list),
            "edges": len(edge_list),
            "direct": direct,
            "indirect": indirect,
            "by_kind": by_kind,
            "truncated": graph_truncated,
        },
        "limits": {
            "max_nodes": max_nodes,
            "max_depth": depth_limit,
            "truncated": graph_truncated,
        },
        "evidence": {
            "candidate_tests": candidate_tests,
            "candidate_judge": candidate_judge,
        },
    }


def build_impact_api(
    detail: Any,
    *,
    seed: str | None = None,
    side: str | None = None,
    kind: str | None = None,
    max_nodes: int = 200,
    max_depth: int | None = None,
) -> dict[str, Any]:
    """Bounded, filterable impact graph for the JSON API and the tree page."""

    symbols: dict[str, models.Symbol] = dict(getattr(detail, "symbols", {}) or {})
    edges_by_id = {edge.edge_id: edge for edge in getattr(detail, "edges", []) or []}
    all_candidates = list(getattr(detail, "candidates", []) or [])
    symbol_changes = {
        change.symbol_change_id: change
        for change in getattr(detail, "symbol_changes", []) or []
    }
    allowed_kinds = {models.EDGE_CALL, models.EDGE_IMPORT, models.EDGE_GLOBAL_READ}
    if kind is not None and kind not in allowed_kinds:
        raise ValueError("kind must be one of call/import/global_read")
    if side is not None and side not in models.SIDES:
        raise ValueError("side must be before or after")

    selected: list[tuple[models.ImpactCandidate, list[models.CallEdge]]] = []
    for candidate in all_candidates:
        if seed is not None and candidate.symbol_change_id != seed:
            continue
        if side is not None and candidate.side != side:
            continue
        if max_depth is not None and int(candidate.min_depth) > max_depth:
            continue
        path_edges = [edges_by_id[eid] for eid in candidate.edge_ids if eid in edges_by_id]
        if kind is not None:
            path_edges = [edge for edge in path_edges if edge.edge_kind == kind]
            if not path_edges:
                continue
        selected.append((candidate, path_edges))

    node_ids: dict[str, None] = {}
    truncated = False

    def add_node(symbol_id: str | None) -> None:
        nonlocal truncated
        if symbol_id and symbol_id not in node_ids:
            if len(node_ids) >= max_nodes:
                truncated = True
                return
            node_ids[symbol_id] = None

    for candidate, path_edges in selected:
        add_node(candidate.seed_symbol_id)
        add_node(candidate.candidate_symbol_id)
        for edge in path_edges:
            add_node(edge.caller_id)
            add_node(edge.callee_id)

    bounded_candidates = []
    kept_paths: list[tuple[models.ImpactCandidate, list[models.CallEdge]]] = []
    edges_payload: dict[str, dict[str, Any]] = {}
    kept_candidate_ids: list[str] = []
    for candidate, path_edges in selected:
        if len(kept_candidate_ids) >= max_nodes:
            truncated = True
            break
        kept_candidate_ids.append(candidate.candidate_id)
        kept_paths.append((candidate, path_edges))
        bounded_candidates.append(_candidate_dict(candidate, symbols, edges_by_id))
        for edge in path_edges:
            if edge.edge_id in edges_payload:
                continue
            if len(edges_payload) >= max_nodes * 4:
                truncated = True
                break
            edges_payload[edge.edge_id] = {
                "edge_id": edge.edge_id,
                "side": edge.side,
                "edge_kind": edge.edge_kind,
                "resolution": edge.resolution,
                "reason": edge.reason,
                "target": edge.target,
                "path": edge.path,
                "line": edge.line,
                "caller_symbol_id": edge.caller_id,
                "callee_symbol_id": edge.callee_id,
                "caller": _symbol_ref(symbols.get(edge.caller_id)),
                "callee": _symbol_ref(symbols.get(edge.callee_id)),
            }
    # Only keep graph paths whose edges fit the bounded edge payload.
    kept_paths = [
        (candidate, [edge for edge in path_edges if edge.edge_id in edges_payload])
        for candidate, path_edges in kept_paths
    ]

    seed_ids = {candidate.symbol_change_id for candidate, _ in selected}
    seeds_payload = []
    for symbol_change_id in sorted(seed_ids):
        symbol_change = symbol_changes.get(symbol_change_id)
        seeds_payload.append(
            {
                "symbol_change_id": symbol_change_id,
                "change_id": symbol_change.change_id if symbol_change else None,
                "kind": symbol_change.kind if symbol_change else None,
                "reason": symbol_change.reason if symbol_change else None,
                "old_symbol": _symbol_ref(
                    symbols.get(symbol_change.old_symbol_id or "") if symbol_change else None
                ),
                "new_symbol": _symbol_ref(
                    symbols.get(symbol_change.new_symbol_id or "") if symbol_change else None
                ),
                "candidate_count": sum(
                    1 for candidate in all_candidates if candidate.symbol_change_id == symbol_change_id
                ),
            }
        )

    graph = _impact_graph_payload(
        detail,
        symbols,
        kept_paths,
        max_nodes=max_nodes,
        max_depth=max_depth,
        truncated=truncated,
    )

    return {
        "schema_version": models.SCHEMA_VERSION,
        "run_id": detail.run.run_id,
        "filters": {
            "seed": seed,
            "side": side,
            "kind": kind,
            "max_nodes": max_nodes,
            "max_depth": max_depth,
        },
        "seeds": seeds_payload,
        "nodes": [
            _symbol_ref(symbols.get(symbol_id))
            for symbol_id in node_ids
            if symbols.get(symbol_id) is not None
        ],
        "edges": list(edges_payload.values()),
        "candidates": bounded_candidates,
        "truncated": truncated,
        "graph": graph,
    }


# --------------------------------------------------------------------------
# history views
# --------------------------------------------------------------------------


def _run_summary_dict(summary: Any) -> dict[str, Any]:
    counts = getattr(summary, "counts", {}) or {}
    return {
        "run_id": summary.run_id,
        "repo_id": summary.repo_id,
        "display_name": summary.display_name,
        "repo_root": summary.repo_root,
        "branch": summary.branch,
        "detached": summary.detached,
        "mode": summary.mode,
        "endpoint_before": summary.endpoint_before,
        "endpoint_after": summary.endpoint_after,
        "started_at": summary.started_at,
        "finished_at": summary.finished_at,
        "status": summary.status,
        "summary": summary.summary,
        "counts": {
            "changes": int(counts.get("changes", 0)),
            "symbol_changes": int(counts.get("symbol_changes", 0)),
            "candidates": int(counts.get("candidates", 0)),
            "tests": int(counts.get("tests", 0)),
        },
    }


def build_history_json(
    runs: list[Any],
    total: int,
    limit: int,
    offset: int,
    next_cursor: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": models.SCHEMA_VERSION,
        "runs": [_run_summary_dict(run) for run in runs],
        "total": int(total),
        "limit": int(limit),
        "offset": int(offset),
        "next_cursor": next_cursor,
    }


def render_history_markdown(runs: list[Any], total: int, limit: int, offset: int) -> str:
    lines = ["# PatchPilot History", ""]
    if not runs:
        lines.append("No analysis runs recorded for this repository yet.")
        lines.append("")
        lines.append("Start with: `patchpilot init` (optional), then `patchpilot analyze`.")
        return "\n".join(lines) + "\n"
    lines.append("| started | run | branch | mode | changes | candidates | status |")
    lines.append("|---|---|---|---|---|---|---|")
    for run in runs:
        counts = getattr(run, "counts", {}) or {}
        lines.append(
            f"| {run.started_at} | `{run.run_id}` | {run.branch or '-'} | {run.mode} | "
            f"{counts.get('changes', 0)} | {counts.get('candidates', 0)} | {run.status} |"
        )
    lines.append("")
    shown_from = offset + 1 if runs else 0
    shown_to = offset + len(runs)
    lines.append(f"Showing {shown_from}-{shown_to} of {total}.")
    return "\n".join(lines) + "\n"


def render_history_summary(runs: list[Any], total: int, limit: int, offset: int) -> str:
    if not runs:
        return "No analysis history for this repository. Run `patchpilot analyze` first."
    lines = [f"History for this repository ({total} run(s)):"]
    for run in runs:
        counts = getattr(run, "counts", {}) or {}
        lines.append(
            f"  {run.started_at}  {run.run_id}  {run.mode:<13} "
            f"changes={counts.get('changes', 0):<3} candidates={counts.get('candidates', 0):<3} "
            f"{run.status}/{run.summary}  {run.branch or '-'}"
        )
    lines.append("")
    lines.append(f"Showing {offset + 1}-{offset + len(runs)} of {total}.")
    return "\n".join(lines)
