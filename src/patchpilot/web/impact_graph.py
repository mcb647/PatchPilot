"""Impact topology page (Cytoscape canvas + no-script path/evidence fallback).

The page is a thin view over persisted evidence only:

* graph data comes from :func:`patchpilot.reports.build_impact_api` (extended
  with ``graph.nodes/edges/positions/stats/limits``), never from the network;
* the server-rendered tree / path list / evidence tables come from the same
  persisted candidates and edges, so JavaScript is a progressive enhancement;
* Cytoscape.js is served from the bundled ``static/vendor`` copy (fixed version,
  licence included); there is no CDN, ``eval`` or ``document.write`` anywhere.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from .. import models, reports
from ..storage import Storage, StorageError

PAGE_MAX_NODES = 200
GRAPH_DEFAULT_MAX_NODES = 40
LIST_DEFAULT_MAX_NODES = 200
MAX_DEPTH = 100

_PRIVATE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
}

_EDGE_KIND_OPTIONS = (
    (models.EDGE_CALL, "调用"),
    (models.EDGE_IMPORT, "导入"),
    (models.EDGE_GLOBAL_READ, "全局读取"),
)
_SIDE_LABELS = {
    models.SIDE_BEFORE: "旧快照",
    models.SIDE_AFTER: "新快照",
    "both": "双侧",
}
_EDGE_KIND_LABELS = dict(_EDGE_KIND_OPTIONS)
_RESOLUTION_LABELS = {"resolved": "已解析", "unresolved": "未解析"}
_SYMBOL_CHANGE_KIND_LABELS = {
    models.SYMCHANGE_ADDED: "新增",
    models.SYMCHANGE_REMOVED: "删除",
    models.SYMCHANGE_MODIFIED: "修改",
    models.SYMCHANGE_RENAMED: "重命名",
}


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def _private(response: Any) -> Any:
    for header, value in _PRIVATE_HEADERS.items():
        response.headers[header] = value
    return response


def _render(
    request: Any,
    templates: Any,
    template_name: str,
    context: dict[str, Any],
    *,
    status_code: int = 200,
    m1_enabled: bool = False,
) -> Any:
    merged = dict(context)
    merged.setdefault("request", request)
    merged["m1_enabled"] = bool(merged.get("m1_enabled", m1_enabled))
    response = templates.TemplateResponse(
        request, template_name, merged, status_code=status_code
    )
    return _private(response)


def _not_found(
    request: Any,
    templates: Any,
    *,
    m1_enabled: bool,
    message: str = "未找到该 Run。",
) -> Any:
    return _render(
        request,
        templates,
        "404.html",
        {"message": message},
        status_code=404,
        m1_enabled=m1_enabled,
    )


def _bad_request(message: str) -> Any:
    from starlette.responses import PlainTextResponse

    return _private(PlainTextResponse(f"错误请求：{message}", status_code=400))


def _clean(raw: str | None) -> str | None:
    value = (raw or "").strip()
    return value or None


def _parse_int(
    name: str, raw: str | None, default: int | None, minimum: int, maximum: int
) -> int | None:
    if raw is None or not str(raw).strip():
        return default
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        raise ValueError(f"{name} 必须是 {minimum} 到 {maximum} 之间的整数") from None
    if value < minimum or value > maximum:
        raise ValueError(f"{name} 必须在 {minimum} 到 {maximum} 范围内")
    return value


def _load_detail(db_path: Path, repo_id: str | None, run_id: str) -> Any | None:
    if not models.is_valid_run_id(run_id):
        return None
    store = Storage(Path(db_path), read_only=True)
    try:
        detail = store.load_run(run_id)
    except StorageError:
        return None
    finally:
        store.close()
    if repo_id is not None and detail.run.repo_id != repo_id:
        return None
    return detail


def _label(mapping: dict[str, str], value: str | None, default: str = "-") -> str:
    if not value:
        return default
    return mapping.get(value, value)


# --------------------------------------------------------------------------
# query parsing / seed selection
# --------------------------------------------------------------------------


def _parse_query(request: Any, detail: Any, default_graph_max: int) -> dict[str, Any]:
    params = request.query_params
    symbol_changes = {
        change.symbol_change_id: change
        for change in getattr(detail, "symbol_changes", []) or []
    }

    seed_given = "seed" in params
    raw_seed = _clean(params.get("seed"))
    if raw_seed is not None and raw_seed not in symbol_changes:
        raise ValueError("seed 必须是该 Run 中存在的符号变更 ID")

    side = _clean(params.get("side"))
    if side is not None and side not in models.SIDES:
        raise ValueError("side 只能为 before 或 after")

    kind = _clean(params.get("kind"))
    if kind is not None and kind not in _EDGE_KIND_LABELS:
        raise ValueError("kind 只能为 call、import 或 global_read")

    depth = _parse_int("depth", params.get("depth"), None, 1, MAX_DEPTH)

    view = (_clean(params.get("view")) or "graph").lower()
    if view not in ("graph", "list"):
        raise ValueError("view 只能为 graph 或 list")

    # The canvas defaults to the documented "two hops / 40 nodes" view; the
    # path-list view is not depth-capped unless the user asks for it.
    depth_defaulted = depth is None and view == "graph"
    graph_depth = depth if depth is not None else (2 if view == "graph" else None)

    default_max = default_graph_max if view == "graph" else LIST_DEFAULT_MAX_NODES
    max_nodes = _parse_int(
        "max_nodes", params.get("max_nodes"), default_max, 1, PAGE_MAX_NODES
    )
    if max_nodes is None:  # pragma: no cover - default is always an int here
        max_nodes = default_max

    return {
        "seed_given": seed_given,
        "raw_seed": raw_seed,
        "side": side,
        "kind": kind,
        "depth": depth,
        "graph_depth": graph_depth,
        "depth_defaulted": depth_defaulted,
        "view": view,
        "max_nodes": int(max_nodes),
        "symbol_changes": symbol_changes,
    }


def _locatable(symbol: models.Symbol | None) -> bool:
    return (
        symbol is not None
        and bool(getattr(symbol, "path", ""))
        and getattr(symbol, "def_line", None) is not None
    )


def _select_seed(
    detail: Any, query: dict[str, Any]
) -> tuple[str | None, str | None, dict[str, int]]:
    """Return ``(graph_seed, graph_side, candidate_counts)``.

    Default: prefer a symbol change whose *after* symbol is locatable, has
    after-side candidates and has candidates matching the active side/kind/depth
    filters; otherwise fall back to a locatable before symbol (the page then
    marks "仅旧侧证据").  An explicit ``seed=`` wins; an explicit empty
    ``seed=`` means "all seeds".
    """

    symbols = getattr(detail, "symbols", None) or {}
    candidates = list(getattr(detail, "candidates", []) or [])
    edges_by_id = {edge.edge_id: edge for edge in getattr(detail, "edges", []) or []}
    symbol_changes = sorted(
        getattr(detail, "symbol_changes", []) or [],
        key=lambda change: change.symbol_change_id,
    )
    counts = {
        change.symbol_change_id: sum(
            1 for candidate in candidates if candidate.symbol_change_id == change.symbol_change_id
        )
        for change in symbol_changes
    }

    def matches(candidate: Any) -> bool:
        if query["side"] is not None and candidate.side != query["side"]:
            return False
        if query["graph_depth"] is not None and int(candidate.min_depth) > query["graph_depth"]:
            return False
        if query["kind"] is not None:
            kinds = {
                edges_by_id[edge_id].edge_kind
                for edge_id in candidate.edge_ids
                if edge_id in edges_by_id
            }
            if query["kind"] not in kinds:
                return False
        return True

    eligible = [candidate for candidate in candidates if matches(candidate)]

    def count(seed: str, side: str | None = None) -> int:
        return sum(
            1
            for candidate in eligible
            if candidate.symbol_change_id == seed
            and (side is None or candidate.side == side)
        )

    if query["seed_given"]:
        seed = query["raw_seed"]
        if seed is None:
            return None, query["side"], counts
        change = query["symbol_changes"][seed]
        after = symbols.get(change.new_symbol_id or "")
        before = symbols.get(change.old_symbol_id or "")
        side = query["side"]
        if side is None:
            if _locatable(after) and count(seed, models.SIDE_AFTER):
                side = models.SIDE_AFTER
            elif _locatable(before) and count(seed, models.SIDE_BEFORE):
                side = models.SIDE_BEFORE
        return seed, side, counts

    preferred = query["side"] or models.SIDE_AFTER
    fallback_after = None
    fallback_before = None
    for change in symbol_changes:
        seed = change.symbol_change_id
        after = symbols.get(change.new_symbol_id or "")
        before = symbols.get(change.old_symbol_id or "")
        if (
            _locatable(after)
            and count(seed, models.SIDE_AFTER)
            and fallback_after is None
        ):
            fallback_after = seed
        if (
            _locatable(before)
            and count(seed, models.SIDE_BEFORE)
            and fallback_before is None
        ):
            fallback_before = seed
    if preferred == models.SIDE_AFTER and fallback_after is not None:
        return fallback_after, models.SIDE_AFTER, counts
    if preferred == models.SIDE_BEFORE and fallback_before is not None:
        return fallback_before, models.SIDE_BEFORE, counts
    if fallback_after is not None:
        return fallback_after, models.SIDE_AFTER, counts
    if fallback_before is not None:
        return fallback_before, models.SIDE_BEFORE, counts
    for change in symbol_changes:
        if count(change.symbol_change_id):
            return change.symbol_change_id, query["side"], counts
    if symbol_changes:
        return symbol_changes[0].symbol_change_id, query["side"], counts
    return None, query["side"], counts


def _seed_entries(detail: Any, counts: dict[str, int]) -> list[dict[str, Any]]:
    symbols = getattr(detail, "symbols", None) or {}
    candidates = list(getattr(detail, "candidates", []) or [])
    entries = []
    for change in sorted(
        getattr(detail, "symbol_changes", []) or [],
        key=lambda item: item.symbol_change_id,
    ):
        after = symbols.get(change.new_symbol_id or "")
        before = symbols.get(change.old_symbol_id or "")
        symbol = after if _locatable(after) else before
        display_name = (
            symbol.display_name
            if symbol is not None
            else (change.new_symbol_id or change.old_symbol_id or change.symbol_change_id)
        )
        path = getattr(symbol, "path", None) or "-"
        candidate_count = counts.get(change.symbol_change_id, 0)
        after_locatable = _locatable(after)
        before_locatable = _locatable(before)
        side_hint = ""
        if after_locatable and any(
            candidate.side == models.SIDE_AFTER
            for candidate in candidates
            if candidate.symbol_change_id == change.symbol_change_id
        ):
            side_hint = "新快照"
        elif before_locatable and any(
            candidate.side == models.SIDE_BEFORE
            for candidate in candidates
            if candidate.symbol_change_id == change.symbol_change_id
        ):
            side_hint = "仅旧侧"
        entries.append(
            {
                "symbol_change_id": change.symbol_change_id,
                "display_name": display_name,
                "path": path,
                "candidate_count": candidate_count,
                "side_hint": side_hint,
                "kind": change.kind,
                "kind_label": _label(_SYMBOL_CHANGE_KIND_LABELS, change.kind),
                "search_label": (
                    f"{display_name} · {path} · {candidate_count} 个候选"
                    + (f" · {side_hint}" if side_hint else "")
                    + f" · {change.symbol_change_id}"
                ),
            }
        )
    return entries


# --------------------------------------------------------------------------
# view-model builders
# --------------------------------------------------------------------------


def _related_tests(candidate_ids: list[str], tests_map: dict[str, list[dict]]) -> list[dict]:
    seen: dict[tuple[str, str], dict] = {}
    for candidate_id in candidate_ids:
        for item in tests_map.get(candidate_id, []):
            key = (item.get("test_path", ""), item.get("qualified_name") or "")
            seen.setdefault(key, item)
    return [seen[key] for key in sorted(seen)]


def _related_judge(candidate_ids: list[str], judge_map: dict[str, dict]) -> list[dict]:
    rows = []
    for candidate_id in candidate_ids:
        verdict = judge_map.get(candidate_id)
        if verdict is not None:
            rows.append({"candidate_id": candidate_id, **verdict})
    return rows


def _shortlist(detail: Any, payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Candidates on the current graph page, grouped per seed, directed/readable."""

    seeds = {
        seed.get("symbol_change_id"): seed for seed in payload.get("seeds", [])
    }
    graph = payload.get("graph", {})
    evidence = graph.get("evidence", {})
    tests_map = evidence.get("candidate_tests", {}) or {}
    judge_map = evidence.get("candidate_judge", {}) or {}

    groups: dict[str, dict[str, Any]] = {}
    for candidate in payload.get("candidates", []):
        seed_id = candidate.get("symbol_change_id")
        seed = seeds.get(seed_id) or {}
        seed_ref = seed.get("new_symbol") or seed.get("old_symbol") or {}
        seed_label = seed_ref.get("display_name") or (candidate.get("seed") or {}).get(
            "display_name"
        ) or candidate.get("seed", {}).get("symbol_id", "")
        edges = []
        for edge in candidate.get("path", []):
            caller = edge.get("caller") or {}
            callee = edge.get("callee") or {}
            resolution = edge.get("decision") or edge.get("resolution")
            edges.append(
                {
                    "caller_label": caller.get("display_name") or edge.get("caller_id") or "?",
                    "callee_label": callee.get("display_name")
                    or edge.get("target")
                    or edge.get("callee_id")
                    or "(未知目标)",
                    "edge_kind": edge.get("edge_kind"),
                    "edge_kind_label": _label(_EDGE_KIND_LABELS, edge.get("edge_kind")),
                    "side": edge.get("side"),
                    "side_label": _label(_SIDE_LABELS, edge.get("side")),
                    "resolution_label": _label(_RESOLUTION_LABELS, resolution),
                    "reason": edge.get("reason"),
                    "location": f"{edge.get('path')}:{edge.get('line')}",
                }
            )
        if edges:
            chain_names = [edge["caller_label"] for edge in reversed(edges)] + [seed_label]
            chain = " → ".join(chain_names)
        else:
            chain = f"{seed_label}（无已解析路径）"
        candidate_label = (candidate.get("candidate") or {}).get("display_name") or candidate.get(
            "candidate_symbol_id", ""
        )
        missing_edges = max(
            0,
            len(candidate.get("edge_ids", [])) - len(candidate.get("path", [])),
        )
        group = groups.setdefault(
            seed_id,
            {
                "symbol_change_id": seed_id,
                "seed_label": seed_label,
                "seed_path": seed_ref.get("path") or "-",
                "kind_label": _label(
                    _SYMBOL_CHANGE_KIND_LABELS, seed.get("kind")
                ),
                "candidate_count": seed.get("candidate_count", 0),
                "candidates": [],
            },
        )
        group["candidates"].append(
            {
                "candidate_id": candidate.get("candidate_id", ""),
                "label": candidate_label,
                "chain": chain,
                "side_label": _label(_SIDE_LABELS, candidate.get("side")),
                "min_depth": candidate.get("min_depth", 0),
                "evidence": candidate.get("evidence"),
                "truncated": bool(candidate.get("truncated", False)),
                "missing_edges": missing_edges,
                "edges": edges,
                "tests": _related_tests(
                    [candidate.get("candidate_id", "")], tests_map
                ),
                "judge": _related_judge(
                    [candidate.get("candidate_id", "")], judge_map
                ),
            }
        )
    for group in groups.values():
        group["candidates"].sort(
            key=lambda item: (item["min_depth"], item["candidate_id"])
        )
    return [groups[key] for key in sorted(groups, key=lambda value: value or "")]


def _node_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    graph = payload.get("graph", {})
    evidence = graph.get("evidence", {})
    tests_map = evidence.get("candidate_tests", {}) or {}
    judge_map = evidence.get("candidate_judge", {}) or {}
    rows = []
    for node in graph.get("nodes", []):
        candidate_ids = list(node.get("candidate_ids", []))
        rows.append(
            {
                "node": node,
                "candidate_count": len(candidate_ids),
                "tests": _related_tests(candidate_ids, tests_map),
                "judge": _related_judge(candidate_ids, judge_map),
            }
        )
    return rows


def _edge_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    graph = payload.get("graph", {})
    evidence = graph.get("evidence", {})
    tests_map = evidence.get("candidate_tests", {}) or {}
    judge_map = evidence.get("candidate_judge", {}) or {}
    nodes = {node["id"]: node for node in graph.get("nodes", [])}
    rows = []
    for edge in graph.get("edges", []):
        source = nodes.get(edge.get("source"), {})
        target = nodes.get(edge.get("target"), {})
        candidate_ids = list(edge.get("candidate_ids", []))
        rows.append(
            {
                "edge": edge,
                "source_label": source.get("label") or edge.get("source", "?"),
                "target_label": target.get("label") or edge.get("target", "?"),
                "edge_kind_label": _label(_EDGE_KIND_LABELS, edge.get("edge_kind")),
                "side_label": _label(_SIDE_LABELS, edge.get("side")),
                "resolution_label": _label(_RESOLUTION_LABELS, edge.get("resolution")),
                "positions": list(edge.get("positions", [])),
                "candidate_count": len(candidate_ids),
                "tests": _related_tests(candidate_ids, tests_map),
                "judge": _related_judge(candidate_ids, judge_map),
            }
        )
    return rows


def _view_switch_url(run_id: str, filters: dict[str, Any], view: str) -> str:
    params: dict[str, str] = {"view": view}
    for key in ("seed", "side", "kind", "depth"):
        value = filters.get(key)
        if value not in (None, ""):
            params[key] = str(value)
    max_nodes = filters.get("max_nodes")
    if max_nodes not in (None, ""):
        params["max_nodes"] = str(max_nodes)
    return f"/runs/{run_id}/impact?" + urlencode(params)


def _legacy_tree(request: Any, detail: Any, query: dict[str, Any]) -> dict[str, Any]:
    """Server-rendered tree used for no-script reading and regression tests.

    ``web/app.py`` keeps the original tree builder used by the P1 page; reusing
    it guarantees the same seeds/nodes/counts/cycle markers in the fallback.
    """

    from . import app as web_app

    try:
        context = web_app._impact_page_context(
            request,
            detail,
            seed=query["raw_seed"] if query["seed_given"] else None,
            side=query["side"],
            kind=query["kind"],
            depth=query["depth"],
        )
    except Exception:  # noqa: BLE001 - the fallback list must never 500 the page
        return {
            "available": False,
            "tree": {"seeds": [], "counts": {}, "truncated": False, "node_limit": 0},
            "filters": {},
            "has_filters": False,
        }
    return {
        "available": True,
        "tree": context.get("tree", {}),
        "filters": context.get("filters", {}),
        "has_filters": context.get("has_filters", False),
    }


# --------------------------------------------------------------------------
# public entry point (wired from web/app.py)
# --------------------------------------------------------------------------


def render_impact_page(
    request: Any,
    templates: Any,
    *,
    db_path: Path,
    repo_id: str | None,
    run_id: str,
    m1_enabled: bool,
) -> Any:
    """Render the impact topology page (graph + list fallback)."""

    if not models.is_valid_run_id(run_id):
        return _not_found(request, templates, m1_enabled=m1_enabled)
    detail = _load_detail(Path(db_path), repo_id, run_id)
    if detail is None:
        return _not_found(request, templates, m1_enabled=m1_enabled)

    from . import app as web_app

    app_max = int(getattr(web_app, "IMPACT_PAGE_MAX_NODES", PAGE_MAX_NODES))
    default_graph_max = max(1, min(GRAPH_DEFAULT_MAX_NODES, app_max))
    try:
        query = _parse_query(request, detail, default_graph_max)
    except ValueError as exc:
        return _bad_request(str(exc))

    graph_seed, graph_side, candidate_counts = _select_seed(detail, query)
    symbols = getattr(detail, "symbols", None) or {}
    selected_change = query["symbol_changes"].get(graph_seed or "")
    selected_after = (
        symbols.get(selected_change.new_symbol_id or "") if selected_change else None
    )
    only_before = bool(
        graph_seed
        and graph_side == models.SIDE_BEFORE
        and selected_change is not None
        and not _locatable(selected_after)
    )

    payload = reports.build_impact_api(
        detail,
        seed=graph_seed,
        side=graph_side,
        kind=query["kind"],
        max_nodes=query["max_nodes"],
        max_depth=query["graph_depth"],
    )
    graph = payload.get("graph", {})
    analysis_truncated = any(
        bool(candidate.truncated) for candidate in getattr(detail, "candidates", []) or []
    )
    view_limit_truncated = bool(graph.get("stats", {}).get("truncated")) or bool(
        payload.get("truncated")
    )
    graph_json = json.dumps(
        graph, ensure_ascii=False, separators=(",", ":")
    )
    seed_entries = _seed_entries(detail, candidate_counts)
    selected_seed_entry = next(
        (entry for entry in seed_entries if entry["symbol_change_id"] == graph_seed),
        None,
    )
    legacy = _legacy_tree(request, detail, query)

    filter_values = {
        "seed": query["raw_seed"] or "",
        "side": query["side"] or "",
        "kind": query["kind"] or "",
        "depth": "" if query["depth"] is None else query["depth"],
        "view": query["view"],
        "max_nodes": query["max_nodes"],
    }
    context = {
        "request": request,
        "run": detail.run,
        "run_id": detail.run.run_id,
        "m1_enabled": bool(m1_enabled),
        "view": query["view"],
        "filters": filter_values,
        "view_switch_url": _view_switch_url(
            detail.run.run_id,
            filter_values,
            "list" if query["view"] == "graph" else "graph",
        ),
        "has_filters": bool(
            query["seed_given"]
            or query["side"]
            or query["kind"]
            or query["depth"] is not None
            or query["view"] != "graph"
        ),
        "seed_entries": seed_entries,
        "selected_seed": graph_seed,
        "selected_seed_entry": selected_seed_entry,
        "selected_side": graph_side,
        "selected_side_label": _label(_SIDE_LABELS, graph_side),
        "only_before": only_before,
        "side_options": [
            {"value": value, "label": label}
            for value, label in _SIDE_LABELS.items()
            if value in models.SIDES
        ],
        "kind_options": [
            {"value": value, "label": label} for value, label in _EDGE_KIND_OPTIONS
        ],
        "max_depth": MAX_DEPTH,
        "graph_depth": query["graph_depth"],
        "depth_defaulted": query["depth_defaulted"],
        "graph": graph,
        "graph_json": graph_json,
        "graph_payload": payload,
        "analysis_truncated": analysis_truncated,
        "view_limit_truncated": view_limit_truncated,
        "shortlist": _shortlist(detail, payload),
        "node_rows": _node_rows(payload),
        "edge_rows": _edge_rows(payload),
        "legacy": legacy,
        "active": "history",
    }
    return _render(
        request, templates, "impact.html", context, m1_enabled=m1_enabled
    )
