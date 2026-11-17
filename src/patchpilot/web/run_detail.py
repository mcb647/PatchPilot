"""Run detail pages: summary first, diffs and long lists on demand.

The first HTML response must stay cheap and small: it never loads or renders
diff hunks, edges or judge rows.  It renders an overview, a per-file summary
table whose rows lazily fetch their diff from ``/runs/{run_id}/changes/{id}``,
and bounded pages of candidates/tests.  ``run-detail.js`` performs the fetch and
injects only the server-rendered (auto-escaped) fragment.

Storage access uses the bounded query API from ``docs/CONTRACTS-USABILITY.md``
section 2.  ``_open_store`` is a tiny seam so tests can inject a fake; production
always opens a read-only :class:`~patchpilot.storage.Storage`.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Iterable

from .. import models
from ..storage import Storage, StorageError

#: Candidates/tests rendered per page in the run detail view.
PAGE_SIZE = 25
#: Diff hunks rendered per request inside one file (long files are paged).
HUNK_PAGE_SIZE = 10
#: Upper bound for a ``*_page`` query parameter (invalid values fall back to 1).
MAX_PAGE = 1000
#: Safety cap for folded symbol-change rows (the table is collapsed anyway).
MAX_SYMBOL_CHANGES = 200

_PRIVATE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
}

_STATUS_LABELS = {
    models.RUN_RUNNING: "运行中",
    models.RUN_COMPLETED: "已完成",
    models.RUN_PARTIAL: "部分完成",
    models.RUN_FAILED: "失败",
}
_SUMMARY_LABELS = {
    models.SUMMARY_NO_CHANGES: "无变更",
    models.SUMMARY_NO_CANDIDATES: "无候选",
    models.SUMMARY_CANDIDATES_FOUND: "发现候选",
    models.SUMMARY_UNKNOWN: "未知",
}
_MODE_LABELS = {
    models.MODE_WORKTREE_NET: "工作区净差异",
    models.MODE_STAGED: "仅暂存区",
    models.MODE_WORKING_TREE: "暂存区 → 工作区",
    models.MODE_BASE: "分支基线",
    models.MODE_COMMIT: "单提交",
    models.MODE_RANGE: "提交区间",
}
_SIDE_LABELS = {
    models.SIDE_BEFORE: "旧快照",
    models.SIDE_AFTER: "新快照",
    "both": "双侧",
}
_KIND_LABELS = {
    models.CHANGE_ADDED: "新增",
    models.CHANGE_REMOVED: "删除",
    models.CHANGE_MODIFIED: "修改",
    models.CHANGE_RENAMED: "重命名",
}
_ANALYSIS_STATUS_LABELS = {
    "analyzed": "已分析",
    "not_analyzed": "未分析",
    "failed": "分析失败",
}
_SYMBOL_KIND_LABELS = {
    models.SYMBOL_MODULE: "模块",
    models.SYMBOL_FUNCTION: "函数",
    models.SYMBOL_ASYNC_FUNCTION: "异步函数",
    models.SYMBOL_CLASS: "类",
    models.SYMBOL_METHOD: "方法",
    models.SYMBOL_NESTED_FUNCTION: "嵌套函数",
}
_SYMBOL_CHANGE_KIND_LABELS = dict(_KIND_LABELS)
_REASON_LABELS = {
    "body": "函数体",
    "signature": "签名/定义",
    "class_header": "类头部",
    "class_body": "类体",
    "module_statement": "模块级语句",
    "module_import": "模块导入",
    "module_renamed": "模块重命名",
    "file_added": "新增文件",
    "file_removed": "删除文件",
    "symbol_added": "新增符号",
    "symbol_removed": "删除符号",
    "text_only": "仅文本变化",
    "global_read": "全局变量读取",
}
_SEVERITY_LABELS = {"info": "提示", "warning": "警告", "error": "错误"}
_STRENGTH_LABELS = {
    models.TEST_STRENGTH_STRONG: "强",
    models.TEST_STRENGTH_WEAK: "弱",
}
_EVIDENCE_LABELS = {
    models.EVIDENCE_CALL: "调用路径",
    models.EVIDENCE_IMPORT: "模块导入",
    models.EVIDENCE_GLOBAL_READ: "全局变量读取",
}
_STAGE_LABELS = {
    "snapshot": "快照捕获",
    "changes": "文件差异",
    "save_changes": "保存文件差异",
    "ast_before": "构建旧快照 AST 索引",
    "ast_after": "构建新快照 AST 索引",
    "save_index": "保存符号索引",
    "symbol_changes": "符号变化映射",
    "impacts": "反向影响追踪",
    "save_impacts": "保存影响候选",
    "tests": "测试推荐",
    "save_tests": "保存测试推荐",
    "judge": "Judge 阶段",
    "save_judge": "保存 Judge 结果",
    "cache_ast": "AST 缓存",
    "cache_judge": "Judge 缓存",
}
_JUDGE_STATUS_LABELS = {
    models.JUDGE_DISABLED: "未启用",
    models.JUDGE_PENDING: "等待中",
    models.JUDGE_COMPLETED: "已完成",
    models.JUDGE_PARTIAL: "部分完成",
    models.JUDGE_FAILED: "失败",
}
_VERDICT_LABELS = {
    models.VERDICT_AFFECTED: "可能受影响",
    models.VERDICT_UNAFFECTED: "可能不受影响",
    models.VERDICT_UNCERTAIN: "证据不足",
}
_JUDGE_ADAPTER_LABELS = {
    "jev": "JEV 规则引擎",
    "llm": "LLM 模型",
    "cache": "缓存",
}
_JUDGE_ERROR_LABELS = {
    models.JUDGE_ERROR_UNAVAILABLE: "服务不可用",
    models.JUDGE_ERROR_TIMEOUT: "超时",
    models.JUDGE_ERROR_INVALID_OUTPUT: "输出无效",
    models.JUDGE_ERROR_RATE_LIMITED: "限流",
    models.JUDGE_ERROR_AUTH: "鉴权失败",
    models.JUDGE_ERROR_BUDGET_EXHAUSTED: "预算耗尽",
    models.JUDGE_ERROR_NOT_CONFIGURED: "未配置",
    models.JUDGE_ERROR_CONTEXT_INSUFFICIENT: "上下文不足",
    models.JUDGE_ERROR_SECRET_REDACTED: "敏感内容已脱敏",
}
_TASK_STATUS_LABELS = {
    models.TASK_QUEUED: "排队中",
    models.TASK_RUNNING: "执行中",
    models.TASK_COMPLETED: "已完成",
    models.TASK_PARTIAL: "部分完成",
    models.TASK_FAILED: "失败",
    models.TASK_CANCELLED: "已取消",
    models.TASK_INTERRUPTED: "已中断",
}

#: Diagnostic codes that mean the static analysis missed part of the picture.
_COVERAGE_GAP_CODES = {
    "diff_limit",
    "side_unavailable",
    "symbol_mapping_unknown",
    "object_missing",
    "python_limit",
    "edge_limit",
    "snapshot_changed",
}


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def _label(mapping: dict[str, str], value: str | None, default: str = "-") -> str:
    if not value:
        return default
    return mapping.get(value, value)


def _open_store(db_path: Path) -> Storage:
    """Open the read-only history database (test seam for fake stores)."""

    return Storage(Path(db_path), read_only=True)


def _parse_page(raw: str | None) -> int:
    """Parse one ``*_page`` parameter; invalid values fall back to page 1."""

    if raw is None or not str(raw).strip():
        return 1
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return 1
    if value < 1 or value > MAX_PAGE:
        return 1
    return value


def _truthy(raw: str | None) -> bool:
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on"}


def _branch_label(run: Any) -> str:
    if getattr(run, "branch", None):
        return str(run.branch)
    return "(分离 HEAD)" if getattr(run, "detached", False) else "-"


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


def _symbol_view(symbol: Any) -> dict[str, Any] | None:
    if symbol is None:
        return None
    return {
        "symbol_id": getattr(symbol, "symbol_id", ""),
        "display_name": getattr(symbol, "display_name", ""),
        "path": getattr(symbol, "path", None),
        "def_line": getattr(symbol, "def_line", None),
        "kind": getattr(symbol, "kind", None),
        "kind_label": _label(_SYMBOL_KIND_LABELS, getattr(symbol, "kind", None)),
        "side": getattr(symbol, "side", None),
        "side_label": _label(_SIDE_LABELS, getattr(symbol, "side", None)),
        "is_test": bool(getattr(symbol, "is_test", False)),
        "missing": False,
    }


def _diagnostic_view(diagnostic: Any, source: str = "") -> dict[str, Any]:
    if isinstance(diagnostic, dict):
        data = dict(diagnostic)
    else:
        data = diagnostic.to_dict() if hasattr(diagnostic, "to_dict") else {}
    details = data.get("details")
    if details in (None, {}, []):
        details_text = ""
    else:
        text = str(details)
        details_text = text[:500] + ("…" if len(text) > 500 else "")
    return {
        "code": data.get("code", ""),
        "message": data.get("message", ""),
        "severity": data.get("severity", "warning"),
        "severity_label": _label(_SEVERITY_LABELS, data.get("severity", "warning")),
        "path": data.get("path"),
        "line": data.get("line"),
        "details_text": details_text,
        "source": source,
    }


def _pagination(
    page: int,
    total: int,
    *,
    parameter: str,
    other_parameter: str,
    other_page: int,
    anchor: str,
    extra_params: dict[str, str] | None = None,
) -> dict[str, Any]:
    total_pages = max(1, math.ceil(total / PAGE_SIZE)) if total else 1
    page = min(max(1, page), total_pages)

    def url(target: int) -> str:
        query = [f"{parameter}={target}"]
        if other_page and other_page != 1:
            query.append(f"{other_parameter}={other_page}")
        for key, value in (extra_params or {}).items():
            if value:
                query.append(f"{key}={value}")
        return "?" + "&".join(query) + "#" + anchor

    start = max(1, page - 3)
    end = min(total_pages, start + 6)
    start = max(1, end - 6)
    pages = [
        {"number": number, "url": url(number), "active": number == page}
        for number in range(start, end + 1)
    ]
    return {
        "page": page,
        "total": total,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_url": url(page - 1) if page > 1 else None,
        "next_url": url(page + 1) if page < total_pages else None,
        "pages": pages,
        "show_first": start > 1,
        "first_url": url(1),
        "show_last": end < total_pages,
        "last_url": url(total_pages),
        "shown_from": (page - 1) * PAGE_SIZE + 1 if total else 0,
        "shown_to": min(page * PAGE_SIZE, total),
    }


# --------------------------------------------------------------------------
# run page context
# --------------------------------------------------------------------------


def _change_summary_view(summary: Any, run_id: str) -> dict[str, Any]:
    change_id = getattr(summary, "change_id", "")
    old_path = getattr(summary, "old_path", None)
    new_path = getattr(summary, "new_path", None)
    if old_path and new_path and old_path != new_path:
        display_path = f"{old_path} → {new_path}"
    else:
        display_path = new_path or old_path or ""
    has_hunks = bool(getattr(summary, "has_hunks", False))
    analysis_status = getattr(summary, "analysis_status", "")
    if analysis_status != "analyzed":
        evidence_label = "未分析"
    elif getattr(summary, "diff_truncated", False):
        evidence_label = "差异已截断"
    elif not has_hunks:
        evidence_label = "无 hunk 正文"
    else:
        evidence_label = "按需加载"
    return {
        "change_id": change_id,
        "old_path": old_path,
        "new_path": new_path,
        "display_path": display_path,
        "kind": getattr(summary, "kind", ""),
        "kind_label": _label(_KIND_LABELS, getattr(summary, "kind", "")),
        "analysis_status": analysis_status,
        "analysis_status_label": _label(_ANALYSIS_STATUS_LABELS, analysis_status),
        "old_changed_lines": int(getattr(summary, "old_changed_lines", 0) or 0),
        "new_changed_lines": int(getattr(summary, "new_changed_lines", 0) or 0),
        "diff_truncated": bool(getattr(summary, "diff_truncated", False)),
        "has_hunks": has_hunks,
        "symbol_change_count": int(getattr(summary, "symbol_change_count", 0) or 0),
        "evidence_label": evidence_label,
        "fragment_url": f"/runs/{run_id}/changes/{change_id}?fragment=1",
        "page_url": f"/runs/{run_id}/changes/{change_id}",
    }


def _coverage_view(
    overview: Any,
    summaries: list[Any],
    diagnostics: list[Any] | None = None,
) -> dict[str, Any]:
    diagnostics = (
        list(diagnostics)
        if diagnostics is not None
        else list(getattr(overview, "diagnostics", None) or [])
    )
    severities = {"info": 0, "warning": 0, "error": 0}
    for diagnostic in diagnostics:
        severity = getattr(diagnostic, "severity", "warning")
        severities[severity] = severities.get(severity, 0) + 1
    stage_errors = [str(item) for item in getattr(overview, "stage_errors", None) or []]
    unanalyzed = sum(
        1 for summary in summaries if getattr(summary, "analysis_status", "") != "analyzed"
    )
    diff_truncated = sum(1 for summary in summaries if getattr(summary, "diff_truncated", False))
    gap_code_count = sum(
        1
        for diagnostic in diagnostics
        if getattr(diagnostic, "code", "") in _COVERAGE_GAP_CODES
    )
    items: list[dict[str, Any]] = []

    def add(label: str, count: int) -> None:
        if count:
            items.append({"label": label, "count": count})

    add("诊断错误", severities.get("error", 0))
    add("失败阶段", len(stage_errors))
    add("未分析文件", unanalyzed)
    add("差异被截断", diff_truncated)
    add("诊断警告", severities.get("warning", 0))
    add("覆盖缺口诊断", gap_code_count)
    if getattr(overview, "truncated", False):
        add("结果被截断", 1)
    has_gap = bool(items)
    if has_gap:
        summary = "覆盖缺口：" + "、".join(
            f"{item['label']} {item['count']}" for item in items
        ) + "；相关结论的证据可能不完整。"
    else:
        summary = "未发现明显覆盖缺口（无错误诊断、无未分析文件、无截断标记）。"
    return {
        "has_gap": has_gap,
        "gap_items": items,
        "summary": summary,
        "error_count": severities.get("error", 0),
        "warning_count": severities.get("warning", 0),
        "info_count": severities.get("info", 0),
        "stage_errors": stage_errors,
    }


def _stage_views(overview: Any, metrics: dict[str, Any]) -> list[dict[str, Any]]:
    raw_stages = getattr(overview, "stages", None)
    if not isinstance(raw_stages, dict):
        raw_stages = metrics.get("stages") if isinstance(metrics.get("stages"), dict) else {}
    stages = []
    for name, duration in (raw_stages or {}).items():
        stages.append(
            {
                "name": str(name),
                "label": _label(_STAGE_LABELS, str(name)),
                "duration_ms": duration,
            }
        )
    return stages


_JUDGE_EVIDENCE_KIND_LABELS = {
    "hunk": "差异片段",
    "symbol": "符号",
    "call_site": "调用点",
    "test": "测试",
    "source": "源码",
}


def _judge_attempt_sequence(attempts: list[Any]) -> str:
    if not attempts:
        return "-"
    parts = []
    for attempt in sorted(
        attempts, key=lambda item: int(getattr(item, "attempt_no", 0) or 0)
    ):
        adapter = _label(
            _JUDGE_ADAPTER_LABELS,
            getattr(attempt, "adapter", None),
            str(getattr(attempt, "adapter", "") or "-"),
        )
        number = int(getattr(attempt, "attempt_no", 0) or 0)
        parts.append(f"#{number} {adapter}")
    return " → ".join(parts)


def _judge_verdict_view(verdict: Any, attempts: list[Any]) -> dict[str, Any]:
    candidate_id = str(getattr(verdict, "candidate_id", "") or "")
    evidence = []
    for item in getattr(verdict, "evidence", None) or ():
        data = item if isinstance(item, dict) else {}
        kind = str(data.get("kind", "") or "")
        evidence.append(
            {
                "path": str(data.get("path", "") or "-"),
                "start_line": data.get("start_line"),
                "end_line": data.get("end_line"),
                "side": str(data.get("side", "") or ""),
                "side_label": _label(_SIDE_LABELS, data.get("side")),
                "kind": kind,
                "kind_label": _label(_JUDGE_EVIDENCE_KIND_LABELS, kind, kind or "-"),
                "evidence_id": data.get("evidence_id"),
            }
        )
    candidate_attempts = [
        attempt
        for attempt in attempts
        if str(getattr(attempt, "candidate_id", "") or "") == candidate_id
    ]
    fallback_events = []
    for attempt in sorted(
        candidate_attempts, key=lambda item: int(getattr(item, "attempt_no", 0) or 0)
    ):
        reason = getattr(attempt, "fallback_reason", None)
        if not reason:
            continue
        fallback_events.append(
            {
                "attempt_no": int(getattr(attempt, "attempt_no", 0) or 0),
                "reason": str(reason),
                "label": _label(_JUDGE_ERROR_LABELS, reason, str(reason)),
            }
        )
    return {
        "candidate_id": candidate_id,
        "verdict": getattr(verdict, "verdict", ""),
        "verdict_label": _label(
            _VERDICT_LABELS, getattr(verdict, "verdict", ""), "未判定"
        ),
        "reason": getattr(verdict, "reason", "") or "",
        "adapter": getattr(verdict, "adapter", ""),
        "adapter_label": _label(
            _JUDGE_ADAPTER_LABELS,
            getattr(verdict, "adapter", None),
            str(getattr(verdict, "adapter", "") or "-"),
        ),
        "model": getattr(verdict, "model", None),
        "attempt_no": int(getattr(verdict, "attempt_no", 0) or 0),
        "evidence": evidence,
        "conditions": [str(item) for item in (getattr(verdict, "conditions", None) or ())],
        "uncertainty": getattr(verdict, "uncertainty", None),
        "attempt_sequence": _judge_attempt_sequence(candidate_attempts),
        "attempts": [
            {
                "attempt_no": int(getattr(attempt, "attempt_no", 0) or 0),
                "adapter": getattr(attempt, "adapter", ""),
                "adapter_label": _label(
                    _JUDGE_ADAPTER_LABELS,
                    getattr(attempt, "adapter", None),
                    str(getattr(attempt, "adapter", "") or "-"),
                ),
                "model": getattr(attempt, "model", None),
                "valid": bool(getattr(attempt, "valid", False)),
                "cache_hit": bool(getattr(attempt, "cache_hit", False)),
                "error_category": getattr(attempt, "error_category", None),
                "error_label": _label(
                    _JUDGE_ERROR_LABELS,
                    getattr(attempt, "error_category", None),
                    str(getattr(attempt, "error_category", "") or "-"),
                ),
                "fallback_reason": getattr(attempt, "fallback_reason", None),
                "fallback_label": _label(
                    _JUDGE_ERROR_LABELS,
                    getattr(attempt, "fallback_reason", None),
                    str(getattr(attempt, "fallback_reason", "") or "-"),
                ),
                "duration_ms": int(getattr(attempt, "duration_ms", 0) or 0),
                "context_tokens_estimate": int(
                    getattr(attempt, "context_tokens_estimate", 0) or 0
                ),
            }
            for attempt in sorted(
                candidate_attempts,
                key=lambda item: int(getattr(item, "attempt_no", 0) or 0),
            )
        ],
        "fallback_events": fallback_events,
    }


def _judge_view(
    overview: Any,
    run: Any,
    *,
    verdicts: list[Any] | tuple[Any, ...] = (),
    attempts: list[Any] | tuple[Any, ...] = (),
) -> dict[str, Any] | None:
    attempts_count = int(getattr(overview, "judge_attempts_count", 0) or 0)
    verdicts_count = int(getattr(overview, "judge_verdicts_count", 0) or 0)
    counts = getattr(overview, "judge_counts", None) or {}
    metrics = run.metrics if isinstance(getattr(run, "metrics", None), dict) else {}
    judge_metrics = metrics.get("judge") if isinstance(metrics.get("judge"), dict) else {}
    requested = bool(judge_metrics.get("requested"))
    status = judge_metrics.get("status")
    if not requested and attempts_count == 0 and verdicts_count == 0:
        return None
    verdict_counts = [
        {
            "code": verdict,
            "label": _label(_VERDICT_LABELS, verdict),
            "count": int(counts.get(verdict, 0) or 0),
        }
        for verdict in models.VERDICTS
        if counts.get(verdict)
    ]
    counts_all = getattr(overview, "counts", None)
    candidate_total = int(counts_all.get("candidates", 0) or 0) if isinstance(counts_all, dict) else 0
    verdict_rows = [
        _judge_verdict_view(verdict, list(attempts)) for verdict in verdicts
    ]
    judged_ids = {row["candidate_id"] for row in verdict_rows}
    unjudged_attempts = []
    for attempt in sorted(
        attempts, key=lambda item: (str(getattr(item, "candidate_id", "")), int(getattr(item, "attempt_no", 0) or 0))
    ):
        candidate_id = str(getattr(attempt, "candidate_id", "") or "")
        if candidate_id in judged_ids:
            continue
        unjudged_attempts.append(
            {
                "candidate_id": candidate_id,
                "attempt_no": int(getattr(attempt, "attempt_no", 0) or 0),
                "adapter": getattr(attempt, "adapter", ""),
                "adapter_label": _label(
                    _JUDGE_ADAPTER_LABELS,
                    getattr(attempt, "adapter", None),
                    str(getattr(attempt, "adapter", "") or "-"),
                ),
                "model": getattr(attempt, "model", None),
                "valid": bool(getattr(attempt, "valid", False)),
                "cache_hit": bool(getattr(attempt, "cache_hit", False)),
                "error_category": getattr(attempt, "error_category", None),
                "error_label": _label(
                    _JUDGE_ERROR_LABELS,
                    getattr(attempt, "error_category", None),
                    str(getattr(attempt, "error_category", "") or "-"),
                ),
                "fallback_reason": getattr(attempt, "fallback_reason", None),
                "fallback_label": _label(
                    _JUDGE_ERROR_LABELS,
                    getattr(attempt, "fallback_reason", None),
                    str(getattr(attempt, "fallback_reason", "") or "-"),
                ),
                "duration_ms": int(getattr(attempt, "duration_ms", 0) or 0),
                "context_tokens_estimate": int(
                    getattr(attempt, "context_tokens_estimate", 0) or 0
                ),
            }
        )
    return {
        "requested": requested,
        "status": status,
        "status_label": _label(_JUDGE_STATUS_LABELS, status, "未判定" if status is None else str(status)),
        "attempts_count": attempts_count,
        "verdicts_count": verdicts_count,
        "verdict_counts": verdict_counts,
        "verdicts": verdict_rows,
        "verdicts_shown": len(verdict_rows),
        "unjudged_attempts": unjudged_attempts,
        "unjudged": max(0, candidate_total - verdicts_count),
        "cache_hits": int(getattr(overview, "judge_cache_hits", 0) or 0),
    }


def _task_view(store: Any, overview: Any, m1_enabled: bool) -> dict[str, Any] | None:
    task_id = getattr(overview, "task_id", None)
    if not task_id:
        return None
    task = None
    try:
        task = store.get_task(task_id)
    except Exception:  # noqa: BLE001 - a missing task row only weakens the hint
        task = None
    if task is None:
        return {
            "task_id": task_id,
            "found": False,
            "link": None,
            "mode_label": None,
            "params_summary": None,
            "status": None,
            "status_label": None,
            "judge": False,
        }
    params = getattr(task, "request", None)
    parts: list[str] = []
    mode = getattr(task, "mode", None)
    if mode:
        parts.append(_label(_MODE_LABELS, mode, str(mode)))
    if isinstance(params, dict):
        for field, label in (
            ("base_ref", "基线"),
            ("commit_ref", "提交"),
            ("range_spec", "区间"),
            ("parent_index", "父提交"),
        ):
            value = params.get(field)
            if value:
                parts.append(f"{label} {value}")
    if getattr(task, "judge", False):
        parts.append("Judge 开启")
    status = getattr(task, "status", None)
    return {
        "task_id": task_id,
        "found": True,
        "link": f"/tasks/{task_id}" if m1_enabled else None,
        "mode_label": _label(_MODE_LABELS, mode, str(mode or "-")),
        "params_summary": " · ".join(parts),
        "status": status,
        "status_label": _label(_TASK_STATUS_LABELS, status, str(status or "-")),
        "judge": bool(getattr(task, "judge", False)),
    }


def _candidate_view(candidate: Any, symbols: dict[str, Any]) -> dict[str, Any]:
    candidate_symbol = symbols.get(getattr(candidate, "candidate_symbol_id", ""))
    seed_symbol = symbols.get(getattr(candidate, "seed_symbol_id", ""))
    return {
        "candidate_id": getattr(candidate, "candidate_id", ""),
        "symbol_change_id": getattr(candidate, "symbol_change_id", ""),
        "side": getattr(candidate, "side", ""),
        "side_label": _label(_SIDE_LABELS, getattr(candidate, "side", "")),
        "min_depth": int(getattr(candidate, "min_depth", 0) or 0),
        "evidence": getattr(candidate, "evidence", ""),
        "evidence_label": _label(_EVIDENCE_LABELS, getattr(candidate, "evidence", "")),
        "truncated": bool(getattr(candidate, "truncated", False)),
        "candidate": _symbol_view(candidate_symbol),
        "candidate_symbol_id": getattr(candidate, "candidate_symbol_id", ""),
        "seed": _symbol_view(seed_symbol),
        "seed_symbol_id": getattr(candidate, "seed_symbol_id", ""),
    }


def _symbol_change_view(symbol_change: Any, symbols: dict[str, Any]) -> dict[str, Any]:
    return {
        "symbol_change_id": getattr(symbol_change, "symbol_change_id", ""),
        "change_id": getattr(symbol_change, "change_id", ""),
        "kind": getattr(symbol_change, "kind", ""),
        "kind_label": _label(_SYMBOL_CHANGE_KIND_LABELS, getattr(symbol_change, "kind", "")),
        "reason": getattr(symbol_change, "reason", ""),
        "reason_label": _label(_REASON_LABELS, getattr(symbol_change, "reason", "")),
        "side": getattr(symbol_change, "side", ""),
        "side_label": _label(_SIDE_LABELS, getattr(symbol_change, "side", "")),
        "structure_changed": bool(getattr(symbol_change, "structure_changed", False)),
        "old": _symbol_view(symbols.get(getattr(symbol_change, "old_symbol_id", "") or "")),
        "new": _symbol_view(symbols.get(getattr(symbol_change, "new_symbol_id", "") or "")),
        "old_changed_lines": len(getattr(symbol_change, "old_changed_lines", None) or []),
        "new_changed_lines": len(getattr(symbol_change, "new_changed_lines", None) or []),
    }


def _test_view(recommendation: Any) -> dict[str, Any]:
    path = getattr(recommendation, "test_path", "")
    qualified_name = getattr(recommendation, "qualified_name", None)
    reference = f"{path}::{qualified_name}" if qualified_name else path
    return {
        "test_path": path,
        "qualified_name": qualified_name,
        "reference": reference,
        "strength": getattr(recommendation, "strength", ""),
        "strength_label": _label(_STRENGTH_LABELS, getattr(recommendation, "strength", "")),
        "side": getattr(recommendation, "side", ""),
        "side_label": _label(_SIDE_LABELS, getattr(recommendation, "side", "")),
        "min_depth": int(getattr(recommendation, "min_depth", 0) or 0),
        "exists_in_after": bool(getattr(recommendation, "exists_in_after", True)),
        "evidence": getattr(recommendation, "evidence", "") or "",
        "candidate_count": len(getattr(recommendation, "candidate_ids", None) or []),
    }


def _fetch_candidate_page(
    store: Any, run_id: str, page: int
) -> tuple[list[Any], int, int]:
    rows, total = store.list_candidates_page(
        run_id, limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE
    )
    total = int(total or 0)
    total_pages = max(1, math.ceil(total / PAGE_SIZE)) if total else 1
    if page > total_pages:
        page = total_pages
        rows, total = store.list_candidates_page(
            run_id, limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE
        )
        total = int(total or 0)
    return list(rows or ()), total, page


def _fetch_test_page(store: Any, run_id: str, page: int) -> tuple[list[Any], int, int]:
    rows, total = store.list_tests_page(
        run_id, limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE
    )
    total = int(total or 0)
    total_pages = max(1, math.ceil(total / PAGE_SIZE)) if total else 1
    if page > total_pages:
        page = total_pages
        rows, total = store.list_tests_page(
            run_id, limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE
        )
        total = int(total or 0)
    return list(rows or ()), total, page


def _run_context(
    store: Any,
    request: Any,
    overview: Any,
    *,
    impact_page: int,
    tests_page: int,
    m1_enabled: bool,
    file_query: str = "",
) -> dict[str, Any]:
    run = overview.run
    run_id = run.run_id
    metrics = run.metrics if isinstance(getattr(run, "metrics", None), dict) else {}

    symbols = store.load_symbols(run_id) or {}
    symbol_changes = list(store.load_symbol_changes(run_id) or ())
    summaries, change_total = store.list_change_summaries(run_id)
    summaries = list(summaries or ())
    change_total = int(change_total or len(summaries))

    symbol_changes_sorted = sorted(
        symbol_changes, key=lambda item: (getattr(item, "symbol_change_id", ""), getattr(item, "change_id", ""))
    )
    symbol_change_views = [
        _symbol_change_view(item, symbols) for item in symbol_changes_sorted[:MAX_SYMBOL_CHANGES]
    ]
    symbol_changes_omitted = max(0, len(symbol_changes_sorted) - MAX_SYMBOL_CHANGES)

    change_views = [_change_summary_view(summary, run_id) for summary in summaries]
    if file_query:
        needle = file_query.casefold()
        change_views = [
            view
            for view in change_views
            if needle in (view.get("display_path") or "").casefold()
        ]
        change_filtered_count = len(change_views)
    else:
        change_filtered_count = change_total

    candidate_rows, candidate_total, impact_page = _fetch_candidate_page(
        store, run_id, impact_page
    )
    test_rows, test_total, tests_page = _fetch_test_page(store, run_id, tests_page)

    judge_verdicts: list[Any] = []
    judge_attempts: list[Any] = []
    try:
        judge_verdicts, _verdict_total = store.list_judge_verdicts_page(
            run_id, limit=50
        )
        judge_attempts, _attempt_total = store.list_judge_attempts_page(
            run_id, limit=100
        )
    except Exception:  # noqa: BLE001 - older DBs without Judge tables still render
        judge_verdicts = []
        judge_attempts = []

    diagnostic_rows: list[tuple[Any, str]] = []
    try:
        diagnostic_rows = store.list_diagnostics(run_id, limit=200)
    except Exception:  # noqa: BLE001 - diagnostics are optional evidence
        diagnostic_rows = [
            (item, "运行级") for item in (getattr(overview, "diagnostics", None) or ())
        ]

    # Group the current candidate page by symbol change, preserving the
    # storage order inside each group and the symbol-change order across groups.
    candidate_views = [_candidate_view(candidate, symbols) for candidate in candidate_rows]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for candidate in candidate_views:
        grouped.setdefault(candidate["symbol_change_id"], []).append(candidate)
    impact_groups = []
    for symbol_change in symbol_changes_sorted:
        symbol_change_id = getattr(symbol_change, "symbol_change_id", "")
        group = grouped.pop(symbol_change_id, None)
        if not group:
            continue
        impact_groups.append(
            {
                "symbol_change": _symbol_change_view(symbol_change, symbols),
                "candidates": group,
            }
        )
    for symbol_change_id, group in grouped.items():
        impact_groups.append(
            {
                "symbol_change": {
                    "symbol_change_id": symbol_change_id,
                    "kind": "",
                    "kind_label": "-",
                    "reason": "",
                    "reason_label": "-",
                    "side": "",
                    "side_label": "-",
                    "structure_changed": False,
                    "old": None,
                    "new": None,
                    "old_changed_lines": 0,
                    "new_changed_lines": 0,
                },
                "candidates": group,
            }
        )

    strong_tests = [view for view in (_test_view(row) for row in test_rows) if view["strength"] != models.TEST_STRENGTH_WEAK]
    weak_tests = [view for view in (_test_view(row) for row in test_rows) if view["strength"] == models.TEST_STRENGTH_WEAK]

    stage_errors = [
        str(item) for item in (getattr(overview, "stage_errors", None) or [])
    ]
    if not stage_errors:
        raw_errors = metrics.get("stage_errors")
        if isinstance(raw_errors, list):
            stage_errors = [str(item) for item in raw_errors]

    counts = getattr(overview, "counts", None)
    if not isinstance(counts, dict):
        counts = {
            "changes": change_total,
            "symbol_changes": len(symbol_changes),
            "candidates": candidate_total,
            "tests": test_total,
        }
    scope = getattr(overview, "scope", None)
    if not isinstance(scope, dict):
        scope = {"before_files": 0, "after_files": 0, "before_python": 0, "after_python": 0}

    coverage = _coverage_view(
        overview, summaries, [item for item, _source in diagnostic_rows]
    )
    if stage_errors and not coverage["stage_errors"]:
        coverage["stage_errors"] = stage_errors
        coverage["has_gap"] = True

    return {
        "request": request,
        "run": run,
        "run_id": run_id,
        "status_label": _label(_STATUS_LABELS, run.status),
        "summary_label": _label(_SUMMARY_LABELS, run.summary),
        "mode_label": _label(_MODE_LABELS, run.mode, str(run.mode or "-")),
        "branch_label": _branch_label(run),
        "counts": counts,
        "scope": scope,
        "coverage": coverage,
        "changes": change_views,
        "change_total": change_total,
        "change_filtered_count": change_filtered_count,
        "file_query": file_query,
        "has_file_query": bool(file_query),
        "symbol_changes": symbol_change_views,
        "symbol_changes_total": len(symbol_changes_sorted),
        "symbol_changes_omitted": symbol_changes_omitted,
        "impact_groups": impact_groups,
        "impact": _pagination(
            impact_page,
            candidate_total,
            parameter="impact_page",
            other_parameter="tests_page",
            other_page=tests_page,
            anchor="impact",
            extra_params={"file_q": file_query},
        ),
        "tests_strong": strong_tests,
        "tests_weak": weak_tests,
        "tests": _pagination(
            tests_page,
            test_total,
            parameter="tests_page",
            other_parameter="impact_page",
            other_page=impact_page,
            anchor="tests",
            extra_params={"file_q": file_query},
        ),
        "diagnostics": [
            _diagnostic_view(item, source) for item, source in diagnostic_rows
        ],
        "stages": _stage_views(overview, metrics),
        "stage_errors": stage_errors,
        "metrics_truncated": bool(getattr(overview, "truncated", False)),
        "judge": _judge_view(
            overview,
            run,
            verdicts=judge_verdicts,
            attempts=judge_attempts,
        ),
        "task_source": _task_view(store, overview, m1_enabled),
        "symbols_count": len(symbols),
        "active": "history",
    }


# --------------------------------------------------------------------------
# change page
# --------------------------------------------------------------------------


def _line_kind(line: str) -> str:
    if line.startswith("+"):
        return "add"
    if line.startswith("-"):
        return "del"
    if line.startswith("\\"):
        return "meta"
    if line.startswith(" "):
        return "ctx"
    return "meta"


def _hunk_header(hunk: Any) -> str:
    return (
        f"@@ -{hunk.old_start},{hunk.old_count} "
        f"+{hunk.new_start},{hunk.new_count} @@"
    )


def _parse_hunk_page(raw: Any) -> int:
    """Parse the 1-based ``hunk_page`` query value; invalid values fall back to 1."""

    if raw is None or str(raw).strip() == "":
        return 1
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return 1
    return value if value >= 1 else 1


def _hunk_pagination(
    page: int,
    total: int,
    *,
    run_id: str,
    change_id: str,
    fragment: bool,
) -> dict[str, Any]:
    total_pages = max(1, math.ceil(total / HUNK_PAGE_SIZE)) if total else 1
    page = min(max(1, page), total_pages)
    base = f"/runs/{run_id}/changes/{change_id}"

    def page_url(target: int) -> str:
        suffix = f"?hunk_page={target}"
        if fragment:
            return base + suffix + "&fragment=1"
        return base + suffix

    def fallback_url(target: int) -> str:
        return base + f"?hunk_page={target}"

    return {
        "page": page,
        "page_size": HUNK_PAGE_SIZE,
        "total": total,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_url": page_url(page - 1) if page > 1 else None,
        "next_url": page_url(page + 1) if page < total_pages else None,
        "prev_fallback_url": fallback_url(page - 1) if page > 1 else None,
        "next_fallback_url": fallback_url(page + 1) if page < total_pages else None,
        "shown_from": (page - 1) * HUNK_PAGE_SIZE + 1 if total else 0,
        "shown_to": min(page * HUNK_PAGE_SIZE, total),
        "fragment": fragment,
    }


def _hunk_view(hunks: Iterable[Any]) -> list[dict[str, Any]]:
    views = []
    for hunk in hunks or ():
        views.append(
            {
                "header": _hunk_header(hunk),
                "lines": [
                    {"kind": _line_kind(line), "text": line}
                    for line in getattr(hunk, "lines", None) or ()
                ],
            }
        )
    return views


def _diff_view(change: Any) -> list[dict[str, Any]]:
    hunks = []
    for hunk in getattr(change, "hunks", None) or ():
        hunks.append(
            {
                "header": _hunk_header(hunk),
                "lines": [
                    {"kind": _line_kind(line), "text": line}
                    for line in getattr(hunk, "lines", None) or ()
                ],
            }
        )
    return hunks


def _change_context(
    request: Any,
    overview: Any,
    change: Any,
    summary: Any | None,
    *,
    fragment: bool,
    hunk_page: int,
    hunks: list[Any],
    hunk_total: int,
) -> dict[str, Any]:
    run = overview.run
    old_path = getattr(change, "old_path", None)
    new_path = getattr(change, "new_path", None)
    if old_path and new_path and old_path != new_path:
        display_path = f"{old_path} → {new_path}"
    else:
        display_path = new_path or old_path or ""
    diagnostics = [_diagnostic_view(item) for item in (getattr(change, "diagnostics", None) or ())]
    pagination = _hunk_pagination(
        hunk_page,
        hunk_total,
        run_id=run.run_id,
        change_id=getattr(change, "change_id", ""),
        fragment=fragment,
    )
    return {
        "request": request,
        "run": run,
        "change": change,
        "change_id": getattr(change, "change_id", ""),
        "display_path": display_path,
        "kind_label": _label(_KIND_LABELS, getattr(change, "kind", "")),
        "analysis_status_label": _label(
            _ANALYSIS_STATUS_LABELS, getattr(change, "analysis_status", "")
        ),
        "rename_basis": getattr(change, "rename_basis", None),
        "diff_truncated": bool(getattr(change, "diff_truncated", False)),
        "old_changed_lines": len(getattr(change, "old_changed_lines", None) or []),
        "new_changed_lines": len(getattr(change, "new_changed_lines", None) or []),
        "hunks": _hunk_view(hunks),
        "has_hunks": bool(hunk_total),
        "hunk_total": hunk_total,
        "hunk_pagination": pagination,
        "symbol_change_count": int(getattr(summary, "symbol_change_count", 0) or 0)
        if summary is not None
        else 0,
        "change_diagnostics": diagnostics,
        "active": "history",
    }


# --------------------------------------------------------------------------
# public entry points (wired from web/app.py)
# --------------------------------------------------------------------------


def render_run_page(
    request: Any,
    templates: Any,
    *,
    db_path: Path,
    repo_id: str | None,
    run_id: str,
    m1_enabled: bool,
) -> Any:
    """Render the summary-first run detail page (no diff bodies on first load)."""

    if not models.is_valid_run_id(run_id):
        return _not_found(request, templates, m1_enabled=m1_enabled)
    impact_page = _parse_page(request.query_params.get("impact_page"))
    tests_page = _parse_page(request.query_params.get("tests_page"))
    file_query = (request.query_params.get("file_q") or "").strip()[:200]
    store = _open_store(Path(db_path))
    try:
        try:
            overview = store.load_run_overview(run_id)
        except StorageError:
            return _not_found(request, templates, m1_enabled=m1_enabled)
        if overview is None:
            return _not_found(request, templates, m1_enabled=m1_enabled)
        run = overview.run
        if repo_id is not None and run.repo_id != repo_id:
            return _not_found(request, templates, m1_enabled=m1_enabled)
        try:
            context = _run_context(
                store,
                request,
                overview,
                impact_page=impact_page,
                tests_page=tests_page,
                m1_enabled=m1_enabled,
                file_query=file_query,
            )
        except StorageError:
            return _not_found(request, templates, m1_enabled=m1_enabled)
        return _render(
            request,
            templates,
            "run.html",
            context,
            m1_enabled=m1_enabled,
        )
    finally:
        store.close()


def render_change_page(
    request: Any,
    templates: Any,
    *,
    db_path: Path,
    repo_id: str | None,
    run_id: str,
    change_id: str,
    m1_enabled: bool,
) -> Any:
    """Render one file diff: a fragment for ``?fragment=1``, otherwise a page."""

    if not models.is_valid_run_id(run_id):
        return _not_found(request, templates, m1_enabled=m1_enabled)
    store = _open_store(Path(db_path))
    try:
        overview = store.load_run_overview(run_id)
        if overview is None:
            return _not_found(request, templates, m1_enabled=m1_enabled)
        run = overview.run
        if repo_id is not None and run.repo_id != repo_id:
            return _not_found(request, templates, m1_enabled=m1_enabled)
        change = store.get_change(run_id, change_id)
        if change is None:
            return _not_found(
                request,
                templates,
                m1_enabled=m1_enabled,
                message="未找到该文件变更。",
            )
        fragment = _truthy(request.query_params.get("fragment"))
        hunk_page_raw = _parse_hunk_page(request.query_params.get("hunk_page"))
        hunk_total = int(len(getattr(change, "hunks", None) or []))
        total_hunk_pages = max(1, math.ceil(hunk_total / HUNK_PAGE_SIZE)) if hunk_total else 1
        hunk_page = min(max(1, hunk_page_raw), total_hunk_pages)
        hunks = store.get_change_hunks_page(
            run_id,
            change_id,
            limit=HUNK_PAGE_SIZE,
            offset=(hunk_page - 1) * HUNK_PAGE_SIZE,
        )[0]
        summary = None
        try:
            summaries, _total = store.list_change_summaries(run_id)
        except StorageError:
            summaries = []
        for item in summaries or ():
            if getattr(item, "change_id", None) == change_id:
                summary = item
                break
        context = _change_context(
            request,
            overview,
            change,
            summary,
            fragment=fragment,
            hunk_page=hunk_page,
            hunks=hunks,
            hunk_total=hunk_total,
        )
        if fragment:
            return _render(
                request,
                templates,
                "_change_fragment.html",
                context,
                m1_enabled=m1_enabled,
            )
        return _render(
            request,
            templates,
            "change_detail.html",
            context,
            m1_enabled=m1_enabled,
        )
    except StorageError:
        return _not_found(request, templates, m1_enabled=m1_enabled)
    finally:
        store.close()
