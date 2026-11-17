"""Read-only local web dashboard for PatchPilot analysis history.

The dashboard is a thin presentation layer over
:class:`patchpilot.storage.Storage`.  It replays the persisted run graph, so it
never invokes Git, the analyzer, tests or the Judge, never mutates the history
database and never reads repository files -- a stored run stays readable after
the working tree has moved on (or was deleted).

Security posture (``docs/CONTRACTS.md`` section 6):

* Jinja2 autoescaping is enabled for every template, and diff / symbol /
  evidence / diagnostic text is only ever rendered as text;
* no JavaScript, no CDN, no CORS: the single asset is the local ``app.css``;
* only loopback ``Host`` headers are accepted (``127.0.0.1``, ``localhost``,
  ``[::1]`` / ``::1`` with an optional port); anything else is ``400``;
* the database is opened with ``Storage(db_path, read_only=True)`` for each
  request, so the web server cannot write the history even by accident.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from html import escape as _html_escape
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from .. import models
from ..storage import RunDetail, Storage, StorageError

__all__ = ["create_app", "PAGE_SIZE", "MAX_PAGE"]

#: Number of runs shown on one history page (``docs/CONTRACTS.md`` section 6).
PAGE_SIZE = 25

#: Upper bound for the ``page`` query parameter so ``OFFSET`` stays bounded.
MAX_PAGE = 100

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


# --------------------------------------------------------------------------
# Chinese UI labels
#
# Raw protocol values (``completed``, ``call_path``, ...) are still shown in
# ``title`` attributes by the templates, so the pages stay debuggable while the
# visible text is Chinese.
# --------------------------------------------------------------------------

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
_CHANGE_KIND_LABELS = {
    models.CHANGE_ADDED: "新增",
    models.CHANGE_REMOVED: "删除",
    models.CHANGE_MODIFIED: "修改",
    models.CHANGE_RENAMED: "重命名",
}
_SYMBOL_CHANGE_KIND_LABELS = dict(_CHANGE_KIND_LABELS)
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
    # P1 resolution rules / edge reasons
    "self_method_unique": "self 方法唯一",
    "explicit_class": "显式类引用",
    "constructor_binding": "构造绑定",
    "class_instantiation": "类实例化",
    "global_read": "全局变量读取",
    "reassigned": "重新绑定",
    "conditional_import": "条件导入",
    "shadowed": "名称遮蔽",
    "local_binding": "局部绑定",
    "dynamic_method": "动态方法",
    "attribute": "动态属性",
    "unsupported_expression": "不支持的表达式",
    "external_module": "外部模块",
}
_SEVERITY_LABELS = {"info": "提示", "warning": "警告", "error": "错误"}
_STRENGTH_LABELS = {
    models.TEST_STRENGTH_STRONG: "强",
    models.TEST_STRENGTH_WEAK: "弱",
}
_EDGE_KIND_LABELS = {
    models.EDGE_CALL: "调用",
    models.EDGE_IMPORT: "导入",
    models.EDGE_GLOBAL_READ: "全局读取",
}
_RESOLUTION_LABELS = {"resolved": "已解析", "unresolved": "未解析"}
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

# -- P1 Judge labels (Chinese labels; the raw protocol values stay in titles) --

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
_VERDICT_UNKNOWN_LABEL = "未判定"
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
    models.JUDGE_ERROR_CACHE_MISS: "缓存未命中",
    models.VERDICT_UNCERTAIN: "证据不足",
}
_EVIDENCE_KIND_LABELS = {
    "hunk": "差异片段",
    "symbol": "符号定义",
    "call_site": "调用点",
    "test": "测试",
}


def _label(mapping: dict[str, str], value: str | None, default: str = "-") -> str:
    if not value:
        return default
    return mapping.get(value, value)


def _branch_label(run: Any) -> str:
    if run.branch:
        return str(run.branch)
    return "(分离 HEAD)" if run.detached else "-"



# --------------------------------------------------------------------------
# Host header validation
# --------------------------------------------------------------------------


def _valid_port(text: str) -> bool:
    return len(text) <= 5 and text.isascii() and text.isdigit() and 0 < int(text) <= 65535


def _parse_host_header(value: str | None) -> str | None:
    """Return the host part of a ``Host`` header when it is well formed.

    ``None`` means "not an acceptable loopback host".  IPv6 literals must be
    bracketed when a port is present (``[::1]:8765``); the bare ``::1`` form is
    accepted because it is a legal ``Host`` value when there is no port.
    """

    if not value:
        return None
    value = value.strip().lower()
    if not value:
        return None
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            return None
        host = value[1:end]
        rest = value[end + 1 :]
        if rest:
            if not rest.startswith(":") or not _valid_port(rest[1:]):
                return None
        return host
    if value.count(":") > 1:
        # An unbracketed IPv6 literal: only the exact loopback spelling is OK.
        return "::1" if value == "::1" else None
    host, separator, port = value.partition(":")
    if separator and not _valid_port(port):
        return None
    return host


def _is_allowed_host(value: str | None) -> bool:
    return _parse_host_header(value) in _LOOPBACK_HOSTS


def _scope_host(scope: dict[str, Any]) -> str | None:
    for key, raw in scope.get("headers") or ():
        if key.lower() == b"host":
            return raw.decode("latin-1")
    return None


class _LoopbackHostMiddleware:
    """Reject every HTTP request whose ``Host`` header is not loopback."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "http" and not _is_allowed_host(_scope_host(scope)):
            response = PlainTextResponse(
                "错误请求：Dashboard 只接受 loopback Host 头"
                "（127.0.0.1、localhost、::1）。",
                status_code=400,
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


# --------------------------------------------------------------------------
# M1 security: CSRF double submit, Origin validation, private page headers
# --------------------------------------------------------------------------

CSRF_COOKIE = "patchpilot_csrf"

#: Every write form carries this hidden field; it must equal the cookie value.
CSRF_FIELD = "csrf_token"

_CSRF_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")

_PRIVATE_RESPONSE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    # Form navigations need a same-origin Origin/Referer for the write guard.
    "Referrer-Policy": "same-origin",
}

#: Size caps for M1 form values (the dashboard never passes these to a shell).
MAX_SETTINGS_TEXT_BYTES = 1_000_000
MAX_REF_LENGTH = 200
MAX_RANGE_LENGTH = 300
_TASK_KEY_RE = re.compile(r"^[0-9A-Za-z_-]{8,128}$")


def _csrf_token_for(request: Request) -> tuple[str, bool]:
    """Return ``(token, must_set_cookie)`` for the double-submit check."""

    token = request.cookies.get(CSRF_COOKIE)
    if token and _CSRF_TOKEN_RE.match(token):
        return token, False
    return secrets.token_hex(16), True


def _origin_allowed(request: Request) -> bool:
    """A write must come from this dashboard's scheme, host and port."""
    origin = request.headers.get("origin")
    source = origin if origin is not None else request.headers.get("referer")
    host = request.headers.get("host")
    if not source or not _is_allowed_host(host):
        return False
    assert host is not None
    authority = "[::1]" if host.strip() == "::1" else host.strip()
    try:
        expected = urlsplit(f"http://{authority}")
        parsed = urlsplit(source.strip())
        expected_port = expected.port if expected.port is not None else 80
        source_port = parsed.port if parsed.port is not None else 80
    except ValueError:
        return False
    if origin is not None and (parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        return False
    port = request.app.state.listen_port
    return (
        parsed.scheme == expected.scheme
        and parsed.hostname == expected.hostname
        and source_port == expected_port
        and (port is None or expected_port == port)
        and parsed.username is None
        and parsed.password is None
    )


def _private_response_headers(response: Response) -> Response:
    for header, value in _PRIVATE_RESPONSE_HEADERS.items():
        response.headers[header] = value
    return response


def _render_html(
    request: Request,
    templates: Jinja2Templates,
    template_name: str,
    context: dict[str, Any],
    *,
    status_code: int = 200,
    m1_enabled: bool = False,
) -> Response:
    """Render one server-side page with CSRF token and private headers."""

    token, needs_cookie = _csrf_token_for(request)
    merged = dict(context)
    merged.setdefault("request", request)
    merged["csrf_token"] = token
    merged["m1_enabled"] = bool(merged.get("m1_enabled", m1_enabled))
    response = templates.TemplateResponse(
        request, template_name, merged, status_code=status_code
    )
    if needs_cookie:
        response.set_cookie(
            CSRF_COOKIE, token, path="/", samesite="strict", httponly=False
        )
    return _private_response_headers(response)


def _redirect(location: str) -> Response:
    return _private_response_headers(
        Response(status_code=303, headers={"Location": location})
    )


def _forbidden(message: str = "禁止访问。") -> Response:
    return _private_response_headers(
        PlainTextResponse(f"403 禁止访问：{message}", status_code=403)
    )


def _unavailable(message: str, status_code: int = 503) -> Response:
    return _private_response_headers(
        PlainTextResponse(f"{status_code} 功能暂不可用：{message}", status_code=status_code)
    )


def _write_guard_error(request: Request, form: Any) -> Response | None:
    """Origin + CSRF double-submit checks; returns a 403 response on failure."""

    if not _origin_allowed(request):
        return _forbidden("来源校验失败：写请求必须来自本机同源页面。")
    cookie = request.cookies.get(CSRF_COOKIE, "")
    field = str(form.get(CSRF_FIELD, "") or "")
    if not cookie or not field or not secrets.compare_digest(cookie, field):
        return _forbidden("CSRF 校验失败，请刷新页面后重试。")
    return None


def _form_text(form: Any, name: str, *, max_length: int = MAX_REF_LENGTH) -> str | None:
    raw = form.get(name)
    if raw is None:
        return None
    value = str(raw).strip()
    if len(value) > max_length:
        raise ValueError(f"{name} 超过最大长度 {max_length}")
    return value or None


def _form_checkbox(form: Any, name: str) -> bool:
    return str(form.get(name, "")).strip().lower() in {"1", "on", "true", "yes"}


# --------------------------------------------------------------------------
# small view-model helpers (pure functions over persisted storage rows)
# --------------------------------------------------------------------------


def _parse_page(raw: str | None) -> int:
    """Validate the ``page`` query parameter (1-based, bounded by MAX_PAGE)."""

    if raw is None or raw.strip() == "":
        return 1
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"page 必须是 1 到 {MAX_PAGE} 之间的整数") from None
    if value < 1 or value > MAX_PAGE:
        raise ValueError(f"page 必须在 1 到 {MAX_PAGE} 之间")
    return value


def _load_history(
    db_path: Path,
    repo_id: str | None,
    offset: int,
    limit: int = PAGE_SIZE,
    *,
    status: str | None = None,
    branch: str | None = None,
    mode: str | None = None,
) -> tuple[list[Any], int, str | None]:
    """Read one filtered history page; a missing database is an empty history."""

    store = Storage(db_path, read_only=True)
    try:
        rows, total = store.list_runs(
            repo_id=repo_id,
            limit=limit,
            offset=offset,
            status=status,
            branch=branch,
            mode=mode,
        )
        return rows, total, None
    except StorageError:
        # A missing database just means this repository has no history yet.
        # A database file that exists but cannot be read is a real problem and
        # is reported instead of being silently hidden.
        if db_path.is_file():
            return [], 0, "历史数据库无法读取。"
        return [], 0, None
    finally:
        store.close()


# --------------------------------------------------------------------------
# UX-2: shared time / status / duration helpers (history + task pages)
# --------------------------------------------------------------------------

_STATUS_SYMBOLS = {
    models.RUN_RUNNING: "●",
    models.RUN_COMPLETED: "✓",
    models.RUN_PARTIAL: "◐",
    models.RUN_FAILED: "✕",
    models.TASK_QUEUED: "◷",
    models.TASK_RUNNING: "●",
    models.TASK_COMPLETED: "✓",
    models.TASK_PARTIAL: "◐",
    models.TASK_FAILED: "✕",
    models.TASK_CANCELLED: "⊘",
    models.TASK_INTERRUPTED: "⚠",
}

_LOCAL_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def _parse_time(value: Any) -> datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _time_view(value: Any, *, fallback: str = "-") -> dict[str, Any]:
    """Local time for display, raw UTC in ``title``/``datetime``."""

    if value is None or str(value).strip() == "":
        return {
            "text": fallback,
            "iso": None,
            "title": None,
            "valid": False,
            "date": "",
            "clock": "",
        }
    parsed = _parse_time(value)
    if parsed is None:
        text = str(value)
        return {
            "text": text,
            "iso": text,
            "title": text,
            "valid": False,
            "date": "",
            "clock": "",
        }
    local = parsed.astimezone()
    raw = str(value)
    return {
        "text": local.strftime(_LOCAL_TIME_FORMAT),
        "iso": parsed.isoformat().replace("+00:00", "Z"),
        "title": raw,
        "valid": True,
        "date": local.strftime("%Y-%m-%d"),
        "clock": local.strftime("%H:%M:%S"),
    }


def _format_duration_ms(value: int | float | None) -> str:
    if value is None:
        return "-"
    milliseconds = max(0, int(value))
    if milliseconds < 1000:
        return f"{milliseconds} 毫秒"
    seconds = milliseconds / 1000
    if seconds < 60:
        return f"{seconds:.1f} 秒"
    minutes, seconds_part = divmod(int(round(seconds)), 60)
    if minutes < 60:
        return f"{minutes} 分 {seconds_part} 秒"
    hours, minutes_part = divmod(minutes, 60)
    return f"{hours} 小时 {minutes_part} 分"


def _duration_since(
    started_at: Any, finished_at: Any = None, *, active: bool = False
) -> dict[str, Any]:
    start = _parse_time(started_at)
    if start is None:
        return {"ms": None, "text": "-", "active": False}
    if finished_at:
        end = _parse_time(finished_at)
    elif active:
        end = datetime.now(UTC)
    else:
        end = None
    if end is None:
        return {"ms": None, "text": "-", "active": False}
    milliseconds = max(0, int((end - start).total_seconds() * 1000))
    return {
        "ms": milliseconds,
        "text": _format_duration_ms(milliseconds),
        "active": active,
    }


def _status_view(
    status: str | None, labels: dict[str, str], *, default: str | None = None
) -> dict[str, Any]:
    value = str(status or "")
    return {
        "status": value,
        "label": _label(labels, value, default or value or "-"),
        "symbol": _STATUS_SYMBOLS.get(value, "·"),
        "title": value,
    }


# -- history filters -------------------------------------------------------

_HISTORY_FILTER_MODES = tuple(models.ALL_MODES)
MAX_BRANCH_FILTER_LENGTH = 200


def _parse_history_filters(query: Any) -> dict[str, str | None]:
    status = _clean_filter(query.get("status"))
    branch = _clean_filter(query.get("branch"))
    mode = _clean_filter(query.get("mode"))
    if status is not None and status not in models.RUN_STATUSES:
        raise ValueError(f"status 只能为 {'、'.join(models.RUN_STATUSES)}")
    if mode is not None and mode not in models.ALL_MODES:
        raise ValueError(f"mode 只能为 {'、'.join(models.ALL_MODES)}")
    if branch is not None and len(branch) > MAX_BRANCH_FILTER_LENGTH:
        raise ValueError(f"branch 最长 {MAX_BRANCH_FILTER_LENGTH} 个字符")
    return {"status": status, "branch": branch, "mode": mode}


def _url_with_params(path: str, params: dict[str, Any]) -> str:
    filtered = {key: value for key, value in params.items() if value not in (None, "")}
    if not filtered:
        return path
    return f"{path}?{urlencode(filtered)}"


def _history_url(filters: dict[str, str | None], page: int | None = None) -> str:
    params: dict[str, Any] = dict(filters)
    if page is not None:
        params["page"] = page
    return _url_with_params("/", params)


# -- task queue filters ----------------------------------------------------


_TASK_GROUP_ORDER = ("queued", "running", "finished")
_TASK_GROUP_LABELS = {
    "queued": "排队中",
    "running": "运行中",
    "finished": "已结束",
}
_TASK_GROUP_STATUSES = {
    "queued": [models.TASK_QUEUED],
    "running": [models.TASK_RUNNING],
    "finished": [
        models.TASK_COMPLETED,
        models.TASK_PARTIAL,
        models.TASK_FAILED,
        models.TASK_CANCELLED,
        models.TASK_INTERRUPTED,
    ],
}


def _parse_task_group(query: Any) -> str | None:
    group = _clean_filter(query.get("group"))
    if group is not None and group not in _TASK_GROUP_ORDER:
        raise ValueError("group 只能为 queued、running 或 finished")
    return group


def _tasks_url(group: str | None, page: int | None = None) -> str:
    params: dict[str, Any] = {}
    if group:
        params["group"] = group
    if page is not None:
        params["page"] = page
    return _url_with_params("/tasks", params)


def _task_group(status: str | None) -> str:
    value = str(status or "")
    if value == models.TASK_QUEUED:
        return "queued"
    if value == models.TASK_RUNNING:
        return "running"
    return "finished"


def _load_detail(
    db_path: Path, repo_id: str | None, run_id: str
) -> RunDetail | None:
    """Load one run; ``None`` means "not found / not visible on this dashboard"."""

    if not models.is_valid_run_id(run_id):
        return None
    store = Storage(db_path, read_only=True)
    try:
        detail = store.load_run(run_id)
    except StorageError:
        return None
    finally:
        store.close()
    if repo_id is not None and detail.run.repo_id != repo_id:
        return None
    return detail


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


def _hunk_header(hunk: models.Hunk) -> str:
    return (
        f"@@ -{hunk.old_start},{hunk.old_count} "
        f"+{hunk.new_start},{hunk.new_count} @@"
    )


def _line_numbers(numbers: list[int] | None) -> str:
    values = [str(int(number)) for number in numbers or []]
    return ", ".join(values) if values else "-"


def _symbol_view(
    symbol_id: str | None, symbols: dict[str, models.Symbol]
) -> dict[str, Any] | None:
    if not symbol_id:
        return None
    symbol = symbols.get(symbol_id)
    if symbol is None:  # pragma: no cover - storage keeps referential integrity
        return {
            "symbol_id": symbol_id,
            "display_name": symbol_id,
            "path": None,
            "module": None,
            "kind": None,
            "kind_label": None,
            "side": None,
            "side_label": None,
            "start_line": None,
            "end_line": None,
            "def_line": None,
            "is_test": False,
            "missing": True,
        }
    return {
        "symbol_id": symbol.symbol_id,
        "display_name": symbol.display_name,
        "path": symbol.path,
        "module": symbol.module,
        "kind": symbol.kind,
        "kind_label": _label(_SYMBOL_KIND_LABELS, symbol.kind),
        "side": symbol.side,
        "side_label": _label(_SIDE_LABELS, symbol.side),
        "start_line": symbol.start_line,
        "end_line": symbol.end_line,
        "def_line": symbol.def_line,
        "is_test": symbol.is_test,
        "missing": False,
    }


def _diagnostic_view(diagnostic: models.Diagnostic, source: str) -> dict[str, Any]:
    details = ""
    if diagnostic.details:
        try:
            details = json.dumps(
                diagnostic.details,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            )
        except (TypeError, ValueError):  # pragma: no cover - defensive
            details = str(diagnostic.details)
        if len(details) > 500:
            details = details[:500] + " ... (details truncated)"
    return {
        "code": diagnostic.code,
        "message": diagnostic.message,
        "severity": diagnostic.severity,
        "severity_label": _label(_SEVERITY_LABELS, diagnostic.severity),
        "path": diagnostic.path,
        "line": diagnostic.line,
        "details": details,
        "source": source,
    }


def _all_diagnostics(detail: RunDetail) -> list[dict[str, Any]]:
    """Run, change and symbol-change diagnostics without duplicated entries."""

    collected: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    def add(diagnostic: models.Diagnostic, source: str) -> None:
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
        collected.append(_diagnostic_view(diagnostic, source))

    for diagnostic in detail.run.diagnostics or []:
        add(diagnostic, "运行级")
    for change in detail.changes:
        for diagnostic in change.diagnostics or []:
            add(diagnostic, f"变更 {change.change_id}")
    for symbol_change in detail.symbol_changes:
        for diagnostic in symbol_change.diagnostics or []:
            add(diagnostic, f"符号变更 {symbol_change.symbol_change_id}")
    return collected


def _change_views(detail: RunDetail) -> list[dict[str, Any]]:
    views: list[dict[str, Any]] = []
    for change in detail.changes:
        hunks: list[dict[str, Any]] = []
        has_lines = False
        for hunk in change.hunks:
            lines = [
                {"kind": _line_kind(str(line)), "text": str(line)}
                for line in hunk.lines
            ]
            has_lines = has_lines or bool(lines)
            hunks.append({"header": _hunk_header(hunk), "lines": lines})
        views.append(
            {
                "change_id": change.change_id,
                "kind": change.kind,
                "kind_label": _label(_CHANGE_KIND_LABELS, change.kind),
                "display_path": change.display_path,
                "old_path": change.old_path,
                "new_path": change.new_path,
                "rename_basis": change.rename_basis,
                "analysis_status": change.analysis_status,
                "analysis_status_label": _label(
                    _ANALYSIS_STATUS_LABELS, change.analysis_status
                ),
                "diff_truncated": bool(change.diff_truncated),
                "hunks": hunks,
                "has_hunks": bool(hunks),
                "has_lines": has_lines,
                "old_changed_lines": _line_numbers(change.old_changed_lines),
                "new_changed_lines": _line_numbers(change.new_changed_lines),
            }
        )
    return views


def _symbol_change_views(detail: RunDetail) -> list[dict[str, Any]]:
    symbols = detail.symbols
    views: list[dict[str, Any]] = []
    for symbol_change in detail.symbol_changes:
        views.append(
            {
                "symbol_change_id": symbol_change.symbol_change_id,
                "change_id": symbol_change.change_id,
                "kind": symbol_change.kind,
                "kind_label": _label(_SYMBOL_CHANGE_KIND_LABELS, symbol_change.kind),
                "reason": symbol_change.reason,
                "reason_label": _label(_REASON_LABELS, symbol_change.reason),
                "structure_changed": bool(symbol_change.structure_changed),
                "side": symbol_change.side,
                "side_label": _label(_SIDE_LABELS, symbol_change.side),
                "old": _symbol_view(symbol_change.old_symbol_id, symbols),
                "new": _symbol_view(symbol_change.new_symbol_id, symbols),
                "old_changed_lines": _line_numbers(symbol_change.old_changed_lines),
                "new_changed_lines": _line_numbers(symbol_change.new_changed_lines),
            }
        )
    return views


def _edge_view(edge: models.CallEdge, symbols: dict[str, models.Symbol]) -> dict[str, Any]:
    return {
        "edge_id": edge.edge_id,
        "side": edge.side,
        "side_label": _label(_SIDE_LABELS, edge.side),
        "edge_kind": edge.edge_kind,
        "edge_kind_label": _label(_EDGE_KIND_LABELS, edge.edge_kind),
        "resolution": edge.resolution,
        "resolution_label": _label(_RESOLUTION_LABELS, edge.resolution),
        "reason": edge.reason,
        "reason_label": _label(_REASON_LABELS, edge.reason),
        "target": edge.target,
        "callee_module": edge.callee_module,
        "path": edge.path,
        "line": edge.line,
        "col": edge.col,
        "caller": _symbol_view(edge.caller_id, symbols),
        "callee": _symbol_view(edge.callee_id, symbols),
    }


def _impact_groups(
    detail: RunDetail, symbol_change_views: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Group impact candidates by symbol change and expand their edge paths."""

    symbols = detail.symbols
    edges_by_id = {edge.edge_id: edge for edge in detail.edges}
    candidates_by_change: dict[str, list[dict[str, Any]]] = {}
    for candidate in detail.candidates:
        edges: list[dict[str, Any]] = []
        missing_edges = 0
        for edge_id in candidate.edge_ids:
            edge = edges_by_id.get(edge_id)
            if edge is None:
                missing_edges += 1
                continue
            edges.append(_edge_view(edge, symbols))
        candidates_by_change.setdefault(candidate.symbol_change_id, []).append(
            {
                "candidate_id": candidate.candidate_id,
                "seed_symbol_id": candidate.seed_symbol_id,
                "candidate_symbol_id": candidate.candidate_symbol_id,
                "side": candidate.side,
                "side_label": _label(_SIDE_LABELS, candidate.side),
                "min_depth": candidate.min_depth,
                "evidence": candidate.evidence,
                "evidence_label": _label(_EVIDENCE_LABELS, candidate.evidence),
                "truncated": bool(candidate.truncated),
                "seed": _symbol_view(candidate.seed_symbol_id, symbols),
                "candidate": _symbol_view(candidate.candidate_symbol_id, symbols),
                "edges": edges,
                "missing_edges": missing_edges,
            }
        )
    return [
        {
            "symbol_change": view,
            "candidates": candidates_by_change.get(view["symbol_change_id"], []),
        }
        for view in symbol_change_views
    ]


def _test_views(detail: RunDetail) -> list[dict[str, Any]]:
    views: list[dict[str, Any]] = []
    for recommendation in detail.test_recommendations:
        qualified = recommendation.qualified_name
        reference = (
            f"{recommendation.test_path}::{qualified}"
            if qualified
            else recommendation.test_path
        )
        views.append(
            {
                "reference": reference,
                "test_path": recommendation.test_path,
                "qualified_name": qualified,
                "side": recommendation.side,
                "side_label": _label(_SIDE_LABELS, recommendation.side),
                "strength": recommendation.strength,
                "strength_label": _label(_STRENGTH_LABELS, recommendation.strength),
                "distance": recommendation.min_depth,
                "exists_in_after": bool(recommendation.exists_in_after),
                "evidence": recommendation.evidence,
                "candidate_ids": list(recommendation.candidate_ids),
                "test_symbol_id": recommendation.test_symbol_id,
            }
        )
    return views


def _scope(detail: RunDetail) -> dict[str, int]:
    entries = list(detail.snapshot_entries or [])
    before = [entry for entry in entries if entry.side == models.SIDE_BEFORE]
    after = [entry for entry in entries if entry.side == models.SIDE_AFTER]
    return {
        "before_files": len(before),
        "after_files": len(after),
        "before_python": sum(1 for entry in before if entry.is_python),
        "after_python": sum(1 for entry in after if entry.is_python),
    }


def _stages(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    raw = metrics.get("stages") if isinstance(metrics, dict) else None
    if not isinstance(raw, dict):
        return []
    stages: list[dict[str, Any]] = []
    for name in sorted(raw):
        try:
            duration = int(raw[name])
        except (TypeError, ValueError):
            duration = raw[name]
        stages.append(
            {
                "name": str(name),
                "label": _label(_STAGE_LABELS, str(name)),
                "duration_ms": duration,
            }
        )
    return stages


def _run_context(request: Request, detail: RunDetail) -> dict[str, Any]:
    run = detail.run
    metrics = run.metrics if isinstance(run.metrics, dict) else {}
    symbol_change_views = _symbol_change_views(detail)
    stage_errors = metrics.get("stage_errors")
    if not isinstance(stage_errors, list):
        stage_errors = []
    return {
        "request": request,
        "run": run,
        "status_label": _label(_STATUS_LABELS, run.status),
        "summary_label": _label(_SUMMARY_LABELS, run.summary),
        "mode_label": _label(_MODE_LABELS, run.mode),
        "branch_label": _branch_label(run),
        "scope": _scope(detail),
        "counts": {
            "changes": len(detail.changes),
            "symbol_changes": len(detail.symbol_changes),
            "candidates": len(detail.candidates),
            "tests": len(detail.test_recommendations),
        },
        "stages": _stages(metrics),
        "stage_errors": [str(name) for name in stage_errors],
        "metrics_truncated": bool(metrics.get("truncated")),
        "diagnostics": _all_diagnostics(detail),
        "changes": _change_views(detail),
        "symbol_changes": symbol_change_views,
        "impact_groups": _impact_groups(detail, symbol_change_views),
        "tests": _test_views(detail),
        "judge": _judge_views(detail),
        "symbols_count": len(detail.symbols),
        "edges_count": len(detail.edges),
    }


def _history_row(run: Any, task_id: str | None = None) -> dict[str, Any]:
    """Flatten one ``RunSummary`` row for the Chinese history table."""

    started = _time_view(getattr(run, "started_at", None))
    status_view = _status_view(getattr(run, "status", None), _STATUS_LABELS)
    summary = str(getattr(run, "summary", "") or "")
    mode = str(getattr(run, "mode", "") or "")
    branch = getattr(run, "branch", None)
    return {
        "run_id": run.run_id,
        "started_at": getattr(run, "started_at", ""),
        "started_time": started,
        "display_name": getattr(run, "display_name", ""),
        "branch": branch,
        "branch_label": _branch_label(run),
        "branch_title": branch or "",
        "mode": mode,
        "mode_label": _label(_MODE_LABELS, mode, mode),
        "counts": getattr(run, "counts", {}) or {},
        "status": status_view["status"],
        "status_label": status_view["label"],
        "status_symbol": status_view["symbol"],
        "status_title": status_view["title"],
        "summary": summary,
        "summary_label": _label(_SUMMARY_LABELS, summary, summary),
        "summary_title": summary,
        "task_id": task_id,
    }


# --------------------------------------------------------------------------
# JSON API helpers (P1, docs/CONTRACTS-P1.md section 6)
# --------------------------------------------------------------------------

_JSON_MEDIA_TYPE = "application/json; charset=utf-8"

API_DEFAULT_LIMIT = 25
API_MAX_LIMIT = 100
API_DEFAULT_MAX_NODES = 200
API_MAX_NODES = 1000

#: Node cap for the HTML impact tree page (``max_nodes`` is not a page filter).
IMPACT_PAGE_MAX_NODES = 200

#: Upper bound for the page's ``depth`` filter.
IMPACT_PAGE_MAX_DEPTH = 100


def _reports_module() -> Any:
    """Import the shared report view-models lazily.

    ``reports.py`` is owned by the Lead; a lazy import keeps the HTML dashboard
    importable even while that module (or its ``changes`` dependency) is being
    edited by a parallel worker.
    """

    from .. import reports

    return reports


def _json_response(payload: Any, status_code: int = 200) -> Response:
    """JSON response with the exact content type required by the P1 contract."""

    return _private_response_headers(
        Response(
            content=json.dumps(payload, ensure_ascii=False),
            media_type=_JSON_MEDIA_TYPE,
            status_code=status_code,
        )
    )


def _json_error(message: str, status_code: int = 400) -> Response:
    return _json_response({"error": message}, status_code=status_code)


def _json_not_found() -> Response:
    return _json_response({"error": "not_found"}, status_code=404)


def _parse_int_param(
    name: str,
    raw: str | None,
    default: int,
    minimum: int,
    maximum: int | None = None,
) -> int:
    """Parse one bounded integer query parameter or raise ``ValueError``."""

    if raw is None or str(raw).strip() == "":
        return default
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        raise ValueError(f"{name} 必须是整数") from None
    if value < minimum or (maximum is not None and value > maximum):
        bounds = f"{minimum}..{maximum}" if maximum is not None else f">= {minimum}"
        raise ValueError(f"{name} 必须在 {bounds} 范围内")
    return value


def _clean_filter(raw: str | None) -> str | None:
    value = (raw or "").strip()
    return value or None


def _normalize_impact_filters(
    detail: RunDetail,
    seed: str | None,
    side: str | None,
    kind: str | None,
) -> tuple[str | None, str | None, str | None]:
    """Validate the shared ``seed``/``side``/``kind`` impact filters."""

    seed_value = _clean_filter(seed)
    side_value = _clean_filter(side)
    kind_value = _clean_filter(kind)
    if side_value is not None and side_value not in models.SIDES:
        raise ValueError("side 只能为 before 或 after")
    if kind_value is not None and kind_value not in (
        models.EDGE_CALL,
        models.EDGE_IMPORT,
        models.EDGE_GLOBAL_READ,
    ):
        raise ValueError("kind 只能为 call、import 或 global_read")
    if seed_value is not None:
        known = {item.symbol_change_id for item in detail.symbol_changes}
        if seed_value not in known:
            raise ValueError("seed 必须是该 Run 中存在的符号变更 ID")
    return seed_value, side_value, kind_value


# --------------------------------------------------------------------------
# impact tree / impact API
# --------------------------------------------------------------------------

_KIND_TO_EVIDENCE = {
    models.EDGE_CALL: models.EVIDENCE_CALL,
    models.EDGE_IMPORT: models.EVIDENCE_IMPORT,
    models.EDGE_GLOBAL_READ: models.EVIDENCE_GLOBAL_READ,
}


def _candidate_matches_kind(
    candidate: models.ImpactCandidate,
    edges_by_id: dict[str, models.CallEdge],
    kind: str,
) -> bool:
    edge_kinds = {
        edge.edge_kind
        for edge in (edges_by_id.get(edge_id) for edge_id in candidate.edge_ids)
        if edge is not None
    }
    if edge_kinds:
        return kind in edge_kinds
    return _KIND_TO_EVIDENCE.get(kind) == candidate.evidence


def _impact_builder(
    detail: RunDetail,
    *,
    seed: str | None = None,
    side: str | None = None,
    kind: str | None = None,
    max_nodes: int = API_DEFAULT_MAX_NODES,
    max_depth: int | None = None,
) -> dict[str, Any]:
    """Build the bounded seed -> caller tree shared by the page and the API.

    The stored impact graph is a set of per-candidate shortest paths
    (``ImpactCandidate.edge_ids`` ordered from the seed outwards).  Walking
    them here reconstructs a tree:

    * shared prefixes are merged (same parent node + same edge are visited once);
    * a symbol that is already an ancestor of the current path becomes a
      ``cycle`` reference node ("↺ 已显示") and is not expanded;
    * ``max_nodes`` bounds the number of nodes; ``truncated`` and
      ``dropped_candidates`` report what did not fit.
    """

    symbols = detail.symbols
    edges_by_id = {edge.edge_id: edge for edge in detail.edges}

    filtered: list[models.ImpactCandidate] = []
    for candidate in detail.candidates:
        if seed is not None and candidate.symbol_change_id != seed:
            continue
        if side is not None and candidate.side != side:
            continue
        if max_depth is not None and int(candidate.min_depth) > max_depth:
            continue
        if kind is not None and not _candidate_matches_kind(
            candidate, edges_by_id, kind
        ):
            continue
        filtered.append(candidate)

    groups: dict[tuple[str, str, str], list[models.ImpactCandidate]] = {}
    for candidate in filtered:
        groups.setdefault(
            (candidate.symbol_change_id, candidate.side, candidate.seed_symbol_id),
            [],
        ).append(candidate)

    nodes_flat: list[dict[str, Any]] = []
    edges_used: dict[str, dict[str, Any]] = {}
    seeds: list[dict[str, Any]] = []
    truncated = False
    handled = 0

    def make_node(
        *,
        symbol_id: str,
        node_side: str,
        depth: int,
        parent: dict[str, Any] | None,
        via_edge: dict[str, Any] | None,
        seed_symbol_id: str,
        cycle: bool = False,
        reference: str | None = None,
    ) -> dict[str, Any] | None:
        nonlocal truncated
        if len(nodes_flat) >= max_nodes:
            truncated = True
            return None
        node: dict[str, Any] = {
            "node_id": f"n{len(nodes_flat) + 1}",
            "symbol_id": symbol_id,
            "symbol": _symbol_view(symbol_id, symbols),
            "side": node_side,
            "side_label": _label(_SIDE_LABELS, node_side),
            "depth": depth,
            "parent_node_id": parent["node_id"] if parent is not None else None,
            "via_edge_id": via_edge["edge_id"] if via_edge is not None else None,
            "via_edge": via_edge,
            "cycle": cycle,
            "reference_node_id": reference,
            "candidate_ids": [],
            "seed_symbol_ids": [seed_symbol_id],
            "children": [],
        }
        nodes_flat.append(node)
        if parent is not None:
            parent["children"].append(node)
        return node

    for (symbol_change_id, candidate_side, seed_symbol_id), candidates in groups.items():
        root = make_node(
            symbol_id=seed_symbol_id,
            node_side=candidate_side,
            depth=0,
            parent=None,
            via_edge=None,
            seed_symbol_id=seed_symbol_id,
        )
        if root is None:
            break
        child_index: dict[tuple[str, str], dict[str, Any]] = {}
        group_candidate_ids: list[str] = []
        for candidate in candidates:
            if truncated:
                break
            group_candidate_ids.append(candidate.candidate_id)
            ancestors: dict[tuple[str, str], str] = {
                (candidate_side, seed_symbol_id): root["node_id"]
            }
            path_nodes: list[dict[str, Any]] = [root]
            current = root
            for edge_id in candidate.edge_ids:
                edge = edges_by_id.get(edge_id)
                if edge is None:
                    # Evidence of this path was truncated in storage; keep the
                    # prefix that is known instead of inventing a node.
                    break
                edge_view = _edge_view(edge, symbols)
                edges_used.setdefault(edge.edge_id, edge_view)
                next_symbol_id = edge.caller_id
                key = (edge.side, next_symbol_id)
                depth = int(current["depth"]) + 1
                if key in ancestors:
                    child = make_node(
                        symbol_id=next_symbol_id,
                        node_side=edge.side,
                        depth=depth,
                        parent=current,
                        via_edge=edge_view,
                        seed_symbol_id=seed_symbol_id,
                        cycle=True,
                        reference=ancestors[key],
                    )
                    if child is not None:
                        path_nodes.append(child)
                    break
                child_key = (current["node_id"], edge.edge_id)
                child = child_index.get(child_key)
                if child is None:
                    child = make_node(
                        symbol_id=next_symbol_id,
                        node_side=edge.side,
                        depth=depth,
                        parent=current,
                        via_edge=edge_view,
                        seed_symbol_id=seed_symbol_id,
                    )
                    if child is None:
                        break
                    child_index[child_key] = child
                ancestors[key] = child["node_id"]
                current = child
                path_nodes.append(child)
            if truncated:
                break
            for node in path_nodes:
                if candidate.candidate_id not in node["candidate_ids"]:
                    node["candidate_ids"].append(candidate.candidate_id)
            handled += 1
        seeds.append(
            {
                "symbol_change_id": symbol_change_id,
                "side": candidate_side,
                "side_label": _label(_SIDE_LABELS, candidate_side),
                "seed_symbol_id": seed_symbol_id,
                "symbol": _symbol_view(seed_symbol_id, symbols),
                "candidate_ids": group_candidate_ids,
                "candidate_count": len(candidates),
                "roots": [root],
            }
        )

    dropped = max(0, len(filtered) - handled) if truncated else 0
    return {
        "run_id": detail.run.run_id,
        "filters": {
            "seed": seed,
            "side": side,
            "kind": kind,
            "max_nodes": max_nodes,
            "max_depth": max_depth,
        },
        "node_limit": max_nodes,
        "truncated": truncated,
        "dropped_candidates": dropped,
        "counts": {
            "seeds": len(seeds),
            "nodes": len(nodes_flat),
            "edges": len(edges_used),
            "candidates": len(filtered),
        },
        "seeds": seeds,
        "nodes": nodes_flat,
        "edges": edges_used,
    }


_API_SYMBOL_FIELDS = (
    "symbol_id",
    "display_name",
    "path",
    "module",
    "kind",
    "side",
    "start_line",
    "end_line",
    "def_line",
    "is_test",
)


def _plain_symbol(view: dict[str, Any] | None) -> dict[str, Any] | None:
    if not view:
        return None
    plain = {field: view.get(field) for field in _API_SYMBOL_FIELDS}
    if view.get("missing"):
        plain["missing"] = True
    return plain


def _plain_edge(edge_view: dict[str, Any]) -> dict[str, Any]:
    return {
        "edge_id": edge_view["edge_id"],
        "side": edge_view["side"],
        "edge_kind": edge_view["edge_kind"],
        "resolution": edge_view["resolution"],
        "reason": edge_view["reason"],
        "target": edge_view["target"],
        "path": edge_view["path"],
        "line": edge_view["line"],
        "col": edge_view["col"],
        "caller": _plain_symbol(edge_view.get("caller")),
        "callee": _plain_symbol(edge_view.get("callee")),
    }


def _impact_api_from_builder(builder: dict[str, Any]) -> dict[str, Any]:
    """Convert the internal tree into the flat, bounded impact API payload."""

    seeds = [
        {
            "symbol_change_id": seed["symbol_change_id"],
            "side": seed["side"],
            "seed_symbol_id": seed["seed_symbol_id"],
            "symbol": _plain_symbol(seed["symbol"]),
            "candidate_ids": list(seed["candidate_ids"]),
            "candidate_count": seed["candidate_count"],
            "root_node_ids": [node["node_id"] for node in seed["roots"]],
        }
        for seed in builder["seeds"]
    ]
    nodes = [
        {
            "node_id": node["node_id"],
            "symbol_id": node["symbol_id"],
            "symbol": _plain_symbol(node["symbol"]),
            "side": node["side"],
            "depth": node["depth"],
            "parent_node_id": node["parent_node_id"],
            "via_edge_id": node["via_edge_id"],
            "cycle": node["cycle"],
            "reference_node_id": node["reference_node_id"],
            "candidate_ids": list(node["candidate_ids"]),
            "seed_symbol_ids": list(node["seed_symbol_ids"]),
        }
        for node in builder["nodes"]
    ]
    edges = [_plain_edge(edge) for edge in builder["edges"].values()]
    return {
        "schema_version": models.SCHEMA_VERSION,
        "run_id": builder["run_id"],
        "filters": builder["filters"],
        "node_limit": builder["node_limit"],
        "truncated": builder["truncated"],
        "dropped_candidates": builder["dropped_candidates"],
        "counts": {
            "seeds": len(seeds),
            "nodes": len(nodes),
            "edges": len(edges),
            "candidates": builder["counts"]["candidates"],
        },
        "seeds": seeds,
        "nodes": nodes,
        "edges": edges,
    }


def _impact_api_payload(
    detail: RunDetail,
    *,
    seed: str | None,
    side: str | None,
    kind: str | None,
    max_nodes: int,
    max_depth: int | None = None,
) -> dict[str, Any]:
    """Return the impact API payload, preferring ``reports.build_impact_api``.

    Switch point: as soon as the Lead's ``reports.build_impact_api`` exists it
    becomes the single source of truth for ``GET /api/v1/runs/{id}/impact``.
    The local implementation below keeps the endpoint usable until then and is
    kept isomorphic (bounded ``seeds``/``nodes``/``edges`` plus ``truncated``).
    """

    try:
        reports = _reports_module()
    except ImportError:  # pragma: no cover - defensive during parallel work
        reports = None
    builder = getattr(reports, "build_impact_api", None) if reports else None
    if callable(builder):
        kwargs: dict[str, Any] = {
            "seed": seed,
            "side": side,
            "kind": kind,
            "max_nodes": max_nodes,
        }
        if max_depth is not None:
            try:
                return builder(detail, max_depth=max_depth, **kwargs)
            except TypeError:  # older builder without depth support
                pass
        return builder(detail, **kwargs)
    builder_view = _impact_builder(
        detail, seed=seed, side=side, kind=kind, max_nodes=max_nodes
    )
    return _impact_api_from_builder(builder_view)


def _impact_page_context(
    request: Request,
    detail: RunDetail,
    *,
    seed: str | None,
    side: str | None,
    kind: str | None,
    depth: int | None,
) -> dict[str, Any]:
    """View model for the Chinese impact tree page."""

    builder = _impact_builder(
        detail,
        seed=seed,
        side=side,
        kind=kind,
        max_nodes=IMPACT_PAGE_MAX_NODES,
        max_depth=depth,
    )
    seed_options = []
    for symbol_change in detail.symbol_changes:
        symbol = detail.symbols.get(
            symbol_change.new_symbol_id or symbol_change.old_symbol_id or ""
        )
        name = (
            symbol.display_name
            if symbol is not None
            else (symbol_change.new_symbol_id or symbol_change.old_symbol_id or "")
        )
        seed_options.append(
            {
                "symbol_change_id": symbol_change.symbol_change_id,
                "label": (
                    f"{name} · {_label(_SYMBOL_CHANGE_KIND_LABELS, symbol_change.kind)}"
                    f"（{symbol_change.symbol_change_id}）"
                ),
                "selected": seed == symbol_change.symbol_change_id,
            }
        )
    side_options = [
        {
            "value": value,
            "label": _label(_SIDE_LABELS, value),
            "selected": side == value,
        }
        for value in models.SIDES
    ]
    kind_options = [
        {
            "value": models.EDGE_CALL,
            "label": _label(_EDGE_KIND_LABELS, models.EDGE_CALL),
            "selected": kind == models.EDGE_CALL,
        },
        {
            "value": models.EDGE_IMPORT,
            "label": _label(_EDGE_KIND_LABELS, models.EDGE_IMPORT),
            "selected": kind == models.EDGE_IMPORT,
        },
        {
            "value": models.EDGE_GLOBAL_READ,
            "label": _label(_EDGE_KIND_LABELS, models.EDGE_GLOBAL_READ),
            "selected": kind == models.EDGE_GLOBAL_READ,
        },
    ]
    return {
        "request": request,
        "run": detail.run,
        "status_label": _label(_STATUS_LABELS, detail.run.status),
        "tree": builder,
        "filters": {
            "seed": seed or "",
            "side": side or "",
            "kind": kind or "",
            "depth": "" if depth is None else depth,
        },
        "has_filters": bool(seed or side or kind or depth is not None),
        "seed_options": seed_options,
        "side_options": side_options,
        "kind_options": kind_options,
        "max_depth": IMPACT_PAGE_MAX_DEPTH,
    }


# --------------------------------------------------------------------------
# Judge verdict view model (P1)
# --------------------------------------------------------------------------


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _evidence_view(item: Any) -> dict[str, Any]:
    data = item.to_dict() if hasattr(item, "to_dict") else (
        dict(item) if isinstance(item, dict) else dict(vars(item))
    )
    return {
        "evidence_id": data.get("evidence_id"),
        "path": data.get("path"),
        "side": data.get("side"),
        "side_label": _label(_SIDE_LABELS, data.get("side")),
        "start_line": data.get("start_line"),
        "end_line": data.get("end_line"),
        "kind": data.get("kind"),
        "kind_label": _label(_EVIDENCE_KIND_LABELS, data.get("kind")),
    }


def _attempt_view(attempt: Any) -> dict[str, Any]:
    usage = _attr(attempt, "usage") or {}
    context_summary = _attr(attempt, "context_summary") or {}
    try:
        usage_text = json.dumps(usage, ensure_ascii=False, sort_keys=True) if usage else ""
    except (TypeError, ValueError):  # pragma: no cover - defensive
        usage_text = str(usage)
    if len(usage_text) > 300:
        usage_text = usage_text[:300] + " ... (已截断)"
    try:
        summary_text = (
            json.dumps(context_summary, ensure_ascii=False, sort_keys=True)
            if context_summary
            else ""
        )
    except (TypeError, ValueError):  # pragma: no cover - defensive
        summary_text = str(context_summary)
    if len(summary_text) > 300:
        summary_text = summary_text[:300] + " ... (已截断)"
    adapter = _attr(attempt, "adapter")
    return {
        "attempt_id": _attr(attempt, "attempt_id"),
        "candidate_id": _attr(attempt, "candidate_id"),
        "attempt_no": int(_attr(attempt, "attempt_no", 0) or 0),
        "adapter": adapter,
        "adapter_label": _label(_JUDGE_ADAPTER_LABELS, adapter),
        "model": _attr(attempt, "model"),
        "started_at": _attr(attempt, "started_at", ""),
        "duration_ms": int(_attr(attempt, "duration_ms", 0) or 0),
        "context_digest": _attr(attempt, "context_digest", ""),
        "context_digest_short": str(_attr(attempt, "context_digest", "") or "")[:12],
        "context_bytes": int(_attr(attempt, "context_bytes", 0) or 0),
        "context_tokens_estimate": int(
            _attr(attempt, "context_tokens_estimate", 0) or 0
        ),
        "cache_hit": bool(_attr(attempt, "cache_hit", False)),
        "valid": bool(_attr(attempt, "valid", False)),
        "error_category": _attr(attempt, "error_category"),
        "error_label": _label(_JUDGE_ERROR_LABELS, _attr(attempt, "error_category")),
        "fallback_reason": _attr(attempt, "fallback_reason"),
        "fallback_label": _label(_JUDGE_ERROR_LABELS, _attr(attempt, "fallback_reason")),
        "request_id": _attr(attempt, "request_id"),
        "usage_text": usage_text,
        "context_summary_text": summary_text,
    }


def _verdict_view(verdict: Any) -> dict[str, Any]:
    code = _attr(verdict, "verdict")
    adapter = _attr(verdict, "adapter")
    return {
        "candidate_id": _attr(verdict, "candidate_id"),
        "attempt_no": int(_attr(verdict, "attempt_no", 0) or 0),
        "verdict": code,
        "verdict_label": _label(_VERDICT_LABELS, code, _VERDICT_UNKNOWN_LABEL),
        "reason": _attr(verdict, "reason", ""),
        "adapter": adapter,
        "adapter_label": _label(_JUDGE_ADAPTER_LABELS, adapter),
        "model": _attr(verdict, "model"),
        "evidence": [_evidence_view(item) for item in (_attr(verdict, "evidence") or [])],
        "conditions": [str(item) for item in (_attr(verdict, "conditions") or [])],
        "uncertainty": _attr(verdict, "uncertainty"),
        "validated_at": _attr(verdict, "validated_at", ""),
        "schema_version": _attr(
            verdict, "schema_version", models.JUDGE_SCHEMA_VERSION
        ),
    }


def _unjudged_reason(attempts: list[dict[str, Any]]) -> str:
    for attempt in reversed(attempts):
        if attempt["error_category"]:
            return f"未能判定：{attempt['error_label']}"
    for attempt in reversed(attempts):
        if attempt["fallback_reason"]:
            return f"未能判定：{attempt['fallback_label']}"
    return "适配器未返回有效判定。"


def _judge_views(detail: RunDetail) -> dict[str, Any] | None:
    """Build the Judge display model, or ``None`` when Judge did not run.

    ``judge_attempts``/``judge_verdicts`` are P1 ``RunDetail`` fields；the
    ``getattr`` fallbacks keep the dashboard working against a P0 database and
    while the storage P1 migration is still being written.
    """

    attempts = list(getattr(detail, "judge_attempts", None) or [])
    verdicts = list(getattr(detail, "judge_verdicts", None) or [])
    if not attempts and not verdicts:
        return None
    run = detail.run
    metrics = run.metrics if isinstance(run.metrics, dict) else {}
    judge_metrics = metrics.get("judge") if isinstance(metrics.get("judge"), dict) else {}
    status = str(
        judge_metrics.get("status")
        or (models.JUDGE_COMPLETED if verdicts else models.JUDGE_DISABLED)
    )
    attempts_by_candidate: dict[str, list[Any]] = {}
    for attempt in attempts:
        attempts_by_candidate.setdefault(_attr(attempt, "candidate_id", ""), []).append(attempt)
    verdicts_by_candidate: dict[str, Any] = {}
    for verdict in verdicts:
        candidate_id = _attr(verdict, "candidate_id", "")
        existing = verdicts_by_candidate.get(candidate_id)
        if existing is None or int(_attr(verdict, "attempt_no", 0) or 0) >= int(
            _attr(existing, "attempt_no", 0) or 0
        ):
            verdicts_by_candidate[candidate_id] = verdict

    ordered_ids: list[str] = []
    for candidate in detail.candidates:
        if (
            candidate.candidate_id in attempts_by_candidate
            or candidate.candidate_id in verdicts_by_candidate
        ):
            ordered_ids.append(candidate.candidate_id)
    for candidate_id in sorted(
        set(attempts_by_candidate) | set(verdicts_by_candidate)
    ):
        if candidate_id not in ordered_ids:
            ordered_ids.append(candidate_id)

    candidates_by_id = {item.candidate_id: item for item in detail.candidates}
    verdict_counts = {code: 0 for code in models.VERDICTS}
    rows: list[dict[str, Any]] = []
    for candidate_id in ordered_ids:
        attempt_views = [
            _attempt_view(attempt)
            for attempt in sorted(
                attempts_by_candidate.get(candidate_id, []),
                key=lambda item: (
                    int(_attr(item, "attempt_no", 0) or 0),
                    str(_attr(item, "attempt_id", "")),
                ),
            )
        ]
        verdict = verdicts_by_candidate.get(candidate_id)
        verdict_view = _verdict_view(verdict) if verdict is not None else None
        if verdict_view is not None and verdict_view["verdict"] in verdict_counts:
            verdict_counts[verdict_view["verdict"]] += 1
        candidate = candidates_by_id.get(candidate_id)
        verdict_attempt = next(
            (
                view
                for view in attempt_views
                if verdict_view is not None
                and view["attempt_no"] == verdict_view["attempt_no"]
            ),
            None,
        )
        cache_hit = bool(
            (verdict_attempt and verdict_attempt["cache_hit"])
            or any(view["cache_hit"] for view in attempt_views)
            or (verdict_view is not None and verdict_view["adapter"] == "cache")
        )
        fallback_events = [
            {
                "attempt_no": view["attempt_no"],
                "label": view["fallback_label"],
                "raw": view["fallback_reason"],
            }
            for view in attempt_views
            if view["fallback_reason"]
        ]
        rows.append(
            {
                "candidate_id": candidate_id,
                "candidate": _symbol_view(candidate.candidate_symbol_id, detail.symbols)
                if candidate is not None
                else None,
                "candidate_symbol_id": candidate.candidate_symbol_id
                if candidate is not None
                else None,
                "verdict": verdict_view,
                "verdict_code": verdict_view["verdict"] if verdict_view else "unknown",
                "verdict_label": verdict_view["verdict_label"]
                if verdict_view
                else _VERDICT_UNKNOWN_LABEL,
                "has_verdict": verdict_view is not None,
                "reason": verdict_view["reason"]
                if verdict_view
                else _unjudged_reason(attempt_views),
                "attempts": attempt_views,
                "attempt_sequence": " → ".join(
                    f"#{view['attempt_no']} {view['adapter_label']}"
                    for view in attempt_views
                )
                or "-",
                "cache_hit": cache_hit,
                "fallback_events": fallback_events,
                "fallback": bool(fallback_events),
            }
        )

    return {
        "status": status,
        "status_label": _label(_JUDGE_STATUS_LABELS, status),
        "requested": bool(judge_metrics.get("requested", attempts or verdicts)),
        "attempts_count": len(attempts),
        "verdicts_count": len(verdicts),
        "cache_hits": int(
            judge_metrics.get(
                "cache_hits",
                sum(1 for attempt in attempts if _attr(attempt, "cache_hit", False)),
            )
        ),
        "verdict_counts": [
            {"code": code, "label": _label(_VERDICT_LABELS, code), "count": verdict_counts[code]}
            for code in models.VERDICTS
        ],
        "rows": rows,
        "note": "以下判定是静态推断结果，仅供参考。",
    }


# --------------------------------------------------------------------------
# M1 settings / tasks view models
# --------------------------------------------------------------------------

TASK_POLL_SECONDS = 3

_TASK_STATUS_LABELS = {
    models.TASK_QUEUED: "排队中",
    models.TASK_RUNNING: "运行中",
    models.TASK_COMPLETED: "已完成",
    models.TASK_PARTIAL: "部分完成",
    models.TASK_FAILED: "失败",
    models.TASK_CANCELLED: "已取消",
    models.TASK_INTERRUPTED: "已中断",
}
_TASK_EVENT_LABELS = {"start": "开始", "done": "完成", "failed": "失败", "info": "信息"}
_SETTINGS_SOURCE_LABELS = {
    "project": "项目配置文件",
    "template": "内置模板（尚未创建项目配置）",
}
_SETTINGS_FIELD_NOTES = [
    {
        "field": "git.mode / git.base / git.include_untracked",
        "note": "默认比较端点；commit / range 模式由任务表单临时选择。",
    },
    {
        "field": "files.include / exclude / source_roots",
        "note": "纳入分析的文件规则与模块根目录；两侧一致应用。",
    },
    {
        "field": "analysis.*",
        "note": "差异、AST、影响追踪与测试推荐的数量/大小上限。",
    },
    {
        "field": "judge.*",
        "note": "Judge 适配器、回退触发、预算；端点与凭据只来自环境变量。",
    },
    {
        "field": "storage.*",
        "note": "证据留存模式、大小上限、保留天数与历史条数。",
    },
    {
        "field": "web.host / web.port / logging.level",
        "note": "监听地址、端口与日志级别；修改后需要重启 Web 服务。",
    },
]

_TASK_TERMINAL_STATUSES = frozenset(
    {
        models.TASK_COMPLETED,
        models.TASK_PARTIAL,
        models.TASK_FAILED,
        models.TASK_CANCELLED,
        models.TASK_INTERRUPTED,
    }
)

#: Storage methods required by the M1 task pages (delivered by storage.py).
_TASK_STORE_METHODS = ("get_task", "list_tasks", "cancel_task")


def _config_edit_module() -> Any:
    """Lazy import so the read-only dashboard still works during M1 work."""

    from .. import config_edit

    return config_edit


def _tasks_module() -> Any:
    from .. import tasks

    return tasks


def _task_storage_ready() -> bool:
    return all(hasattr(Storage, name) for name in _TASK_STORE_METHODS)


def _load_project_config(repo_root: Path) -> tuple[Any, str | None]:
    """Load the effective project configuration; never raises."""

    from .. import config as config_mod

    try:
        config, _path = config_mod.load_config(Path(repo_root))
        return config, None
    except Exception as exc:  # ConfigError and friends
        try:
            fallback = config_mod.Config()
        except Exception:  # pragma: no cover - defensive
            fallback = None
        return fallback, f"项目配置无效：{exc}"


def _pretty_json(value: Any) -> str:
    try:
        return json.dumps(
            value, ensure_ascii=False, indent=2, sort_keys=True, default=str
        )
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return str(value)


def _value_display(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return _pretty_json(value)
    return str(value)


def _judge_form_info(config: Any) -> dict[str, Any]:
    judge = getattr(config, "judge", None)
    jev = getattr(judge, "jev", None)
    llm = getattr(judge, "llm", None)
    jev_profile = getattr(jev, "profile", None)
    llm_protocol = getattr(llm, "protocol", None)
    providers: list[str] = []
    if jev_profile:
        providers.append(f"JEV（{jev_profile}）")
    if llm_protocol:
        providers.append(f"LLM（{llm_protocol}）")
    configured = bool(providers)
    return {
        "configured": configured,
        "providers": providers,
        "provider_text": "、".join(providers) if providers else "未配置适配器",
        "jev_profile": jev_profile,
        "jev_model": getattr(jev, "model", None),
        "llm_protocol": llm_protocol,
        "llm_model": getattr(llm, "model", None),
        "max_attempts": getattr(judge, "max_attempts", "-"),
        "max_total_tokens": getattr(judge, "max_total_tokens", "-"),
        "max_input_tokens_per_attempt": getattr(
            judge, "max_input_tokens_per_attempt", "-"
        ),
        "run_deadline_seconds": getattr(judge, "run_deadline_seconds", "-"),
        "send_scope": (
            "仅发送裁剪后的变更 hunk、符号定义与调用点片段；"
            "不发送整文件、仓库路径、凭据或无关调用路径。"
        ),
        "disabled_reason": (
            None
            if configured
            else "项目配置未设置 judge.jev.profile 或 judge.llm.protocol，Judge 不可用。"
        ),
    }


def _mode_options(selected: str | None = None) -> list[dict[str, Any]]:
    return [
        {
            "value": mode,
            "label": _label(_MODE_LABELS, mode, mode),
            "selected": mode == selected,
        }
        for mode in models.ALL_MODES
    ]


# -- settings ---------------------------------------------------------------


# -- settings: structured form (settings_form.py, US-4) ---------------------

_SETTINGS_FIELD_SOURCE_LABELS = {
    "project": "项目文件",
    "template": "内置模板",
    "default": "内置默认",
}


def _settings_form_module() -> Any:
    """Lazy import of the optional structured settings form module."""

    from .. import settings_form

    return settings_form


def _nested_get(mapping: Any, dotted_path: str) -> Any:
    current = mapping
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _request_host_and_port(request: Request) -> tuple[str | None, str | None]:
    value = str(request.headers.get("host", "") or "").strip().lower()
    if not value:
        return None, None
    if value.startswith("["):
        end = value.find("]")
        host = value[1:end] if end >= 0 else value
        rest = value[end + 1 :] if end >= 0 else ""
        port = rest[1:] if rest.startswith(":") else ""
        return host or None, port or None
    host, separator, port = value.partition(":")
    return host or None, (port if separator else None)


def _settings_field_display(spec: Any, value: Any) -> str:
    """Render one config value the way its control expects it."""

    kind = str(_attr(spec, "kind", "text") or "text")
    if kind == "list":
        if value is None:
            items: list[Any] = []
        elif isinstance(value, (list, tuple)):
            items = list(value)
        else:
            items = [value]
        return "\n".join(str(item) for item in items)
    if kind == "tristate":
        if value is None:
            return ""
        return "true" if bool(value) else "false"
    if kind == "bool":
        return "true" if bool(value) else "false"
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def _settings_choices(spec: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in _attr(spec, "choices", ()) or ():
        if isinstance(item, (tuple, list)) and len(item) >= 2:
            value, label = str(item[0]), str(item[1])
        else:  # pragma: no cover - defensive
            value = label = str(item)
        result.append({"value": value, "label": label, "selected": False})
    return result


def _settings_conditional_note(spec: Any) -> str | None:
    condition = _attr(spec, "conditional", None)
    if not condition:
        return None
    if condition == "git.mode==base":
        return "提示：仅当 git.mode=base 时使用该基线引用。"
    return f"提示：{condition}"


def _settings_runtime_rows(
    fields: list[dict[str, Any]],
    view: Any,
    request: Request,
    db_path: Path,
) -> list[dict[str, Any]]:
    """Saved project values vs the actual values of the running instance."""

    effective = _attr(view, "effective", {}) or {}
    host, port = _request_host_and_port(request)
    runtime = {
        "web.host": host or "-",
        "web.port": port or "-",
        "storage.path": str(db_path),
    }
    saved = {
        "web.host": _nested_get(effective, "web.host"),
        "web.port": _nested_get(effective, "web.port"),
        "storage.path": _nested_get(effective, "storage.path"),
    }
    rows: list[dict[str, Any]] = []
    for field in fields:
        if field.get("group") != "service":
            continue
        path = field["path"]
        if path not in runtime:
            continue
        saved_value = saved.get(path)
        if path == "storage.path" and saved_value is None:
            saved_display = "（默认位置）"
        else:
            saved_display = _value_display(saved_value)
        runtime_display = runtime[path]
        rows.append(
            {
                "path": path,
                "label": field["label"],
                "saved": saved_display,
                "runtime": runtime_display,
                "differs": saved_display != runtime_display,
            }
        )
    return rows


def _build_structured_settings(
    form_module: Any,
    view: Any,
    request: Request,
    db_path: Path,
    *,
    draft_values: dict[str, Any] | None = None,
    removes: set[str] | None = None,
    field_errors: list[Any] | None = None,
) -> dict[str, Any] | None:
    """Build the grouped structured-form view model from ``settings_form``."""

    if form_module is None or view is None:
        return None
    removes = set(removes or ())
    try:
        field_values = form_module.load_field_values(view, reset_paths=set(removes))
    except Exception:  # pragma: no cover - defensive around the optional module
        return None
    error_map: dict[str, str] = {}
    top_errors: list[str] = []
    for item in field_errors or []:
        field_name = str(_attr(item, "field", "") or "")
        message = str(_attr(item, "message", "") or "")
        if field_name:
            error_map.setdefault(field_name, message)
        elif message:
            top_errors.append(message)

    fields: list[dict[str, Any]] = []
    restart_fields: list[str] = []
    for field_value in field_values:
        spec = _attr(field_value, "spec", None)
        path = str(_attr(spec, "path", "") or "")
        if not path:
            continue
        kind = str(_attr(spec, "kind", "text") or "text")
        label = str(_attr(spec, "label", path) or path)
        group = str(_attr(spec, "group", "default") or "default")
        display = str(_attr(field_value, "display", "") or "")
        if draft_values is not None and path in draft_values:
            display = _settings_field_display(spec, draft_values[path])
        source = str(_attr(field_value, "source", "default") or "default")
        minimum = _attr(spec, "minimum", None)
        maximum = _attr(spec, "maximum", None)
        unit = str(_attr(spec, "unit", "") or "")
        restart = bool(_attr(spec, "restart", False))
        choices = _settings_choices(spec)
        for choice in choices:
            choice["selected"] = choice["value"] == display
        tristate_options = [
            {"value": "", "label": "按模式默认（空）", "selected": display == ""},
            {"value": "true", "label": "包含", "selected": display == "true"},
            {"value": "false", "label": "排除", "selected": display == "false"},
        ]
        bool_options = [
            {"value": "true", "label": "是", "selected": display == "true"},
            {"value": "false", "label": "否", "selected": display == "false"},
        ]
        has_range = minimum is not None or maximum is not None
        field = {
            "path": path,
            "label": label,
            "group": group,
            "kind": kind,
            "help": str(_attr(spec, "help", "") or ""),
            "display": display,
            "source": source,
            "source_label": _label(_SETTINGS_FIELD_SOURCE_LABELS, source, source),
            "choices": choices,
            "tristate_options": tristate_options,
            "bool_options": bool_options,
            "minimum": minimum,
            "maximum": maximum,
            "unit": unit,
            "restart": restart,
            "conditional": _attr(spec, "conditional", None),
            "conditional_note": _settings_conditional_note(spec),
            "rows": int(_attr(spec, "rows", 4) or 4),
            "reset": bool(_attr(field_value, "reset", False)) or path in removes,
            "reset_name": f"reset:{path}",
            "error": error_map.get(path, ""),
            "has_range": has_range,
        }
        if restart:
            restart_fields.append(label)
        fields.append(field)

    groups: list[dict[str, Any]] = []
    for item in getattr(form_module, "GROUPS", ()) or ():
        if isinstance(item, (tuple, list)) and len(item) >= 3:
            group_id, title, description = (str(item[0]), str(item[1]), str(item[2]))
        else:  # pragma: no cover - defensive
            group_id = str(_attr(item, "id", ""))
            title = str(_attr(item, "title", group_id))
            description = str(_attr(item, "description", ""))
        groups.append(
            {
                "id": group_id,
                "title": title,
                "description": description,
                "fields": [field for field in fields if field["group"] == group_id],
            }
        )
    return {
        "groups": groups,
        "fields": fields,
        "errors": top_errors,
        "error_map": error_map,
        "restart_fields": restart_fields,
        "runtime": _settings_runtime_rows(fields, view, request, db_path),
    }


def _settings_draft_values(
    form: Any, errors: list[Any], form_module: Any
) -> dict[str, Any]:
    """Recover the raw submitted text of fields that failed parsing.

    ``parse_form`` only returns successfully parsed values, so an invalid value
    (for example ``999`` in an int field) would otherwise be replaced by the
    stored value when the page is re-rendered.  Keeping the raw text here makes
    the error state preserve the user's draft next to the control.
    """

    drafts: dict[str, Any] = {}
    field_by_path = getattr(form_module, "FIELD_BY_PATH", None)
    if not field_by_path:
        field_by_path = {
            spec.path: spec for spec in getattr(form_module, "FIELDS", ()) or ()
        }
    for item in errors or []:
        path = str(_attr(item, "field", "") or "")
        if not path or path in drafts:
            continue
        raw = form.get(path)
        if raw is None:
            continue
        text = str(raw)
        spec = field_by_path.get(path)
        kind = str(_attr(spec, "kind", "text") or "text")
        if kind == "list":
            drafts[path] = [
                line.strip() for line in text.splitlines() if line.strip()
            ]
        else:
            drafts[path] = text.strip()
    return drafts


def _normalize_settings_view(view: Any) -> dict[str, Any]:
    source = str(_attr(view, "source", "template") or "template")
    return {
        "path": _attr(view, "path", None),
        "exists": bool(_attr(view, "exists", False)),
        "source": source,
        "source_label": _label(_SETTINGS_SOURCE_LABELS, source, source),
        "raw": str(_attr(view, "raw", "") or ""),
        "digest": str(_attr(view, "digest", "") or ""),
        "effective_text": _pretty_json(_attr(view, "effective", {}) or {}),
    }


def _normalize_settings_preview(preview: Any) -> dict[str, Any] | None:
    if preview is None:
        return None
    errors = []
    for item in _attr(preview, "errors", []) or []:
        errors.append(
            {
                "field": str(_attr(item, "field", "") or ""),
                "message": str(_attr(item, "message", "") or ""),
                "line": _attr(item, "line", None),
            }
        )
    diff = []
    for item in _attr(preview, "diff", []) or []:
        diff.append(
            {
                "field": str(_attr(item, "field", "") or ""),
                "old": _value_display(_attr(item, "old", None)),
                "new": _value_display(_attr(item, "new", None)),
            }
        )
    return {
        "ok": bool(_attr(preview, "ok", False)),
        "errors": errors,
        "warnings": [str(item) for item in (_attr(preview, "warnings", []) or [])],
        "diff": diff,
        "effective_text": _pretty_json(_attr(preview, "effective", {}) or {}),
        "preview_digest": str(_attr(preview, "preview_digest", "") or ""),
        "path": str(_attr(preview, "path", "") or ""),
    }


def _settings_context(
    request: Request,
    *,
    view: Any = None,
    raw: str | None = None,
    preview: Any = None,
    error: str | None = None,
    conflict: bool = False,
    saved: bool = False,
    structured: dict[str, Any] | None = None,
    notice: str | None = None,
    extra_warnings: list[str] | None = None,
    structured_preview: bool = False,
) -> dict[str, Any]:
    view_data = _normalize_settings_view(view) if view is not None else {
        "path": None,
        "exists": False,
        "source": "template",
        "source_label": _label(_SETTINGS_SOURCE_LABELS, "template"),
        "raw": "",
        "digest": "",
        "effective_text": "{}",
    }
    raw_text = view_data["raw"] if raw is None else raw
    preview_data = _normalize_settings_preview(preview)
    if preview_data is not None and extra_warnings:
        preview_data["warnings"] = list(preview_data["warnings"]) + [
            warning for warning in extra_warnings if warning not in preview_data["warnings"]
        ]
    return {
        "request": request,
        "m1_enabled": True,
        "active": "settings",
        "settings": view_data,
        "raw": raw_text,
        "expected_digest": view_data["digest"],
        "preview": preview_data,
        "error_message": error,
        "conflict": conflict,
        "saved": saved,
        "field_notes": _SETTINGS_FIELD_NOTES,
        "structured": structured,
        "settings_notice": notice,
        "structured_preview": bool(structured_preview),
    }


# -- tasks ------------------------------------------------------------------


def _task_status_label(status: str | None) -> str:
    return _label(_TASK_STATUS_LABELS, status, status or "-")


def _task_status_class(status: str | None) -> str:
    return f"status-{status}" if status else "status-unknown"


def _task_is_active(record: Any) -> bool:
    return str(_attr(record, "status", "")) in (
        models.TASK_QUEUED,
        models.TASK_RUNNING,
    )


def _task_stage_views(stages: Any) -> list[dict[str, Any]]:
    views = []
    for event in stages or []:
        data = event if isinstance(event, dict) else _attr(event, "__dict__", {}) or {}
        stage = str(data.get("stage", "") or "")
        status = str(data.get("status", "") or "")
        duration_ms = data.get("duration_ms")
        views.append(
            {
                "stage": stage,
                "stage_label": _label(_STAGE_LABELS, stage, stage or "-"),
                "status": status,
                "status_label": _label(_TASK_EVENT_LABELS, status, status or "-"),
                "at": data.get("at"),
                "time": _time_view(data.get("at"), fallback="-"),
                "duration_ms": duration_ms,
                "duration_text": _format_duration_ms(duration_ms)
                if duration_ms is not None
                else "",
            }
        )
    return views


def _task_diagnostic_views(diagnostics: Any) -> list[dict[str, Any]]:
    views = []
    for item in diagnostics or []:
        if isinstance(item, dict):
            data = dict(item)
        elif hasattr(item, "to_dict"):
            data = item.to_dict()
        else:  # pragma: no cover - defensive
            data = dict(vars(item))
        severity = str(data.get("severity", "warning") or "warning")
        views.append(
            {
                "code": str(data.get("code", "") or ""),
                "message": str(data.get("message", "") or ""),
                "severity": severity,
                "severity_label": _label(_SEVERITY_LABELS, severity, severity),
                "path": data.get("path"),
                "line": data.get("line"),
            }
        )
    return views


def _task_params_summary(record: Any) -> str:
    parts = [_label(_MODE_LABELS, _attr(record, "mode", ""), str(_attr(record, "mode", "")))]
    base_ref = _attr(record, "base_ref", None)
    commit_ref = _attr(record, "commit_ref", None)
    range_spec = _attr(record, "range_spec", None)
    parent_index = _attr(record, "parent_index", None)
    if base_ref:
        parts.append(f"base={base_ref}")
    if commit_ref:
        parts.append(f"commit={commit_ref}")
    if range_spec:
        parts.append(f"range={range_spec}")
    if parent_index is not None:
        parts.append(f"parent={parent_index}")
    parts.append("Judge 开启" if _attr(record, "judge", False) else "Judge 关闭")
    if _attr(record, "include_untracked", False):
        parts.append("包含未跟踪文件")
    return " · ".join(parts)


def _task_view(record: Any, *, detail: bool = False) -> dict[str, Any]:
    status = str(_attr(record, "status", models.TASK_QUEUED) or models.TASK_QUEUED)
    run_id = _attr(record, "run_id", None)
    stages = _task_stage_views(_attr(record, "stages", []) or [])
    current_stage = stages[-1] if stages else None
    created_time = _time_view(_attr(record, "created_at", None))
    started_time = _time_view(_attr(record, "started_at", None))
    finished_time = _time_view(_attr(record, "finished_at", None))
    heartbeat_time = _time_view(_attr(record, "worker_heartbeat_at", None))
    duration = _duration_since(
        _attr(record, "started_at", None),
        _attr(record, "finished_at", None),
        active=status == models.TASK_RUNNING,
    )
    if status == models.TASK_QUEUED:
        duration_text = "等待 worker 领取"
    else:
        duration_text = duration["text"]
    updated_time = (
        finished_time
        if finished_time["valid"]
        else (
            current_stage["time"]
            if current_stage is not None and current_stage["time"]["valid"]
            else (started_time if started_time["valid"] else created_time)
        )
    )
    status_view = _status_view(status, _TASK_STATUS_LABELS)
    diagnostics = _task_diagnostic_views(_attr(record, "diagnostics", []) or [])
    failure_message = next(
        (
            diagnostic["message"]
            for diagnostic in diagnostics
            if diagnostic["severity"] == "error"
        ),
        None,
    )
    error_code = _attr(record, "error_code", None)
    view = {
        "task_id": str(_attr(record, "task_id", "") or ""),
        "repo_id": _attr(record, "repo_id", ""),
        "repo_root": _attr(record, "repo_root", ""),
        "status": status,
        "status_label": status_view["label"],
        "status_symbol": status_view["symbol"],
        "status_class": _task_status_class(status),
        "group": _task_group(status),
        "is_active": status in (models.TASK_QUEUED, models.TASK_RUNNING),
        "can_cancel": status == models.TASK_QUEUED,
        "can_retry": status in _TASK_TERMINAL_STATUSES,
        "mode": str(_attr(record, "mode", "") or ""),
        "mode_label": _label(
            _MODE_LABELS, _attr(record, "mode", ""), str(_attr(record, "mode", "") or "-")
        ),
        "base_ref": _attr(record, "base_ref", None),
        "commit_ref": _attr(record, "commit_ref", None),
        "range_spec": _attr(record, "range_spec", None),
        "parent_index": _attr(record, "parent_index", None),
        "judge": bool(_attr(record, "judge", False)),
        "include_untracked": bool(_attr(record, "include_untracked", False)),
        "config_digest": str(_attr(record, "config_digest", "") or ""),
        "error_code": error_code,
        "failure_reason": str(error_code) if error_code else None,
        "failure_message": failure_message,
        "task_key": _attr(record, "task_key", None),
        "run_id": run_id,
        "run_href": f"/runs/{run_id}" if run_id else None,
        "created_at": _attr(record, "created_at", ""),
        "started_at": _attr(record, "started_at", None),
        "finished_at": _attr(record, "finished_at", None),
        "worker_heartbeat_at": _attr(record, "worker_heartbeat_at", None),
        "created_time": created_time,
        "started_time": started_time,
        "finished_time": finished_time,
        "heartbeat_time": heartbeat_time,
        "updated_time": updated_time,
        "duration": duration,
        "duration_text": duration_text,
        "current_stage": current_stage,
        "stages": stages,
        "diagnostics": diagnostics,
        "params_summary": _task_params_summary(record),
    }
    if detail:
        view["config_text"] = _pretty_json(_attr(record, "config_json", {}) or {})
        view["request_text"] = _pretty_json(_attr(record, "request", {}) or {})
    return view


def _task_form_values(
    form: Any = None, record: Any = None
) -> dict[str, Any]:
    values: dict[str, Any] = {
        "mode": models.MODE_WORKTREE_NET,
        "base_ref": "",
        "commit_ref": "",
        "range_spec": "",
        "parent_index": "",
        "judge": False,
        "include_untracked": False,
    }
    if record is not None:
        parent_index = _attr(record, "parent_index", None)
        values.update(
            {
                "mode": str(
                    _attr(record, "mode", models.MODE_WORKTREE_NET)
                    or models.MODE_WORKTREE_NET
                ),
                "base_ref": str(_attr(record, "base_ref", None) or ""),
                "commit_ref": str(_attr(record, "commit_ref", None) or ""),
                "range_spec": str(_attr(record, "range_spec", None) or ""),
                "parent_index": "" if parent_index is None else str(parent_index),
                "judge": bool(_attr(record, "judge", False)),
                "include_untracked": bool(_attr(record, "include_untracked", False)),
            }
        )
    if form is not None:
        values.update(
            {
                "mode": str(form.get("mode", "") or values["mode"]),
                "base_ref": str(form.get("base_ref", "") or ""),
                "commit_ref": str(form.get("commit_ref", "") or ""),
                "range_spec": str(form.get("range_spec", "") or ""),
                "parent_index": str(form.get("parent_index", "") or ""),
                "judge": _form_checkbox(form, "judge"),
                "include_untracked": _form_checkbox(form, "include_untracked"),
            }
        )
    return values


def _task_params_from_form(form: Any) -> dict[str, Any]:
    """Validate the enumerated/size-limited task form values (400 on failure)."""

    mode = str(form.get("mode", "") or "").strip()
    if mode not in models.ALL_MODES:
        raise ValueError("不支持的分析模式")
    base_ref = _form_text(form, "base_ref", max_length=MAX_REF_LENGTH)
    commit_ref = _form_text(form, "commit_ref", max_length=MAX_REF_LENGTH)
    range_spec = _form_text(form, "range_spec", max_length=MAX_RANGE_LENGTH)
    parent_raw = _form_text(form, "parent_index", max_length=8)
    parent_index = None
    if parent_raw is not None:
        if not parent_raw.isdigit():
            raise ValueError("parent_index 必须是正整数")
        parent_index = int(parent_raw)
        if not 1 <= parent_index <= 64:
            raise ValueError("parent_index 必须在 1 到 64 之间")
    include_untracked = _form_checkbox(form, "include_untracked")
    if include_untracked and mode != models.MODE_WORKING_TREE:
        raise ValueError("include_untracked 仅适用于 working-tree 模式")
    if parent_index is not None and mode != models.MODE_COMMIT:
        raise ValueError("parent_index 仅适用于 commit 模式")
    return {
        "mode": mode,
        "base_ref": base_ref,
        "commit_ref": commit_ref,
        "range_spec": range_spec,
        "parent_index": parent_index,
        "judge": _form_checkbox(form, "judge"),
        "include_untracked": include_untracked,
    }


def _task_endpoint_preview(
    form_values: dict[str, Any], config: Any
) -> dict[str, Any]:
    """Natural-language endpoint preview for the task form (server text)."""

    mode = str(form_values.get("mode") or models.MODE_WORKTREE_NET)
    base_default = (
        str(getattr(getattr(config, "git", None), "base", None) or "main").strip()
        or "main"
    )
    base_ref = str(form_values.get("base_ref") or "").strip()
    commit_ref = str(form_values.get("commit_ref") or "").strip()
    range_spec = str(form_values.get("range_spec") or "").strip()
    parent_index = str(form_values.get("parent_index") or "").strip()
    hint = ""
    if mode == models.MODE_WORKTREE_NET:
        text = "HEAD → 工作区（含未提交与未忽略的未跟踪改动）"
        hint = "默认净差异：比较 HEAD 提交树与当前工作区。"
    elif mode == models.MODE_STAGED:
        text = "HEAD → 暂存区（index）"
        hint = "只比较已暂存内容，工作区未暂存改动不参与。"
    elif mode == models.MODE_WORKING_TREE:
        text = "暂存区（index） → 工作区"
        hint = "比较已暂存内容与当前工作区；可选包含未跟踪文件。"
    elif mode == models.MODE_BASE:
        base = base_ref or base_default
        text = f"{base}（合并基线） → HEAD"
        hint = f"只读取提交树：merge-base({base}, HEAD) → HEAD，工作区状态不影响结果。"
    elif mode == models.MODE_COMMIT:
        reference = commit_ref or "（待填写提交引用）"
        if parent_index:
            text = f"{reference}^（父提交 {parent_index}） → {reference}"
        else:
            text = f"{reference}^（父提交） → {reference}"
        hint = "只读取 Git 对象；merge commit 建议在“高级选项”里选择父提交序号。"
    elif mode == models.MODE_RANGE:
        if "..." in range_spec:
            left, _, right = range_spec.partition("...")
            left = left.strip() or "A"
            right = right.strip() or "B"
            text = f"{left} 的合并基线 → {right}"
            hint = "三点区间 A...B：比较共同祖先与 B。"
        elif ".." in range_spec:
            left, _, right = range_spec.partition("..")
            left = left.strip() or "A"
            right = right.strip() or "B"
            text = f"{left} → {right}"
            hint = "两点区间 A..B：比较两个提交树。"
        else:
            text = "（输入 A..B 或 A...B）"
            hint = "range 模式必须提供非空的 A..B 或 A...B。"
    else:  # pragma: no cover - enumeration validated earlier
        text = "-"
    return {
        "mode": mode,
        "mode_label": _label(_MODE_LABELS, mode, mode),
        "text": text,
        "hint": hint,
        "default_base": base_default,
    }


_TASK_FIELD_ERROR_HINTS = (
    ("mode", ("不支持的分析模式", "比较模式", "mode")),
    ("commit_ref", ("commit_ref", "commit 模式", "提交引用")),
    ("range_spec", ("range_spec", "range 模式", "提交区间")),
    ("base_ref", ("base_ref", "base 模式", "基线")),
    ("parent_index", ("parent_index", "父提交")),
    ("include_untracked", ("include_untracked", "未跟踪")),
)


def _task_field_errors(message: str | None) -> dict[str, str]:
    """Map a task validation message back to the control that caused it."""

    if not message:
        return {}
    text = str(message)
    errors: dict[str, str] = {}
    for field, keywords in _TASK_FIELD_ERROR_HINTS:
        if any(keyword in text for keyword in keywords):
            errors[field] = text
    return errors


def _task_new_context(
    request: Request,
    *,
    form_values: dict[str, Any],
    judge_info: dict[str, Any],
    config_error: str | None = None,
    error: str | None = None,
    notice: str | None = None,
    from_task_id: str | None = None,
    task_key: str | None = None,
    endpoint_preview: dict[str, Any] | None = None,
    field_errors: dict[str, str] | None = None,
    default_base: str = "main",
) -> dict[str, Any]:
    return {
        "request": request,
        "m1_enabled": True,
        "active": "tasks",
        "form": form_values,
        "mode_options": _mode_options(str(form_values.get("mode") or "")),
        "judge_info": judge_info,
        "config_error": config_error,
        "error_message": error,
        "error_fields": field_errors or {},
        "endpoint_preview": endpoint_preview or {
            "text": "-",
            "hint": "",
            "default_base": default_base,
        },
        "default_base": default_base,
        "notice": notice,
        "from_task_id": from_task_id,
        "task_key": task_key or secrets.token_hex(16),
    }


def _run_task_source(
    db_path: Path, repo_id: str | None, run_id: str
) -> dict[str, Any] | None:
    """Return the queue task that produced ``run_id`` (P1/M1 linkage)."""

    if not hasattr(Storage, "get_task_for_run"):
        return None
    store = Storage(db_path, read_only=True)
    try:
        record = store.get_task_for_run(run_id)
    except Exception:  # pragma: no cover - missing task API / older database
        return None
    finally:
        store.close()
    if record is None:
        return None
    if repo_id is not None and _attr(record, "repo_id", None) != repo_id:
        return None
    return _task_view(record)


def _task_sources_for_runs(
    db_path: Path, repo_id: str | None, run_ids: list[str]
) -> dict[str, str]:
    """Map ``run_id -> task_id`` for the history table (one read connection)."""

    if not run_ids or not hasattr(Storage, "get_task_for_run"):
        return {}
    store = Storage(db_path, read_only=True)
    try:
        sources: dict[str, str] = {}
        for run_id in run_ids:
            try:
                record = store.get_task_for_run(run_id)
            except Exception:  # pragma: no cover - defensive
                continue
            if record is None:
                continue
            if repo_id is not None and _attr(record, "repo_id", None) != repo_id:
                continue
            task_id = _attr(record, "task_id", None)
            if task_id:
                sources[run_id] = str(task_id)
        return sources
    finally:
        store.close()


def _progress_fragment(record: Any) -> Response:
    """Small server-rendered progress fragment for the no-JS polling page."""

    view = _task_view(record)
    active = view["is_active"]
    stages = view["stages"]
    started = sum(1 for stage in stages if stage["status"] in ("start", "done", "failed"))
    stage_items = "".join(
        "<li><code>{}</code> {}{}{}</li>".format(
            _html_escape(stage["stage_label"]),
            _html_escape(stage["status_label"]),
            "" if stage.get("duration_ms") is None else f" · {stage['duration_ms']} ms",
            ""
            if not stage.get("at")
            else f" · {_html_escape(str(stage['at']))}",
        )
        for stage in stages[-12:]
    )
    parts = [
        '<div class="task-progress" data-task-id="{}" data-status="{}"'
        ' data-active="{}" data-stages="{}">'.format(
            _html_escape(view["task_id"]),
            _html_escape(view["status"]),
            "1" if active else "0",
            len(stages),
        ),
        '<p>状态：<span class="status {}">{}</span></p>'.format(
            _html_escape(view["status_class"]),
            _html_escape(view["status_label"]),
        ),
    ]
    if view["current_stage"]:
        stage = view["current_stage"]
        parts.append(
            '<p>当前阶段：<code>{}</code> <span class="task-stage-status task-stage-{}">{}</span>{} </p>'.format(
                _html_escape(stage["stage_label"]),
                _html_escape(stage["status"]),
                _html_escape(stage["status_label"]),
                ""
                if not stage["time"]["valid"]
                else f' <span class="meta">{_html_escape(stage["time"]["text"])}</span>',
            )
        )
    parts.append(
        '<p>已耗时：<span data-task-duration>{}</span></p>'.format(
            _html_escape(view["duration_text"])
        )
    )
    parts.append(
        '<p>更新时间：<span data-task-updated title="{}">{}</span></p>'.format(
            _html_escape(str(view["updated_time"]["title"] or "")),
            _html_escape(view["updated_time"]["text"]),
        )
    )
    if view["worker_heartbeat_at"]:
        parts.append(
            "<p class=\"meta\">worker 心跳：{}</p>".format(
                _html_escape(str(view["worker_heartbeat_at"]))
            )
        )
    if stages:
        parts.append(f"<p>已记录阶段事件：{started}/{len(stages)}</p>")
        parts.append(f'<ol class="task-stages">{stage_items}</ol>')
    else:
        parts.append('<p class="muted">尚无阶段事件。</p>')
    if active:
        parts.append(
            f'<p class="meta">任务尚未结束，页面每 {TASK_POLL_SECONDS} 秒自动刷新。</p>'
        )
    else:
        parts.append('<p class="meta">任务已结束，停止刷新。</p>')
    if view["run_href"]:
        parts.append(
            '<p><a class="button" href="{}">查看生成的 Run</a></p>'.format(
                _html_escape(view["run_href"])
            )
        )
    parts.append("</div>")
    return _private_response_headers(HTMLResponse("".join(parts)))


# --------------------------------------------------------------------------
# application factory
# --------------------------------------------------------------------------


def create_app(
    db_path: Path,
    repo_id: str | None = None,
    *,
    repo_root: Path | None = None,
    enable_worker: bool = False,
    listen_port: int | None = None,
) -> FastAPI:
    """Build the local dashboard application.

    Parameters
    ----------
    db_path:
        Path of the SQLite history database.  A missing database is not an
        error: the history page renders its empty state.
    repo_id:
        When given, only runs/tasks recorded for this repository are listed and
        any other id answers ``404`` (the dashboard never shows another
        repository's data).
    repo_root:
        Working tree the dashboard is scoped to.  ``patchpilot web`` passes it;
        only then are the settings/tasks pages enabled (otherwise ``404``).
    enable_worker:
        Start the single-threaded :class:`patchpilot.tasks.TaskWorker` from the
        FastAPI lifespan and stop it on shutdown.
    listen_port:
        Actual server port used to validate browser writes.
    """

    db_path = Path(db_path)
    repo_root = Path(repo_root) if repo_root is not None else None
    if repo_root is not None and repo_id is None:
        repo_id = models.repo_id_for(repo_root)
    m1_enabled = repo_root is not None

    worker_store: Storage | None = None

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        nonlocal worker_store
        application.state.worker = None
        application.state.worker_error = None
        application.state.worker_store = None
        if enable_worker and repo_root is not None:
            try:
                tasks_module = _tasks_module()
                worker_store = Storage(db_path)
                worker_store.initialize()
                worker = tasks_module.TaskWorker(worker_store, repo_id or "")
                worker.start()
                application.state.worker = worker
                application.state.worker_store = worker_store
            except Exception as exc:  # a worker problem must not kill the pages
                application.state.worker_error = f"{type(exc).__name__}: {exc}"
                if worker_store is not None:
                    try:
                        worker_store.close()
                    except Exception:  # pragma: no cover - defensive
                        pass
                worker_store = None
        try:
            yield
        finally:
            worker = getattr(application.state, "worker", None)
            if worker is not None:
                try:
                    worker.stop()
                except Exception:  # pragma: no cover - defensive
                    pass
            application.state.worker = None
            if worker_store is not None:
                try:
                    worker_store.close()
                except Exception:  # pragma: no cover - defensive
                    pass
                worker_store = None

    app = FastAPI(
        title="PatchPilot dashboard",
        version=models.ANALYZER_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.db_path = db_path
    app.state.listen_port = listen_port
    app.state.repo_id = repo_id
    app.state.repo_root = repo_root
    app.state.page_size = PAGE_SIZE
    app.state.m1_enabled = m1_enabled
    app.state.enable_worker = enable_worker
    app.state.worker = None
    app.state.worker_error = None
    app.add_middleware(_LoopbackHostMiddleware)

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    def history_page(request: Request, page: str | None = None) -> Response:
        try:
            page_number = _parse_page(page)
            filters = _parse_history_filters(request.query_params)
        except ValueError as exc:
            return PlainTextResponse(f"错误请求：{exc}", status_code=400)
        offset = (page_number - 1) * PAGE_SIZE
        runs, total, read_error = _load_history(
            db_path,
            repo_id,
            offset,
            status=filters["status"],
            branch=filters["branch"],
            mode=filters["mode"],
        )
        task_sources = _task_sources_for_runs(
            db_path, repo_id, [run.run_id for run in runs]
        )
        total_pages = max(1, -(-total // PAGE_SIZE))
        status_options = [
            {
                "value": value,
                "label": _label(_STATUS_LABELS, value),
                "selected": filters["status"] == value,
            }
            for value in models.RUN_STATUSES
        ]
        mode_options = [
            {
                "value": value,
                "label": _label(_MODE_LABELS, value),
                "selected": filters["mode"] == value,
            }
            for value in models.ALL_MODES
        ]
        filter_chips = []
        for key, label, mapping in (
            ("status", "状态", _STATUS_LABELS),
            ("mode", "模式", _MODE_LABELS),
            ("branch", "分支", None),
        ):
            value = filters.get(key)
            if not value:
                continue
            remaining = dict(filters)
            remaining[key] = None
            filter_chips.append(
                {
                    "key": key,
                    "label": label,
                    "value": value,
                    "value_label": _label(mapping, value) if mapping else value,
                    "remove_href": _history_url(remaining),
                }
            )
        context = {
            "request": request,
            "runs": [
                _history_row(run, task_sources.get(run.run_id)) for run in runs
            ],
            "total": total,
            "page": page_number,
            "page_size": PAGE_SIZE,
            "total_pages": total_pages,
            "has_prev": page_number > 1,
            "has_next": page_number < total_pages,
            "prev_page": page_number - 1,
            "next_page": page_number + 1,
            "prev_href": _history_url(filters, page_number - 1),
            "next_href": _history_url(filters, page_number + 1),
            "first_href": _history_url(filters, 1),
            "clear_href": "/",
            "filters": filters,
            "has_filters": any(bool(value) for value in filters.values()),
            "filter_chips": filter_chips,
            "status_options": status_options,
            "mode_options": mode_options,
            "shown_from": offset + 1 if runs else 0,
            "shown_to": offset + len(runs),
            "repo_id": repo_id,
            "active": "history",
            "db_path": db_path,
            "db_exists": db_path.is_file(),
            "read_error": read_error,
            "new_analysis_href": "/tasks/new" if m1_enabled else None,
        }
        return _render_html(
            request, templates, "history.html", context, m1_enabled=m1_enabled
        )

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_page(request: Request, run_id: str) -> Response:
        from . import run_detail

        return run_detail.render_run_page(
            request,
            templates,
            db_path=db_path,
            repo_id=repo_id,
            run_id=run_id,
            m1_enabled=m1_enabled,
        )

    @app.get("/runs/{run_id}/changes/{change_id}", response_class=HTMLResponse)
    def change_page(request: Request, run_id: str, change_id: str) -> Response:
        from . import run_detail

        return run_detail.render_change_page(
            request,
            templates,
            db_path=db_path,
            repo_id=repo_id,
            run_id=run_id,
            change_id=change_id,
            m1_enabled=m1_enabled,
        )

    # -- read-only JSON API (P1, docs/CONTRACTS-P1.md section 6.1) ----------

    @app.get("/api/v1/runs")
    def api_history(
        limit: str | None = None, offset: str | None = None
    ) -> Response:
        try:
            limit_value = _parse_int_param(
                "limit", limit, API_DEFAULT_LIMIT, 1, API_MAX_LIMIT
            )
            offset_value = _parse_int_param("offset", offset, 0, 0)
        except ValueError as exc:
            return _json_error(str(exc))
        runs, total, read_error = _load_history(
            db_path, repo_id, offset_value, limit=limit_value
        )
        if read_error:
            return _json_error("历史数据库无法读取。", status_code=503)
        payload = _reports_module().build_history_json(
            runs, total, limit_value, offset_value
        )
        return _json_response(payload)

    @app.get("/api/v1/runs/{run_id}")
    def api_run(run_id: str) -> Response:
        detail = _load_detail(db_path, repo_id, run_id)
        if detail is None:
            return _json_not_found()
        return _json_response(_reports_module().build_json_report(detail))

    @app.get("/api/v1/runs/{run_id}/impact")
    def api_impact(
        run_id: str,
        seed: str | None = None,
        side: str | None = None,
        kind: str | None = None,
        max_nodes: str | None = None,
        depth: str | None = None,
    ) -> Response:
        detail = _load_detail(db_path, repo_id, run_id)
        if detail is None:
            return _json_not_found()
        try:
            max_nodes_value = _parse_int_param(
                "max_nodes", max_nodes, API_DEFAULT_MAX_NODES, 1, API_MAX_NODES
            )
            depth_value = None
            depth_raw = _clean_filter(depth)
            if depth_raw is not None:
                depth_value = _parse_int_param(
                    "depth", depth_raw, 1, 1, IMPACT_PAGE_MAX_DEPTH
                )
            seed_value, side_value, kind_value = _normalize_impact_filters(
                detail, seed, side, kind
            )
        except ValueError as exc:
            return _json_error(str(exc))
        payload = _impact_api_payload(
            detail,
            seed=seed_value,
            side=side_value,
            kind=kind_value,
            max_nodes=max_nodes_value,
            max_depth=depth_value,
        )
        return _json_response(payload)

    # -- HTML impact tree (P1, docs/CONTRACTS-P1.md section 6.2) ------------

    @app.get("/runs/{run_id}/impact", response_class=HTMLResponse)
    def impact_page(request: Request, run_id: str) -> Response:
        from . import impact_graph

        return impact_graph.render_impact_page(
            request,
            templates,
            db_path=db_path,
            repo_id=repo_id,
            run_id=run_id,
            m1_enabled=m1_enabled,
        )

    # -- M1 settings page (structured form + advanced YAML) -----------------

    def _load_settings_module() -> Any:
        try:
            return _config_edit_module()
        except ImportError:
            return None

    def _load_settings_form_module() -> Any:
        try:
            return _settings_form_module()
        except ImportError:
            return None

    def _load_settings_view(config_edit: Any) -> Any:
        try:
            return config_edit.load_settings(repo_root)
        except Exception:
            return None

    def _structured_view(
        form_module: Any,
        view: Any,
        request: Request,
        *,
        draft_values: dict[str, Any] | None = None,
        removes: set[str] | None = None,
        field_errors: list[Any] | None = None,
    ) -> dict[str, Any] | None:
        if form_module is None or view is None:
            return None
        return _build_structured_settings(
            form_module,
            view,
            request,
            db_path,
            draft_values=draft_values,
            removes=removes,
            field_errors=field_errors,
        )

    def _settings_form_mode(form: Any) -> str:
        mode = str(form.get("form_mode", "") or "").strip().lower()
        if mode in ("structured", "raw"):
            return mode
        return "raw" if form.get("raw") is not None else "structured"

    def _settings_render(
        request: Request,
        *,
        view: Any = None,
        raw: str | None = None,
        preview: Any = None,
        error: str | None = None,
        conflict: bool = False,
        saved: bool = False,
        structured: dict[str, Any] | None = None,
        notice: str | None = None,
        extra_warnings: list[str] | None = None,
        structured_preview: bool = False,
        status_code: int = 200,
    ) -> Response:
        context = _settings_context(
            request,
            view=view,
            raw=raw,
            preview=preview,
            error=error,
            conflict=conflict,
            saved=saved,
            structured=structured,
            notice=notice,
            extra_warnings=extra_warnings,
            structured_preview=structured_preview,
        )
        return _render_html(
            request,
            templates,
            "settings.html",
            context,
            status_code=status_code,
            m1_enabled=m1_enabled,
        )

    def _settings_notice(form_module: Any) -> str | None:
        if form_module is not None:
            return None
        return (
            "结构化表单依赖 settings_form 模块，当前版本暂不可用；"
            "可继续使用下方高级 YAML 编辑。"
        )

    def _restart_warnings(
        structured: dict[str, Any] | None, preview: Any
    ) -> list[str]:
        if not structured or preview is None:
            return []
        changed = {
            str(_attr(item, "field", "")) for item in (_attr(preview, "diff", []) or [])
        }
        labels = [
            field["label"]
            for field in structured.get("fields", [])
            if field.get("restart") and field.get("path") in changed
        ]
        if not labels:
            return []
        return [f"以下字段修改后需要重启 Web 服务后生效：{'、'.join(labels)}。"]

    def _structured_errors_from(preview: Any) -> list[Any]:
        return list(_attr(preview, "errors", []) or [])

    def _config_error_fields(form_module: Any, exc: Exception) -> list[Any]:
        mapper = getattr(form_module, "errors_for_config_error", None)
        if not callable(mapper):
            return []
        try:
            return list(mapper(exc) or [])
        except Exception:  # pragma: no cover - defensive around optional module
            return []

    def _structured_action(
        request: Request, form: Any, config_edit: Any, *, save: bool
    ) -> Response:
        form_module = _load_settings_form_module()
        if form_module is None:
            view = _load_settings_view(config_edit)
            return _settings_render(
                request,
                view=view,
                raw=str(form.get("raw", "") or ""),
                error="结构化表单暂不可用，请使用高级 YAML 编辑。",
                status_code=400,
                notice=_settings_notice(form_module),
            )
        try:
            values, removes, parse_errors = form_module.parse_form(form)
        except Exception as exc:
            view = _load_settings_view(config_edit)
            structured = _structured_view(form_module, view, request)
            return _settings_render(
                request,
                view=view,
                error=f"表单解析失败：{exc}",
                status_code=400,
                structured=structured,
                notice=_settings_notice(form_module),
            )
        draft_values = dict(values or {})
        remove_set = set(removes or ())
        view = _load_settings_view(config_edit)
        if parse_errors:
            drafts = _settings_draft_values(form, parse_errors, form_module)
            drafts.update(draft_values)
            structured = _structured_view(
                form_module,
                view,
                request,
                draft_values=drafts,
                removes=remove_set,
                field_errors=list(parse_errors),
            )
            return _settings_render(
                request,
                view=view,
                raw=(_attr(view, "raw", "") if view is not None else ""),
                error="请修正标记的字段后再预览。",
                status_code=400,
                structured=structured,
                notice=_settings_notice(form_module),
            )
        try:
            merged = form_module.merged_raw(view, values, remove_set)
        except Exception as exc:
            structured = _structured_view(
                form_module,
                view,
                request,
                draft_values=draft_values,
                removes=remove_set,
                field_errors=_config_error_fields(form_module, exc),
            )
            return _settings_render(
                request,
                view=view,
                raw=(_attr(view, "raw", "") if view is not None else ""),
                error=f"无法生成配置：{exc}",
                status_code=400,
                structured=structured,
                notice=_settings_notice(form_module),
            )
        expected_digest = str(
            form.get("expected_digest", "")
            or (_attr(view, "digest", "") if view is not None else "")
        )
        try:
            preview = config_edit.preview_settings(repo_root, merged)
        except Exception as exc:
            structured = _structured_view(
                form_module,
                view,
                request,
                draft_values=draft_values,
                removes=remove_set,
            )
            return _settings_render(
                request,
                view=view,
                raw=merged,
                error=f"预览失败：{exc}",
                status_code=400,
                structured=structured,
                notice=_settings_notice(form_module),
            )
        structured = _structured_view(
            form_module,
            view,
            request,
            draft_values=draft_values,
            removes=remove_set,
            field_errors=_structured_errors_from(preview),
        )
        preview_ok = bool(_attr(preview, "ok", False))
        if not save:
            extra = _restart_warnings(structured, preview)
            return _settings_render(
                request,
                view=view,
                raw=merged,
                preview=preview,
                error=None if preview_ok else "配置存在错误，未保存。",
                status_code=200 if preview_ok else 400,
                structured=structured,
                extra_warnings=extra,
                structured_preview=preview_ok,
                notice=_settings_notice(form_module),
            )
        preview_digest = str(form.get("preview_digest", "") or "")
        if not expected_digest or not preview_digest:
            return _settings_render(
                request,
                view=view,
                raw=merged,
                preview=preview,
                error="请先预览配置并确认差异后再保存。",
                status_code=400,
                structured=structured,
                notice=_settings_notice(form_module),
            )
        merged_digest = hashlib.sha256(merged.encode("utf-8")).hexdigest()
        current_digest = str(_attr(view, "digest", "") if view is not None else "")
        if expected_digest and current_digest and expected_digest != current_digest:
            fresh = _load_settings_view(config_edit)
            structured = _structured_view(
                form_module,
                fresh,
                request,
                draft_values=draft_values,
                removes=remove_set,
            )
            return _settings_render(
                request,
                view=fresh,
                raw=merged,
                conflict=True,
                error="配置文件已被外部修改，请重新预览后再保存。",
                status_code=409,
                structured=structured,
                notice=_settings_notice(form_module),
            )
        if merged_digest != preview_digest:
            return _settings_render(
                request,
                view=view,
                raw=merged,
                conflict=True,
                error="表单内容在预览后有改动，请重新预览后再保存。",
                status_code=409,
                structured=structured,
                notice=_settings_notice(form_module),
            )
        try:
            config_edit.save_settings(
                repo_root,
                merged,
                expected_digest=expected_digest,
                preview_digest=preview_digest,
            )
        except Exception as exc:
            conflict_type = getattr(config_edit, "SettingsConflict", None)
            if conflict_type is not None and isinstance(exc, conflict_type):
                fresh = _load_settings_view(config_edit)
                structured = _structured_view(
                    form_module,
                    fresh,
                    request,
                    draft_values=draft_values,
                    removes=remove_set,
                )
                return _settings_render(
                    request,
                    view=fresh,
                    raw=merged,
                    conflict=True,
                    error="配置文件已被外部修改，请重新预览后再保存。",
                    status_code=409,
                    structured=structured,
                    notice=_settings_notice(form_module),
                )
            structured = _structured_view(
                form_module,
                view,
                request,
                draft_values=draft_values,
                removes=remove_set,
                field_errors=_config_error_fields(form_module, exc),
            )
            return _settings_render(
                request,
                view=view,
                raw=merged,
                error=f"保存失败：{exc}",
                status_code=400,
                structured=structured,
                notice=_settings_notice(form_module),
            )
        return _redirect("/settings?saved=1")

    def _raw_preview(
        request: Request, form: Any, config_edit: Any
    ) -> Response:
        raw = str(form.get("raw", "") or "")
        form_module = _load_settings_form_module()
        notice = _settings_notice(form_module)
        view = _load_settings_view(config_edit)
        structured = _structured_view(form_module, view, request)
        if len(raw.encode("utf-8")) > MAX_SETTINGS_TEXT_BYTES:
            return _settings_render(
                request,
                view=view,
                raw=raw,
                error=f"配置文本超过 {MAX_SETTINGS_TEXT_BYTES} 字节上限。",
                status_code=400,
                structured=structured,
                notice=notice,
            )
        try:
            preview = config_edit.preview_settings(repo_root, raw)
        except Exception as exc:
            return _settings_render(
                request,
                view=view,
                raw=raw,
                error=f"预览失败：{exc}",
                status_code=400,
                structured=structured,
                notice=notice,
            )
        return _settings_render(
            request,
            view=view,
            raw=raw,
            preview=preview,
            structured=structured,
            notice=notice,
        )

    def _raw_save(request: Request, form: Any, config_edit: Any) -> Response:
        raw = str(form.get("raw", "") or "")
        expected_digest = str(form.get("expected_digest", "") or "")
        preview_digest = str(form.get("preview_digest", "") or "")
        form_module = _load_settings_form_module()
        notice = _settings_notice(form_module)
        view = _load_settings_view(config_edit)
        structured = _structured_view(form_module, view, request)
        if not expected_digest or not preview_digest:
            return _settings_render(
                request,
                view=view,
                raw=raw,
                error="请先预览配置并确认差异后再保存。",
                status_code=400,
                structured=structured,
                notice=notice,
            )
        try:
            config_edit.save_settings(
                repo_root,
                raw,
                expected_digest=expected_digest,
                preview_digest=preview_digest,
            )
        except Exception as exc:
            conflict_type = getattr(config_edit, "SettingsConflict", None)
            if conflict_type is not None and isinstance(exc, conflict_type):
                fresh = _load_settings_view(config_edit)
                structured = _structured_view(form_module, fresh, request)
                return _settings_render(
                    request,
                    view=fresh,
                    raw=raw,
                    conflict=True,
                    error="配置文件已被外部修改，请重新预览后再保存。",
                    status_code=409,
                    structured=structured,
                    notice=notice,
                )
            return _settings_render(
                request,
                view=view,
                raw=raw,
                error=f"保存失败：{exc}",
                status_code=400,
                structured=structured,
                notice=notice,
            )
        return _redirect("/settings?saved=1")

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request, saved: str | None = None) -> Response:
        if repo_root is None:
            raise StarletteHTTPException(status_code=404, detail="设置页面未启用。")
        config_edit = _load_settings_module()
        if config_edit is None:
            return _unavailable("配置编辑模块尚未就绪。")
        form_module = _load_settings_form_module()
        notice = _settings_notice(form_module)
        try:
            view = config_edit.load_settings(repo_root)
        except Exception as exc:
            return _settings_render(
                request,
                error=f"无法加载项目配置：{exc}",
                saved=saved == "1",
                notice=notice,
            )
        structured = _structured_view(form_module, view, request)
        return _settings_render(
            request,
            view=view,
            saved=saved == "1",
            structured=structured,
            notice=notice,
        )

    @app.post("/settings/preview", response_class=HTMLResponse)
    async def settings_preview(request: Request) -> Response:
        if repo_root is None:
            raise StarletteHTTPException(status_code=404, detail="设置页面未启用。")
        form = await request.form()
        guard = _write_guard_error(request, form)
        if guard is not None:
            return guard
        config_edit = _load_settings_module()
        if config_edit is None:
            return _unavailable("配置编辑模块尚未就绪。")
        if _settings_form_mode(form) == "structured":
            return _structured_action(request, form, config_edit, save=False)
        return _raw_preview(request, form, config_edit)

    @app.post("/settings/save")
    async def settings_save(request: Request) -> Response:
        if repo_root is None:
            raise StarletteHTTPException(status_code=404, detail="设置页面未启用。")
        form = await request.form()
        guard = _write_guard_error(request, form)
        if guard is not None:
            return guard
        config_edit = _load_settings_module()
        if config_edit is None:
            return _unavailable("配置编辑模块尚未就绪。")
        if _settings_form_mode(form) == "structured":
            return _structured_action(request, form, config_edit, save=True)
        return _raw_save(request, form, config_edit)

    # -- M1: analysis task queue --------------------------------------------

    def _open_task_store(*, read_only: bool) -> Any:
        store = Storage(db_path, read_only=read_only)
        if not read_only:
            # The browser flow may be the very first writer (empty history).
            store.initialize()
        return store

    def _task_new_render_context(
        request: Request,
        *,
        form_values: dict[str, Any],
        config: Any,
        config_error: str | None,
        judge_info: dict[str, Any],
        error: str | None = None,
        notice: str | None = None,
        from_task_id: str | None = None,
    ) -> dict[str, Any]:
        endpoint = _task_endpoint_preview(form_values, config)
        return _task_new_context(
            request,
            form_values=form_values,
            judge_info=judge_info,
            config_error=config_error,
            error=error,
            notice=notice,
            from_task_id=from_task_id,
            endpoint_preview=endpoint,
            field_errors=_task_field_errors(error),
            default_base=endpoint["default_base"],
        )

    @app.get("/tasks", response_class=HTMLResponse)
    def tasks_page(request: Request, page: str | None = None) -> Response:
        if repo_root is None:
            raise StarletteHTTPException(status_code=404, detail="任务页面未启用。")
        try:
            page_number = _parse_page(page)
            group = _parse_task_group(request.query_params)
        except ValueError as exc:
            return PlainTextResponse(f"错误请求：{exc}", status_code=400)
        offset = (page_number - 1) * PAGE_SIZE
        records: list[dict[str, Any]] = []
        total = 0
        notice = None
        worker_heartbeat = None
        statuses = _TASK_GROUP_STATUSES.get(group) if group else None
        if not _task_storage_ready():
            notice = "任务存储尚未就绪（storage 任务表未迁移），暂时无法读取队列。"
        else:
            store = _open_task_store(read_only=True)
            try:
                rows, total = store.list_tasks(
                    repo_id or "",
                    statuses=statuses,
                    limit=PAGE_SIZE,
                    offset=offset,
                )
                records = [_task_view(record) for record in rows]
                heartbeat_raw = next(
                    (
                        _attr(record, "worker_heartbeat_at", None)
                        for record in rows
                        if _attr(record, "status", None) == models.TASK_RUNNING
                        and _attr(record, "worker_heartbeat_at", None)
                    ),
                    None,
                )
                worker_heartbeat = _time_view(heartbeat_raw) if heartbeat_raw else None
            except StorageError:
                notice = "任务列表读取失败：历史数据库不可用。"
            except Exception as exc:  # pragma: no cover - defensive
                notice = f"任务列表读取失败：{exc}"
            finally:
                store.close()
        total_pages = max(1, -(-total // PAGE_SIZE))
        worker = getattr(app.state, "worker", None)
        group_options = [
            {
                "value": value,
                "label": _TASK_GROUP_LABELS[value],
                "selected": group == value,
            }
            for value in _TASK_GROUP_ORDER
        ]
        context = {
            "request": request,
            "m1_enabled": m1_enabled,
            "active": "tasks",
            "tasks": records,
            "total": total,
            "page": page_number,
            "total_pages": total_pages,
            "has_prev": page_number > 1,
            "has_next": page_number < total_pages,
            "prev_page": page_number - 1,
            "next_page": page_number + 1,
            "prev_href": _tasks_url(group, page_number - 1),
            "next_href": _tasks_url(group, page_number + 1),
            "first_href": _tasks_url(group, 1),
            "clear_href": "/tasks",
            "group": group,
            "group_label": _TASK_GROUP_LABELS.get(group or "", "全部任务"),
            "group_options": group_options,
            "has_filters": group is not None,
            "shown_from": offset + 1 if records else 0,
            "shown_to": offset + len(records),
            "notice": notice,
            "worker_enabled": bool(enable_worker),
            "worker_running": worker is not None,
            "worker_error": getattr(app.state, "worker_error", None),
            "worker_heartbeat": worker_heartbeat,
        }
        return _render_html(
            request, templates, "tasks.html", context, m1_enabled=m1_enabled
        )

    @app.get("/tasks/new", response_class=HTMLResponse)
    def task_new_page(request: Request) -> Response:
        if repo_root is None:
            raise StarletteHTTPException(status_code=404, detail="任务页面未启用。")
        from_task_id = request.query_params.get("from")
        form_values = _task_form_values()
        notice = None
        if from_task_id:
            if not models.is_valid_run_id(from_task_id):
                raise StarletteHTTPException(status_code=404, detail="未找到该任务。")
            if not _task_storage_ready():
                notice = "任务存储尚未就绪，无法载入历史任务参数。"
            else:
                store = _open_task_store(read_only=True)
                try:
                    record = store.get_task(from_task_id)
                finally:
                    store.close()
                if record is None or _attr(record, "repo_id", None) != repo_id:
                    raise StarletteHTTPException(
                        status_code=404, detail="未找到该任务。"
                    )
                form_values = _task_form_values(record=record)
                notice = (
                    f"已载入任务 {from_task_id} 的参数；确认后提交会生成新的任务。"
                )
        config, config_error = _load_project_config(repo_root)
        query_mode = _clean_filter(request.query_params.get("mode"))
        if query_mode in models.ALL_MODES:
            form_values["mode"] = query_mode
        for query_field, max_length in (
            ("base_ref", MAX_REF_LENGTH),
            ("commit_ref", MAX_REF_LENGTH),
            ("range_spec", MAX_RANGE_LENGTH),
        ):
            value = _clean_filter(request.query_params.get(query_field))
            if value is not None:
                form_values[query_field] = value[:max_length]
        query_parent = _clean_filter(request.query_params.get("parent_index"))
        if query_parent is not None and query_parent.isdigit():
            parsed_parent = int(query_parent)
            if 1 <= parsed_parent <= 64:
                form_values["parent_index"] = str(parsed_parent)
        context = _task_new_render_context(
            request,
            form_values=form_values,
            config=config,
            config_error=config_error,
            judge_info=_judge_form_info(config),
            notice=notice,
            from_task_id=from_task_id,
        )
        return _render_html(
            request, templates, "task_new.html", context, m1_enabled=m1_enabled
        )

    @app.post("/tasks")
    async def submit_task_page(request: Request) -> Response:
        if repo_root is None:
            raise StarletteHTTPException(status_code=404, detail="任务页面未启用。")
        form = await request.form()
        guard = _write_guard_error(request, form)
        if guard is not None:
            return guard
        config, config_error = _load_project_config(repo_root)
        judge_info = _judge_form_info(config)
        try:
            params = _task_params_from_form(form)
        except ValueError as exc:
            return _render_html(
                request,
                templates,
                "task_new.html",
                _task_new_render_context(
                    request,
                    form_values=_task_form_values(form=form),
                    config=config,
                    config_error=config_error,
                    judge_info=judge_info,
                    error=str(exc),
                ),
                status_code=400,
                m1_enabled=m1_enabled,
            )
        task_key_raw = str(form.get("task_key", "") or "").strip()
        task_key = (
            task_key_raw if _TASK_KEY_RE.match(task_key_raw) else secrets.token_hex(16)
        )
        if not _task_storage_ready():
            return _unavailable("任务存储尚未就绪（storage 任务表未迁移）。")
        try:
            tasks_module = _tasks_module()
        except ImportError:
            return _unavailable("任务执行模块尚未就绪。")
        if config is None or config_error:
            return _render_html(
                request,
                templates,
                "task_new.html",
                _task_new_render_context(
                    request,
                    form_values=_task_form_values(form=form),
                    config=config,
                    config_error=config_error,
                    judge_info=judge_info,
                    error="项目配置无效，请先在设置页修复后再提交任务。",
                ),
                status_code=400,
                m1_enabled=m1_enabled,
            )
        validation_error = getattr(tasks_module, "TaskValidationError", None)
        store = _open_task_store(read_only=False)
        try:
            params_obj = tasks_module.TaskParams(**params)
            record = tasks_module.submit_task(
                store,
                repo_root,
                repo_id or "",
                config,
                params_obj,
                task_key=task_key,
            )
        except Exception as exc:
            if validation_error is not None and isinstance(exc, validation_error):
                return _render_html(
                    request,
                    templates,
                    "task_new.html",
                    _task_new_render_context(
                        request,
                        form_values=_task_form_values(form=form),
                        config=config,
                        config_error=config_error,
                        judge_info=judge_info,
                        error=str(exc),
                    ),
                    status_code=400,
                    m1_enabled=m1_enabled,
                )
            if isinstance(exc, StorageError):
                return _unavailable("任务存储不可用，请稍后重试。")
            return _render_html(
                request,
                templates,
                "task_new.html",
                _task_new_render_context(
                    request,
                    form_values=_task_form_values(form=form),
                    config=config,
                    config_error=config_error,
                    judge_info=judge_info,
                    error=f"任务提交失败：{exc}",
                ),
                status_code=500,
                m1_enabled=m1_enabled,
            )
        finally:
            store.close()
        task_id = str(_attr(record, "task_id", "") or "")
        if not task_id:  # pragma: no cover - defensive
            return _unavailable("任务提交后未返回任务 ID。")
        return _redirect(f"/tasks/{task_id}")

    @app.get("/tasks/{task_id}", response_class=HTMLResponse)
    def task_detail_page(request: Request, task_id: str) -> Response:
        if repo_root is None:
            raise StarletteHTTPException(status_code=404, detail="任务页面未启用。")
        record = _load_task(task_id)
        if record is None:
            raise StarletteHTTPException(status_code=404, detail="未找到该任务。")
        context = {
            "request": request,
            "m1_enabled": m1_enabled,
            "active": "tasks",
            "task": _task_view(record, detail=True),
            "poll_seconds": TASK_POLL_SECONDS,
            "notice": (
                "任务已取消。" if request.query_params.get("cancelled") else None
            ),
        }
        return _render_html(
            request, templates, "task_detail.html", context, m1_enabled=m1_enabled
        )

    @app.get("/tasks/{task_id}/progress", response_class=HTMLResponse)
    def task_progress_page(request: Request, task_id: str) -> Response:
        if repo_root is None:
            raise StarletteHTTPException(status_code=404, detail="任务页面未启用。")
        record = _load_task(task_id)
        if record is None:
            raise StarletteHTTPException(status_code=404, detail="未找到该任务。")
        return _progress_fragment(record)

    @app.post("/tasks/{task_id}/cancel")
    async def task_cancel_page(request: Request, task_id: str) -> Response:
        if repo_root is None:
            raise StarletteHTTPException(status_code=404, detail="任务页面未启用。")
        form = await request.form()
        guard = _write_guard_error(request, form)
        if guard is not None:
            return guard
        if not models.is_valid_run_id(task_id):
            raise StarletteHTTPException(status_code=404, detail="未找到该任务。")
        if not _task_storage_ready():
            return _unavailable("任务存储尚未就绪（storage 任务表未迁移）。")
        store = _open_task_store(read_only=False)
        try:
            record = store.get_task(task_id)
            if record is None or _attr(record, "repo_id", None) != repo_id:
                raise StarletteHTTPException(
                    status_code=404, detail="未找到该任务。"
                )
            cancelled = bool(store.cancel_task(task_id))
            fresh = store.get_task(task_id)
        finally:
            store.close()
        if cancelled:
            return _redirect(f"/tasks/{task_id}?cancelled=1")
        context = {
            "request": request,
            "m1_enabled": m1_enabled,
            "active": "tasks",
            "task": _task_view(fresh, detail=True),
            "poll_seconds": TASK_POLL_SECONDS,
            "notice": "该任务已经开始或已结束，无法取消。",
        }
        return _render_html(
            request,
            templates,
            "task_detail.html",
            context,
            status_code=409,
            m1_enabled=m1_enabled,
        )

    @app.post("/tasks/{task_id}/retry")
    async def task_retry_page(request: Request, task_id: str) -> Response:
        if repo_root is None:
            raise StarletteHTTPException(status_code=404, detail="任务页面未启用。")
        form = await request.form()
        guard = _write_guard_error(request, form)
        if guard is not None:
            return guard
        record = _load_task(task_id)
        if record is None:
            raise StarletteHTTPException(status_code=404, detail="未找到该任务。")
        return _redirect(f"/tasks/new?from={task_id}")

    def _load_task(task_id: str) -> Any:
        if not models.is_valid_run_id(task_id):
            return None
        if not _task_storage_ready():
            return None
        store = _open_task_store(read_only=True)
        try:
            record = store.get_task(task_id)
        finally:
            store.close()
        if record is None:
            return None
        if repo_id is not None and _attr(record, "repo_id", None) != repo_id:
            return None
        return record

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        if exc.status_code == 404:
            # JSON API callers always get a JSON error, even for paths that do
            # not match a route (for example an escaped "/" inside a run id).
            if request.url.path.startswith("/api/"):
                return _json_not_found()
            message = (
                exc.detail
                if isinstance(exc.detail, str) and exc.detail
                else "页面不存在。"
            )
            return _render_html(
                request,
                templates,
                "404.html",
                {"request": request, "status_code": 404, "message": message},
                status_code=404,
                m1_enabled=m1_enabled,
            )
        return _private_response_headers(
            PlainTextResponse(
                str(exc.detail), status_code=exc.status_code, headers=exc.headers
            )
        )

    return app
