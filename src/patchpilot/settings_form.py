"""Structured settings form model (US-1).

The settings page normally edits the project YAML through a small whitelist of
typed controls instead of raw YAML.  This module owns:

* :data:`FIELDS` / :data:`GROUPS` -- the whitelist, labels, help texts, ranges
  and control kinds, in page order;
* :func:`load_field_values` -- current effective values plus their source
  (project file / built-in template / built-in default) for rendering;
* :func:`parse_form` -- strict per-field parsing of submitted form values into
  typed values, the set of "reset to default" paths and field errors;
* :func:`merged_raw` -- merge only those typed values into the existing YAML
  with a ``ruamel.yaml`` round-trip, preserving comments, key order and quote
  style of everything the user did not touch;
* :func:`errors_for_config_error` -- map a semantic ``config.ConfigError`` back
  to the dotted form field so the error can be shown next to its control.

Form field naming (used by the Web layer)
-----------------------------------------

* value control name: the dotted path itself, e.g. ``analysis.max_depth``;
* reset checkbox name: ``reset:<path>`` -- a non-empty value removes that
  override (the field falls back to the built-in default);
* list controls submit one entry per line (blank lines and surrounding spaces
  are dropped); an empty textarea means an explicit empty list, which is
  different from "not configured" (reset);
* tristate controls submit ``""`` (mode default), ``"true"`` or ``"false"``;
* "not configured" means the field must be removed from the YAML, so only the
  reset checkbox does that.  A field whose key is absent from the form is left
  untouched.

The merged text is validated by the existing strict parser afterwards
(``config_edit.preview_settings`` / ``config_edit.save_settings``); this module
only guarantees per-field syntax/type/range errors, not cross-field semantics.
"""

from __future__ import annotations

import io
import re
from dataclasses import dataclass
from typing import Any, Mapping

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.error import YAMLError as RuamelYAMLError

from . import config as config_module
from .config import DEFAULT_EXCLUDES, ConfigError
from .models import P0_MODES

__all__ = [
    "FIELD_BY_PATH",
    "FIELDS",
    "GROUPS",
    "RESET_PREFIX",
    "FieldSpec",
    "FieldValue",
    "display_value",
    "errors_for_config_error",
    "load_field_values",
    "merged_raw",
    "parse_form",
]

#: Form key prefix of the "remove this override" checkbox.
RESET_PREFIX = "reset:"

#: Fields whose lower bound is exclusive (0 < value <= maximum).
_EXCLUSIVE_MINIMUMS: dict[str, float] = {
    "analysis.rename_similarity_threshold": 0.0,
}

#: Text fields where an empty submission means "unset" instead of an error.
_TEXT_ALLOW_EMPTY = frozenset({"storage.path"})

_TRUE_VALUES = frozenset({"true", "1", "on", "yes"})
_FALSE_VALUES = frozenset({"false", "0", "off", "no", ""})

_INT_RE = re.compile(r"^[+-]?\d+$")
_FLOAT_RE = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$")


# --------------------------------------------------------------------------
# public data model
# --------------------------------------------------------------------------


@dataclass
class FieldSpec:
    """One editable setting rendered as a form control."""

    path: str
    label: str
    group: str
    kind: str
    default: Any
    help: str
    choices: list[tuple[str, str]] = ()
    minimum: int | float | None = None
    maximum: int | float | None = None
    unit: str = ""
    restart: bool = False
    conditional: str | None = None
    rows: int = 4


@dataclass
class FieldValue:
    """One field's current effective value plus how to render it."""

    spec: FieldSpec
    value: Any
    display: str
    source: str  # "project" | "template" | "default"
    reset: bool = False


GROUPS: tuple[tuple[str, str, str], ...] = (
    (
        "default",
        "默认分析",
        "选择默认比较方式与未跟踪文件处理；基线模式才会用到基线 ref。",
    ),
    (
        "scope",
        "分析范围",
        "按行编辑包含规则、排除规则与源码根；排除规则优先于包含规则。",
    ),
    (
        "depth",
        "深度与证据",
        "调用链深度、候选上限与历史中保留的证据形式。",
    ),
    (
        "advanced",
        "高级",
        "静态预算、缓存、历史保留与日志级别；通常无需修改。",
    ),
    (
        "service",
        "服务与存储",
        "监听地址、端口与数据库位置；修改后需重启 Web 服务才会生效。",
    ),
)

_MODE_LABELS: dict[str, str] = {
    "worktree-net": "工作区净变更（默认）",
    "staged": "暂存区",
    "working-tree": "工作区全部改动",
    "base": "与基线比较",
}

FIELDS: tuple[FieldSpec, ...] = (
    # -- default ----------------------------------------------------------
    FieldSpec(
        path="git.mode",
        label="比较模式",
        group="default",
        kind="select",
        default="worktree-net",
        help="新建分析默认比较哪两侧；也可在任务表单中单次覆盖。",
        choices=[(mode, _MODE_LABELS.get(mode, mode)) for mode in P0_MODES],
    ),
    FieldSpec(
        path="git.base",
        label="基线 ref",
        group="default",
        kind="text",
        default="main",
        help="仅“与基线比较”模式使用，例如 main 或 origin/main。",
        conditional="git.mode==base",
    ),
    FieldSpec(
        path="git.include_untracked",
        label="未跟踪文件",
        group="default",
        kind="tristate",
        default=None,
        help="“按模式默认”沿用比较模式的内建行为；其余两项显式包含或排除。",
    ),
    # -- scope ------------------------------------------------------------
    FieldSpec(
        path="files.include",
        label="包含规则",
        group="scope",
        kind="list",
        default=["**"],
        help="每行一个 glob；只有匹配的路径才会被分析。",
        rows=6,
    ),
    FieldSpec(
        path="files.exclude",
        label="排除规则",
        group="scope",
        kind="list",
        default=list(DEFAULT_EXCLUDES),
        help="每行一个 glob；排除优先于包含，例如 **/build/**。",
        rows=8,
    ),
    FieldSpec(
        path="files.source_roots",
        label="源码根",
        group="scope",
        kind="list",
        default=["src", "."],
        help="每行一个源码根，用于把文件路径解析成模块名。",
        rows=4,
    ),
    # -- depth ------------------------------------------------------------
    FieldSpec(
        path="analysis.max_depth",
        label="影响链深度",
        group="depth",
        kind="int",
        default=3,
        help="从改动符号出发最多追踪几层调用者。",
        minimum=0,
        maximum=10,
        unit="层",
    ),
    FieldSpec(
        path="analysis.max_candidates_per_change",
        label="单个变更候选上限",
        group="depth",
        kind="int",
        default=30,
        help="每个符号变更最多保留的受影响候选数。",
        minimum=1,
        maximum=1000,
        unit="个",
    ),
    FieldSpec(
        path="analysis.max_candidates_per_run",
        label="单次分析候选上限",
        group="depth",
        kind="int",
        default=500,
        help="一次分析所有变更合计的候选数上限。",
        minimum=1,
        maximum=10000,
        unit="个",
    ),
    FieldSpec(
        path="storage.evidence_mode",
        label="证据留存方式",
        group="depth",
        kind="radio",
        default="excerpts",
        help="“保留差异片段”能在历史中查看源码；“仅元数据”更省空间但看不到正文。",
        choices=[
            ("excerpts", "保留差异片段（可查看源码）"),
            ("metadata_only", "仅保存元数据（不保存源码正文）"),
        ],
    ),
    # -- advanced ---------------------------------------------------------
    FieldSpec(
        path="analysis.max_python_files_per_side",
        label="每侧 Python 文件上限",
        group="advanced",
        kind="int",
        default=2000,
        help="快照每一侧最多索引的 Python 文件数。",
        minimum=1,
        maximum=50000,
        unit="个",
    ),
    FieldSpec(
        path="analysis.max_python_bytes_per_side",
        label="每侧 Python 字节上限",
        group="advanced",
        kind="int",
        default=33554432,
        help="快照每一侧最多读取的 Python 源码字节数。",
        minimum=1,
        maximum=1 << 31,
        unit="字节",
    ),
    FieldSpec(
        path="analysis.max_file_bytes",
        label="单文件读取上限",
        group="advanced",
        kind="int",
        default=262144,
        help="超过该大小的文件不进入差异分析。",
        minimum=1,
        maximum=1 << 30,
        unit="字节",
    ),
    FieldSpec(
        path="analysis.max_diff_lines_per_side",
        label="每侧差异行上限",
        group="advanced",
        kind="int",
        default=3000,
        help="单文件每侧最多保留的差异行数。",
        minimum=1,
        maximum=1000000,
        unit="行",
    ),
    FieldSpec(
        path="analysis.max_diff_line_product",
        label="差异规模上限",
        group="advanced",
        kind="int",
        default=4000000,
        help="旧侧行数×新侧行数的上限，用于限制大文件 diff。",
        minimum=1,
        maximum=1 << 40,
    ),
    FieldSpec(
        path="analysis.rename_similarity_threshold",
        label="相似度重命名阈值",
        group="advanced",
        kind="float",
        default=0.8,
        help="0 到 1 之间（不含 0）；越高越保守，只有非常相似的文件才配对。",
        minimum=0.0,
        maximum=1.0,
    ),
    FieldSpec(
        path="analysis.max_rename_candidates",
        label="重命名候选上限",
        group="advanced",
        kind="int",
        default=200,
        help="相似度配对时每侧参与计算的候选路径数上限。",
        minimum=1,
        maximum=10000,
        unit="个",
    ),
    FieldSpec(
        path="cache.ast_enabled",
        label="AST 索引缓存",
        group="advanced",
        kind="bool",
        default=True,
        help="开启后重复分析可复用未变化文件的 AST 索引。",
    ),
    FieldSpec(
        path="cache.judge_enabled",
        label="Judge 结果缓存",
        group="advanced",
        kind="bool",
        default=True,
        help="开启后相同上下文的 Judge 判定可复用缓存结果。",
    ),
    FieldSpec(
        path="cache.ttl_days",
        label="缓存保留天数",
        group="advanced",
        kind="int",
        default=7,
        help="过期缓存会被清理；0 表示不按时间过期。",
        minimum=0,
        unit="天",
    ),
    FieldSpec(
        path="cache.max_bytes",
        label="缓存容量上限",
        group="advanced",
        kind="int",
        default=104857600,
        help="缓存总量上限，超出后按时间淘汰；0 表示不按大小淘汰。",
        minimum=0,
        unit="字节",
    ),
    FieldSpec(
        path="storage.max_evidence_bytes_per_run",
        label="单次证据字节上限",
        group="advanced",
        kind="int",
        default=2097152,
        help="每个 Run 保存的差异片段总字节上限。",
        minimum=0,
        unit="字节",
    ),
    FieldSpec(
        path="storage.retain_days",
        label="历史保留天数",
        group="advanced",
        kind="int",
        default=30,
        help="`patchpilot history prune` 默认保留最近多少天的 Run。",
        minimum=0,
        unit="天",
    ),
    FieldSpec(
        path="storage.max_runs",
        label="历史保留条数",
        group="advanced",
        kind="int",
        default=100,
        help="`patchpilot history prune` 默认最多保留多少个 Run。",
        minimum=0,
        unit="条",
    ),
    FieldSpec(
        path="logging.level",
        label="日志级别",
        group="advanced",
        kind="select",
        default="INFO",
        help="CLI 与 Web 的日志详细程度。",
        choices=[
            ("DEBUG", "DEBUG（调试）"),
            ("INFO", "INFO（默认）"),
            ("WARNING", "WARNING（警告）"),
            ("ERROR", "ERROR（错误）"),
        ],
    ),
    # -- service ----------------------------------------------------------
    FieldSpec(
        path="web.host",
        label="监听地址",
        group="service",
        kind="select",
        default="127.0.0.1",
        help="仅允许本机回环地址；修改后需重启 Web 服务。",
        choices=[
            ("127.0.0.1", "127.0.0.1（仅本机）"),
            ("localhost", "localhost（仅本机）"),
            ("::1", "::1（IPv6 本机）"),
        ],
        restart=True,
    ),
    FieldSpec(
        path="web.port",
        label="监听端口",
        group="service",
        kind="int",
        default=8765,
        help="修改后需重启 Web 服务。",
        minimum=1,
        maximum=65535,
        unit="端口",
        restart=True,
    ),
    FieldSpec(
        path="storage.path",
        label="数据库位置",
        group="service",
        kind="text",
        default=None,
        help="相对用户状态目录的路径；留空使用默认位置。修改后需重启 Web 服务。",
        restart=True,
    ),
)

#: Field lookup used by the Web layer (e.g. to attach field errors).
FIELD_BY_PATH: dict[str, FieldSpec] = {spec.path: spec for spec in FIELDS}

_FIELD_ERROR_MESSAGE_RE = re.compile(
    r"^(?P<field>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
    r" (?:must|has|contains|is|are|values?)\b"
)
_UNSUPPORTED_RE = re.compile(r"^unsupported configuration key:\s*(?P<key>.+)$")
_SECTION_RE = re.compile(r"^configuration section '(?P<section>[^']+)'")


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


class _FieldError(ValueError):
    """Internal per-field parse error (message is user facing)."""


def _copy_value(value: Any) -> Any:
    if isinstance(value, list):
        return list(value)
    if isinstance(value, dict):
        return dict(value)
    return value


def display_value(spec: FieldSpec, value: Any) -> str:
    """Render an effective value for its form control.

    Lists become one entry per line, ``None`` becomes an empty control value and
    booleans use lower-case ``true``/``false`` (so they round-trip through
    :func:`parse_form`).
    """

    if spec.kind == "list":
        if not value:
            return ""
        return "\n".join(str(item) for item in value)
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _lookup(mapping: Mapping[str, Any], dotted: str) -> tuple[bool, Any]:
    current: Any = mapping
    for part in dotted.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _has_path(data: Any, dotted: str) -> bool:
    found, _value = _lookup(data, dotted)
    return found


def _field_text(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, (list, tuple)):
        return "\n".join(str(item) for item in raw)
    return str(raw)


def _config_parser_yaml() -> YAML:
    parser = YAML()
    parser.preserve_quotes = True
    return parser


def _load_yaml_mapping(text: str) -> Any:
    try:
        return _config_parser_yaml().load(text)
    except (RuamelYAMLError, ValueError):
        return None


# --------------------------------------------------------------------------
# load_field_values
# --------------------------------------------------------------------------


def load_field_values(
    view: Any, *, reset_paths: set[str] | None = None
) -> list[FieldValue]:
    """Return the current value/source of every field for rendering.

    ``view`` is a ``config_edit.SettingsView`` (or ``None`` when loading the
    project file failed).  Values come from the parsed effective configuration;
    ``source`` is ``"project"`` when the key is explicitly present in the
    project file, ``"template"`` when it comes from the built-in template (no
    project file) and ``"default"`` when neither contains the key.  ``reset``
    fields (``reset_paths``) render the built-in default and mark themselves as
    a pending removal.
    """

    resets = set(reset_paths or ())
    effective_raw = getattr(view, "effective", None)
    effective: dict[str, Any] = (
        dict(effective_raw) if isinstance(effective_raw, Mapping) else {}
    )
    has_effective = bool(effective)
    base_source = str(getattr(view, "source", "") or "")
    raw = getattr(view, "raw", None)
    parsed = _load_yaml_mapping(raw) if isinstance(raw, str) else None
    if not isinstance(parsed, Mapping):
        parsed = None
    if not has_effective:
        parsed = None

    values: list[FieldValue] = []
    for spec in FIELDS:
        if spec.path in resets:
            default_value = _copy_value(spec.default)
            values.append(
                FieldValue(
                    spec=spec,
                    value=default_value,
                    display=display_value(spec, default_value),
                    source="default",
                    reset=True,
                )
            )
            continue
        found, value = _lookup(effective, spec.path)
        if not found or not has_effective:
            value = _copy_value(spec.default)
        else:
            value = _copy_value(value)
        if parsed is not None and _has_path(parsed, spec.path):
            source = "template" if base_source == "template" else "project"
        else:
            source = "default"
        values.append(
            FieldValue(
                spec=spec,
                value=value,
                display=display_value(spec, value),
                source=source,
                reset=False,
            )
        )
    return values


# --------------------------------------------------------------------------
# parse_form
# --------------------------------------------------------------------------


def _bounds_error(spec: FieldSpec, value: int | float) -> str | None:
    minimum = spec.minimum
    maximum = spec.maximum
    exclusive_min = _EXCLUSIVE_MINIMUMS.get(spec.path)
    if minimum is not None:
        if exclusive_min is not None and exclusive_min == minimum:
            if not value > minimum:
                return f"{spec.label}必须大于 {minimum}"
        elif value < minimum:
            return f"{spec.label}不能小于 {minimum}"
    if maximum is not None and value > maximum:
        return f"{spec.label}不能大于 {maximum}"
    return None


def _parse_int(spec: FieldSpec, text: str) -> int:
    if not text:
        raise _FieldError(f"{spec.label}不能为空，请填写整数")
    if not _INT_RE.match(text):
        raise _FieldError(f"{spec.label}必须是整数")
    value = int(text, 10)
    message = _bounds_error(spec, value)
    if message is not None:
        raise _FieldError(message)
    return value


def _parse_float(spec: FieldSpec, text: str) -> float:
    if not text:
        raise _FieldError(f"{spec.label}不能为空，请填写数字")
    if not _FLOAT_RE.match(text):
        raise _FieldError(f"{spec.label}必须是数字")
    value = float(text)
    message = _bounds_error(spec, value)
    if message is not None:
        raise _FieldError(message)
    return value


def _parse_bool(spec: FieldSpec, text: str) -> bool:
    lowered = text.strip().lower()
    if lowered in _TRUE_VALUES:
        return True
    if lowered in _FALSE_VALUES:
        return False
    raise _FieldError(f"{spec.label}必须是 true 或 false")


def _parse_tristate(spec: FieldSpec, text: str) -> bool | None:
    lowered = text.strip().lower()
    if lowered == "":
        return None
    if lowered in ("true", "1", "on", "yes"):
        return True
    if lowered in ("false", "0", "off", "no"):
        return False
    raise _FieldError(f"{spec.label}必须是“按模式默认”、true 或 false")


def _parse_list(text: str) -> list[str]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return [line.strip() for line in normalized.split("\n") if line.strip()]


def _parse_text(spec: FieldSpec, text: str) -> str | None:
    value = text.strip()
    if spec.path in _TEXT_ALLOW_EMPTY:
        return value or None
    if not value:
        raise _FieldError(f"{spec.label}不能为空")
    return value


def _parse_value(spec: FieldSpec, text: str) -> Any:
    kind = spec.kind
    if kind == "int":
        return _parse_int(spec, text)
    if kind == "float":
        return _parse_float(spec, text)
    if kind == "bool":
        return _parse_bool(spec, text)
    if kind == "tristate":
        return _parse_tristate(spec, text)
    if kind in ("select", "radio"):
        value = text.strip()
        allowed = [choice[0] for choice in spec.choices]
        if not value:
            raise _FieldError(f"{spec.label}必须选择一项")
        if value not in allowed:
            raise _FieldError(f"{spec.label}的取值不在允许范围内")
        return value
    if kind == "list":
        return _parse_list(text)
    if kind == "text":
        return _parse_text(spec, text)
    raise _FieldError(f"{spec.label}的控件类型不受支持")  # pragma: no cover


def parse_form(
    form: Mapping[str, Any],
) -> tuple[dict[str, Any], set[str], list[dict]]:
    """Parse structured settings form values.

    Returns ``(values, removes, errors)`` where ``values`` maps dotted field
    paths to typed values, ``removes`` is the set of fields whose override
    should be deleted, and ``errors`` is an ordered list of
    ``{"field", "message"}`` entries (one per invalid field, in page order).
    Only :data:`FIELDS` paths are accepted; unknown form keys are ignored.
    """

    values: dict[str, Any] = {}
    removes: set[str] = set()
    errors: list[dict] = []

    for spec in FIELDS:
        reset_value = form.get(RESET_PREFIX + spec.path)
        if reset_value is not None and _field_text(reset_value).strip():
            removes.add(spec.path)
            continue
        if spec.path not in form:
            continue
        text = _field_text(form.get(spec.path))
        try:
            parsed = _parse_value(spec, text)
        except _FieldError as exc:
            errors.append({"field": spec.path, "message": str(exc)})
            continue
        values[spec.path] = parsed

    return values, removes, errors


# --------------------------------------------------------------------------
# merged_raw (ruamel round-trip)
# --------------------------------------------------------------------------


def _base_raw(view: Any) -> str:
    if view is None:
        # Loading the project file failed (unreadable or invalid YAML): never
        # silently replace it with the template -- the advanced YAML editor must
        # fix the existing file first.
        raise ConfigError(
            "无法读取当前配置文件，请刷新页面后重试，或使用高级 YAML 编辑修正"
        )
    raw = getattr(view, "raw", None)
    source = str(getattr(view, "source", "") or "")
    if raw is None or source == "template":
        return config_module.CONFIG_TEMPLATE
    return raw


def _round_trip_yaml() -> YAML:
    parser = YAML()
    parser.preserve_quotes = True
    parser.width = 4096
    parser.indent(mapping=2, sequence=4, offset=2)
    parser.default_flow_style = False
    return parser


def _mapping_for_child(node: Any, child_key: str) -> Any:
    child = node.get(child_key) if isinstance(node, Mapping) else None
    if isinstance(child, Mapping):
        return child
    replacement = CommentedMap()
    node[child_key] = replacement
    return replacement


def _set_path(data: Any, parts: list[str], value: Any) -> None:
    node = data
    for part in parts[:-1]:
        node = _mapping_for_child(node, part)
    node[parts[-1]] = value


def _delete_path(data: Any, parts: list[str]) -> bool:
    node: Any = data
    for part in parts[:-1]:
        if not isinstance(node, Mapping):
            return False
        node = node.get(part)
    if isinstance(node, Mapping) and parts[-1] in node:
        del node[parts[-1]]
        return True
    return False


def merged_raw(view: Any, values: dict[str, Any], removes: set[str]) -> str:
    """Merge typed form values/removals into the current YAML text.

    Only the submitted keys are modified: everything else (comments, key order,
    flow style, quotes and formatting) is kept by the ``ruamel.yaml``
    round-trip.  Removing a key deletes the whole key (its parent section is
    left in place).  A project file that is not valid YAML raises
    ``ConfigError`` instead of being overwritten, so the advanced YAML editor
    must fix it first.

    Values equal to the currently effective value are skipped, so a form that
    submits every rendered control does not materialize untouched defaults or
    reformat unchanged flow-style lists; only real changes are written.
    """

    base = _base_raw(view)
    if not values and not removes:
        return base

    effective_raw = getattr(view, "effective", None)
    effective: Mapping[str, Any] = (
        effective_raw if isinstance(effective_raw, Mapping) else {}
    )

    parser = _round_trip_yaml()
    try:
        data = parser.load(base)
    except (RuamelYAMLError, ValueError) as exc:
        raise ConfigError(
            "当前配置文件不是有效 YAML，请使用高级 YAML 编辑修正后再保存"
        ) from exc
    if data is None:
        data = CommentedMap()
    if not isinstance(data, CommentedMap):
        raise ConfigError(
            "当前配置文件不是有效的 YAML 映射，请使用高级 YAML 编辑修正后再保存"
        )

    changed = False
    for path, value in values.items():
        if path in removes:
            continue
        found, current_value = _lookup(effective, path)
        if found and current_value == value:
            continue
        _set_path(data, path.split("."), value)
        changed = True
    for path in removes:
        if _delete_path(data, path.split(".")):
            changed = True
    if not changed:
        return base

    stream = io.StringIO()
    parser.dump(data, stream)
    return stream.getvalue()


# --------------------------------------------------------------------------
# ConfigError -> field errors
# --------------------------------------------------------------------------


def _field_from_message(message: str) -> str:
    match = _UNSUPPORTED_RE.match(message)
    if match is not None:
        key = match.group("key").strip()
        if len(key) >= 2 and key[0] == key[-1] and key[0] in ("'", '"'):
            key = key[1:-1]
        return key
    match = _SECTION_RE.match(message)
    if match is not None:
        return match.group("section")
    match = _FIELD_ERROR_MESSAGE_RE.match(message)
    if match is not None:
        return match.group("field")
    return ""


def errors_for_config_error(exc: Exception) -> list[dict]:
    """Map a semantic ``config.ConfigError`` to its dotted form field.

    Returns ``[]`` when the error cannot be attributed to one of the editable
    fields (YAML syntax errors, unknown keys, Judge-only settings, ...): those
    belong to the advanced YAML editor / top-level error area.
    """

    message = " ".join(str(exc or "").split())
    if not message:
        return []
    if not isinstance(exc, ConfigError):
        return []
    field_name = _field_from_message(message)
    if not field_name or field_name not in FIELD_BY_PATH:
        return []
    return [{"field": field_name, "message": message}]
