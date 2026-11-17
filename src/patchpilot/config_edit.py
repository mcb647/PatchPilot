"""Preview and save the project configuration file (M1 Web settings).

The strict parser in :mod:`patchpilot.config` is the single source of truth for
what a valid configuration is: this module previews a submitted YAML text with
``config.parse_config_text`` and saves it only after re-parsing, so the Web form
can never persist a file the CLI would reject.

Concurrency model
-----------------
* Every local save runs under a module-level :class:`threading.Lock`, so two
  browser tabs cannot interleave their read-check-write sequence.
* ``save_settings`` requires the digest of the file the preview was based on
  (``expected_digest``) and the digest of the submitted text
  (``preview_digest``).  Either mismatch raises :class:`SettingsConflict`
  (rendered as HTTP 409 and requiring a fresh preview).
* Writes go to a temporary file in the same directory and are published with
  ``os.replace``; a failed write removes the temporary file and leaves the old
  configuration untouched.  Symbolic links and non-regular targets are refused
  so the editor cannot be used to overwrite arbitrary files.

Nothing in this module logs or embeds the whole configuration text: parse errors
carry the offending field/line only.  The submitted text is written byte for
byte, so comments and formatting survive a round trip.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import config as config_module
from .config import CONFIG_FILENAME, LEGACY_CONFIG_FILENAME, ConfigError

__all__ = [
    "RESTART_FIELDS",
    "SettingsConflict",
    "SettingsPreview",
    "SettingsView",
    "load_settings",
    "preview_settings",
    "save_settings",
]

#: Effective values that only a Web service restart can pick up.
RESTART_FIELDS = frozenset({"web.host", "web.port", "storage.path"})

#: Serializes the read-check-write sequence of local settings saves.
_WRITE_LOCK = threading.Lock()

_DUPLICATE_RE = re.compile(r"^duplicate configuration key:\s*(?P<key>.+)$")
_UNSUPPORTED_RE = re.compile(r"^unsupported configuration key:\s*(?P<key>.+)$")
_SECTION_RE = re.compile(r"^configuration section '(?P<section>[^']+)'")
_VERSION_RE = re.compile(r"^unsupported configuration version\b")
_FIELD_PREFIX_RE = re.compile(
    r"^(?P<field>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
    r" (?:must|has|contains|is|are|values?)\b"
)
_KEY_LINE_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<key>[A-Za-z0-9_.-]+)[ \t]*:"
)


# --------------------------------------------------------------------------
# public data model
# --------------------------------------------------------------------------


@dataclass
class SettingsView:
    """One loaded configuration state shown by ``GET /settings``.

    ``path`` is the actual file path for a project file and ``None`` when the
    built-in template is shown; ``source`` is ``"project"`` or ``"template"``.
    """

    path: str | None
    exists: bool
    source: str
    raw: str
    digest: str
    effective: dict[str, Any]


@dataclass
class SettingsPreview:
    """Parsed preview of edited configuration text.

    ``errors`` entries are ``{"field", "message", "line"?, "column"?}``; YAML
    syntax errors carry the line/column marks, semantic errors carry the dotted
    field name.  ``diff`` entries are ``{"field", "old", "new"}`` sorted by
    field; ``effective`` is empty when the text does not parse.
    """

    ok: bool
    errors: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    diff: list[dict[str, Any]] = field(default_factory=list)
    effective: dict[str, Any] = field(default_factory=dict)
    preview_digest: str = ""
    path: str = ""


class SettingsConflict(Exception):
    """Raised when a settings save races with another writer or a stale preview."""


# --------------------------------------------------------------------------
# paths, digests and reading
# --------------------------------------------------------------------------


def _root(repo_root: Path) -> Path:
    return Path(repo_root).expanduser().resolve()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _template_bytes() -> bytes:
    return config_module.CONFIG_TEMPLATE.encode("utf-8")


def _existing_config_path(root: Path) -> Path | None:
    for path in (root / CONFIG_FILENAME, root / LEGACY_CONFIG_FILENAME):
        try:
            if path.is_file():
                return path
        except OSError:  # pragma: no cover - defensive, is_file swallows most
            continue
    return None


def _read_raw(path: Path) -> tuple[str, bytes]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        detail = exc.strerror or exc.__class__.__name__
        raise ConfigError(f"cannot read {path.name}: {detail}") from exc
    try:
        return data.decode("utf-8"), data
    except UnicodeDecodeError as exc:
        raise ConfigError(f"cannot decode {path.name} as UTF-8") from exc


def _current_state(root: Path) -> tuple[Path | None, str, str, Path]:
    """Return ``(existing_path, raw, digest, save_target)``."""

    existing = _existing_config_path(root)
    if existing is None:
        raw = config_module.CONFIG_TEMPLATE
        return None, raw, _sha256_bytes(_template_bytes()), root / CONFIG_FILENAME
    raw, data = _read_raw(existing)
    return existing, raw, _sha256_bytes(data), existing


def _parse_effective(raw: str) -> dict[str, Any]:
    """Effective values of ``raw``; empty dict when the text is invalid."""

    try:
        parsed = config_module.parse_config_text(raw)
    except ConfigError:
        return {}
    return config_module.config_to_dict(parsed)


# --------------------------------------------------------------------------
# error extraction (field + YAML line/column, never the whole text)
# --------------------------------------------------------------------------


def _iter_key_paths(text: str):
    """Yield ``(dotted_key_path_tuple, line_number)`` for YAML mapping keys.

    Best-effort YAML structure scan used only to point at the offending line;
    the authoritative parse/validation is ``config.parse_config_text``.
    """

    stack: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.split("#", 1)[0].rstrip()
        if not stripped.strip():
            continue
        match = _KEY_LINE_RE.match(stripped)
        if match is None:
            continue
        indent = len(match.group("indent"))
        key = match.group("key")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        path = tuple(item[1] for item in stack) + (key,)
        yield path, number
        stack.append((indent, key))


def _first_key_line(text: str, dotted_field: str) -> int | None:
    wanted = tuple(part for part in dotted_field.split(".") if part)
    if not wanted:
        return None
    for path, number in _iter_key_paths(text):
        if path == wanted:
            return number
    return None


def _last_key_location(
    text: str, key: str
) -> tuple[tuple[str, ...], int] | None:
    found: tuple[tuple[str, ...], int] | None = None
    for path, number in _iter_key_paths(text):
        if path and path[-1] == key:
            found = (path, number)
    return found


def _clean_key(value: str) -> str:
    cleaned = value.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
        cleaned = cleaned[1:-1]
    return cleaned


def _field_from_message(message: str) -> str:
    match = _UNSUPPORTED_RE.match(message)
    if match is not None:
        return _clean_key(match.group("key"))
    match = _SECTION_RE.match(message)
    if match is not None:
        return _clean_key(match.group("section"))
    if _VERSION_RE.match(message):
        return "version"
    match = _FIELD_PREFIX_RE.match(message)
    if match is not None:
        return match.group("field")
    return ""


def _yaml_mark(exc: ConfigError) -> tuple[int | None, int | None]:
    """Line/column of the underlying YAML error, when there is one."""

    cause = exc.__cause__
    if cause is None:
        return None, None
    mark = getattr(cause, "problem_mark", None)
    if mark is None:
        mark = getattr(cause, "context_mark", None)
    if mark is None:
        return None, None
    try:
        return int(mark.line) + 1, int(mark.column) + 1
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return None, None


def _yaml_problem(exc: ConfigError) -> str | None:
    """Single-line YAML problem summary without the offending source snippet."""

    cause = exc.__cause__
    if cause is None:
        return None
    problem = getattr(cause, "problem", None)
    if not problem:
        return None
    line, column = _yaml_mark(exc)
    location = ""
    if line is not None:
        location = f" (line {line}"
        if column is not None:
            location += f", column {column}"
        location += ")"
    return f"cannot parse YAML: {problem}{location}"


def _sanitized_message(exc: ConfigError) -> str:
    """Error text safe for exceptions/logs: never the raw configuration text."""

    yaml_message = _yaml_problem(exc)
    if yaml_message is not None:
        return yaml_message
    message = " ".join(str(exc).split())
    return message or exc.__class__.__name__


def _config_error_entry(exc: ConfigError, raw_text: str) -> dict[str, Any]:
    message = _sanitized_message(exc)
    field_name = ""
    line: int | None = None
    column: int | None = None

    duplicate = _DUPLICATE_RE.match(message)
    if duplicate is not None:
        key = _clean_key(duplicate.group("key"))
        located = _last_key_location(raw_text, key)
        if located is None:
            field_name = key
        else:
            path, line = located
            field_name = ".".join(path)
    else:
        field_name = _field_from_message(message)
        line, column = _yaml_mark(exc)
        if line is None and field_name:
            line = _first_key_line(raw_text, field_name)

    entry: dict[str, Any] = {"field": field_name, "message": message}
    if line is not None:
        entry["line"] = line
        if column is not None:
            entry["column"] = column
    return entry


# --------------------------------------------------------------------------
# effective-value diff
# --------------------------------------------------------------------------


def _flatten(mapping: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for key, value in mapping.items():
        dotted = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            flat.update(_flatten(value, dotted))
        else:
            flat[dotted] = value
    return flat


def _compute_diff(
    old_effective: dict[str, Any], new_effective: dict[str, Any]
) -> list[dict[str, Any]]:
    old_flat = _flatten(old_effective)
    new_flat = _flatten(new_effective)
    changes: list[dict[str, Any]] = []
    for field_name in sorted(set(old_flat) | set(new_flat)):
        old_value = old_flat.get(field_name)
        new_value = new_flat.get(field_name)
        if old_value != new_value:
            changes.append(
                {"field": field_name, "old": old_value, "new": new_value}
            )
    return changes


def _restart_warnings(diff: list[dict[str, Any]]) -> list[str]:
    warnings = []
    for entry in diff:
        field_name = entry["field"]
        if field_name in RESTART_FIELDS:
            warnings.append(f"{field_name} 已修改，重启后生效（需重启 Web 服务）")
    return warnings


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------


def load_settings(repo_root: Path) -> SettingsView:
    """Load the settings state of one repository for the settings page.

    ``.patchpilot.yaml`` wins over the legacy ``patchpilot.yaml``; when neither
    exists the built-in template is returned with ``path=None`` and
    ``source="template"``.  A current file that does not parse is still returned
    verbatim (``raw``/``digest`` remain usable) with an empty ``effective``
    mapping, so the Web page can show and repair a broken configuration.
    """

    root = _root(repo_root)
    existing = _existing_config_path(root)
    if existing is None:
        raw = config_module.CONFIG_TEMPLATE
        return SettingsView(
            path=None,
            exists=False,
            source="template",
            raw=raw,
            digest=_sha256_bytes(_template_bytes()),
            effective=_parse_effective(raw),
        )
    raw, data = _read_raw(existing)
    return SettingsView(
        path=str(existing),
        exists=True,
        source="project",
        raw=raw,
        digest=_sha256_bytes(data),
        effective=_parse_effective(raw),
    )


def preview_settings(repo_root: Path, raw_text: str) -> SettingsPreview:
    """Validate edited configuration text and describe its effect.

    Never touches disk.  Errors come from ``config.parse_config_text`` (with a
    best-effort dotted field and YAML line/column), ``diff`` compares the
    currently effective values with the new ones by dotted field, and
    ``warnings`` flags values that only a Web restart can apply.
    """

    if not isinstance(raw_text, str):
        raise TypeError("raw_text must be a string")
    root = _root(repo_root)
    _existing, current_raw, _current_digest, target = _current_state(root)

    errors: list[dict[str, Any]] = []
    warnings: list[str] = []
    diff: list[dict[str, Any]] = []
    effective: dict[str, Any] = {}

    try:
        parsed = config_module.parse_config_text(raw_text)
    except ConfigError as exc:
        errors.append(_config_error_entry(exc, raw_text))
    else:
        effective = config_module.config_to_dict(parsed)
        diff = _compute_diff(_parse_effective(current_raw), effective)
        warnings = _restart_warnings(diff)

    return SettingsPreview(
        ok=not errors,
        errors=errors,
        warnings=warnings,
        diff=diff,
        effective=effective,
        preview_digest=_sha256_text(raw_text),
        path=str(target),
    )


def _check_writable_target(root: Path, target: Path) -> None:
    """Refuse symlinked/non-regular/escaping configuration targets."""

    if target.name not in (CONFIG_FILENAME, LEGACY_CONFIG_FILENAME):
        raise SettingsConflict("配置文件名不受支持")
    if target.parent != root:
        raise SettingsConflict("配置路径逃逸仓库根目录")
    try:
        resolved_parent = target.parent.resolve(strict=True)
    except OSError as exc:
        detail = exc.strerror or exc.__class__.__name__
        raise SettingsConflict(f"仓库根目录不可用: {detail}") from exc
    if resolved_parent != root:
        raise SettingsConflict("配置路径逃逸仓库根目录")

    try:
        info = target.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        detail = exc.strerror or exc.__class__.__name__
        raise SettingsConflict(f"无法检查配置文件状态: {detail}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise SettingsConflict("拒绝保存到符号链接配置文件")
    if not stat.S_ISREG(info.st_mode):
        raise SettingsConflict("配置文件路径不是普通文件")


def _write_atomic(target: Path, data: bytes) -> None:
    """Write ``data`` to a same-directory temp file then publish atomically."""

    descriptor: int | None = None
    temp_path: Path | None = None
    try:
        descriptor, temp_name = tempfile.mkstemp(
            prefix=".patchpilot-", suffix=".tmp", dir=str(target.parent)
        )
        temp_path = Path(temp_name)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            mode = stat.S_IMODE(target.stat().st_mode)
        except OSError:
            mode = None
        if mode is not None:
            try:
                os.chmod(temp_path, mode)
            except OSError:  # pragma: no cover - best effort on Windows
                pass
        os.replace(temp_path, target)
        temp_path = None
    finally:
        if descriptor is not None:  # pragma: no cover - fdopen ownership
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temp_path is not None:
            try:
                temp_path.unlink()
            except OSError:
                pass


def save_settings(
    repo_root: Path,
    raw_text: str,
    *,
    expected_digest: str,
    preview_digest: str,
) -> SettingsView:
    """Persist edited configuration text and return the reloaded view.

    ``expected_digest`` must match the digest of the currently loaded file (or
    of the template when no file exists yet) and ``preview_digest`` must match
    ``sha256(raw_text.encode("utf-8"))``; either mismatch means another writer
    won or the preview is stale and raises :class:`SettingsConflict`.  Invalid
    text raises ``ConfigError`` before anything is written.  Existing files are
    saved in place (canonical or legacy); a missing file is created as
    ``.patchpilot.yaml``.
    """

    if not isinstance(raw_text, str):
        raise TypeError("raw_text must be a string")
    if not isinstance(expected_digest, str) or not isinstance(
        preview_digest, str
    ):
        raise SettingsConflict("缺少配置摘要，请重新加载设置并预览")
    root = _root(repo_root)
    submitted_digest = _sha256_text(raw_text)

    with _WRITE_LOCK:
        _existing, _raw, current_digest, target = _current_state(root)
        if expected_digest != current_digest:
            raise SettingsConflict("配置文件已被修改，请重新加载设置并预览")
        if preview_digest != submitted_digest:
            raise SettingsConflict("预览摘要与提交内容不一致，请重新预览")

        # Validate before touching the filesystem: only a parseable
        # configuration may ever replace the current one.
        try:
            config_module.parse_config_text(raw_text)
        except ConfigError as exc:
            raise ConfigError(_sanitized_message(exc)) from None
        _check_writable_target(root, target)
        _write_atomic(target, raw_text.encode("utf-8"))
        return load_settings(root)
