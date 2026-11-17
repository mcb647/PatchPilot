"""Configuration loading, validation and file selection rules.

Effective order is: command line arguments, project ``.patchpilot.yaml``,
built-in defaults.  A missing project file is not an error.  The YAML loader is
safe and rejects duplicate keys, unknown keys and out-of-range values, because
the same file also selects what may be sent to external services in P1.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import JUDGE_FALLBACK_TRIGGERS, P0_MODES, digest_of

CONFIG_FILENAME = ".patchpilot.yaml"
LEGACY_CONFIG_FILENAME = "patchpilot.yaml"

DEFAULT_EXCLUDES = [
    "**/.git/**",
    "**/.venv/**",
    "**/venv/**",
    "**/node_modules/**",
    "**/build/**",
    "**/dist/**",
]


class ConfigError(ValueError):
    """Raised when project configuration is missing, malformed or unsupported."""


@dataclass
class GitConfig:
    mode: str = "worktree-net"
    base: str = "main"
    include_untracked: bool | None = None  # None => mode default


@dataclass
class FilesConfig:
    include: list[str] = field(default_factory=lambda: ["**"])
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    source_roots: list[str] = field(default_factory=lambda: ["src", "."])


@dataclass
class AnalysisConfig:
    max_depth: int = 3
    max_candidates_per_change: int = 30
    max_candidates_per_run: int = 500
    max_python_files_per_side: int = 2000
    max_python_bytes_per_side: int = 33554432
    max_file_bytes: int = 262144
    max_diff_lines_per_side: int = 3000
    max_diff_line_product: int = 4000000
    max_edges: int = 50000
    # P1: bounded similarity rename detection.
    rename_similarity_threshold: float = 0.8
    max_rename_candidates: int = 200


@dataclass
class JevAdapterConfig:
    # Only known adapters are selectable from project configuration; endpoints
    # and credentials always come from fixed environment variables.
    profile: str | None = None  # fake | http (http awaits the real contract)
    model: str | None = None


@dataclass
class LlmAdapterConfig:
    protocol: str | None = None  # openai
    model: str | None = None


@dataclass
class JudgeConfig:
    enabled: bool = False
    fallback_on: list[str] = field(
        default_factory=lambda: [
            "unavailable",
            "timeout",
            "invalid_output",
            "uncertain",
        ]
    )
    timeout_seconds: int = 20
    run_deadline_seconds: int = 90
    max_attempts: int = 12
    max_input_tokens_per_attempt: int = 6000
    max_output_tokens_per_attempt: int = 800
    max_total_tokens: int = 60000
    jev: JevAdapterConfig = field(default_factory=JevAdapterConfig)
    llm: LlmAdapterConfig = field(default_factory=LlmAdapterConfig)


@dataclass
class CacheConfig:
    ast_enabled: bool = True
    judge_enabled: bool = True
    ttl_days: int = 7
    max_bytes: int = 104857600


@dataclass
class StorageConfig:
    path: str | None = None
    evidence_mode: str = "excerpts"  # excerpts | metadata_only
    max_evidence_bytes_per_run: int = 2097152
    retain_days: int = 30
    max_runs: int = 100


@dataclass
class WebConfig:
    host: str = "127.0.0.1"
    port: int = 8765


@dataclass
class LoggingConfig:
    level: str = "INFO"


@dataclass
class Config:
    version: int = 1
    git: GitConfig = field(default_factory=GitConfig)
    files: FilesConfig = field(default_factory=FilesConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    judge: JudgeConfig = field(default_factory=JudgeConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    web: WebConfig = field(default_factory=WebConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return digest_of(self.to_dict())


# --------------------------------------------------------------------------
# glob translation
# --------------------------------------------------------------------------

_GLOB_CACHE: dict[str, re.Pattern[str]] = {}


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a slash separated repo-relative glob into a regex.

    ``**/`` matches zero or more leading directories (so ``**/build/**``
    matches ``build/x.py`` and ``a/build/y.py``), ``**`` matches across
    separators and ``*``/``?`` stay inside one path segment.
    """

    cached = _GLOB_CACHE.get(pattern)
    if cached is not None:
        return cached
    out: list[str] = ["^"]
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if pattern.startswith("**/", i):
                out.append("(?:.*/)?")
                i += 3
                continue
            if pattern.startswith("**", i):
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
            continue
        if ch == "?":
            out.append("[^/]")
            i += 1
            continue
        if ch == "[":
            j = i + 1
            if j < n and pattern[j] in "!^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j < n:
                inner = pattern[i + 1 : j]
                if inner.startswith("!"):
                    inner = "^" + inner[1:]
                out.append("[" + inner + "]")
                i = j + 1
                continue
            out.append(re.escape(ch))
            i += 1
            continue
        out.append(re.escape(ch))
        i += 1
    out.append("$")
    compiled = re.compile("".join(out))
    _GLOB_CACHE[pattern] = compiled
    return compiled


def match_any(path: str, patterns: list[str]) -> bool:
    return any(glob_to_regex(p).match(path) for p in patterns)


def is_excluded(path: str, files: FilesConfig) -> bool:
    return match_any(path, files.exclude)


def is_included(path: str, files: FilesConfig) -> bool:
    return match_any(path, files.include)


def file_selected(path: str, files: FilesConfig) -> bool:
    """Exclusion wins; otherwise the include list selects the path."""

    return is_included(path, files) and not is_excluded(path, files)


# --------------------------------------------------------------------------
# state directory and database location
# --------------------------------------------------------------------------


def state_root() -> Path:
    override = os.environ.get("PATCHPILOT_HOME")
    if override:
        return Path(override).expanduser().resolve()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return (Path(base) / "PatchPilot").resolve()
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg:
        return (Path(xdg) / "patchpilot").resolve()
    return (Path.home() / ".local" / "state" / "patchpilot").resolve()


def resolve_db_path(config: Config, repo_id: str) -> Path:
    """Resolve the SQLite database path for a repository.

    A project override must be a relative path below the user state directory;
    absolute paths and ``..`` escapes are rejected.
    """

    root = state_root()
    if config.storage.path:
        raw = config.storage.path.replace("\\", "/")
        if raw.startswith("/") or ":" in raw:
            raise ConfigError("storage.path must be a relative path below the user state directory")
        parts = [p for p in raw.split("/") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            raise ConfigError("storage.path must not contain '..'")
        candidate = root.joinpath(*parts).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:  # pragma: no cover - defensive
            raise ConfigError("storage.path escapes the user state directory") from exc
        return candidate
    return (root / "repos" / repo_id[:16] / "patchpilot.db").resolve()


# --------------------------------------------------------------------------
# YAML loading with strict validation
# --------------------------------------------------------------------------


class _StrictLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode):  # type: ignore[override]
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in mapping:
            raise ConfigError(f"duplicate configuration key: {key}")
        mapping[key] = loader.construct_object(value_node)
    return mapping


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


_SCHEMA: dict[str, Any] = {
    "version": int,
    "git": {"mode": str, "base": str, "include_untracked": (bool, type(None))},
    "files": {"include": list, "exclude": list, "source_roots": list},
    "analysis": {
        "max_depth": int,
        "max_candidates_per_change": int,
        "max_candidates_per_run": int,
        "max_python_files_per_side": int,
        "max_python_bytes_per_side": int,
        "max_file_bytes": int,
        "max_diff_lines_per_side": int,
        "max_diff_line_product": int,
        "max_edges": int,
        "rename_similarity_threshold": float,
        "max_rename_candidates": int,
    },
    "judge": {
        "enabled": bool,
        "fallback_on": list,
        "timeout_seconds": int,
        "run_deadline_seconds": int,
        "max_attempts": int,
        "max_input_tokens_per_attempt": int,
        "max_output_tokens_per_attempt": int,
        "max_total_tokens": int,
        "jev": {"profile": (str, type(None)), "model": (str, type(None))},
        "llm": {"protocol": (str, type(None)), "model": (str, type(None))},
    },
    "cache": {
        "ast_enabled": bool,
        "judge_enabled": bool,
        "ttl_days": int,
        "max_bytes": int,
    },
    "storage": {
        "path": (str, type(None)),
        "evidence_mode": str,
        "max_evidence_bytes_per_run": int,
        "retain_days": int,
        "max_runs": int,
    },
    "web": {"host": str, "port": int},
    "logging": {"level": str},
}

ANALYSIS_RANGES = {
    "max_depth": (1, 32),
    "max_candidates_per_change": (1, 5000),
    "max_candidates_per_run": (1, 50000),
    "max_python_files_per_side": (1, 50000),
    "max_python_bytes_per_side": (1, 1 << 31),
    "max_file_bytes": (1, 1 << 30),
    "max_diff_lines_per_side": (1, 1000000),
    "max_diff_line_product": (1, 1 << 40),
    "max_edges": (1, 10000000),
    "max_rename_candidates": (1, 10000),
}

KNOWN_JEV_PROFILES = (None, "fake", "http")
KNOWN_LLM_PROTOCOLS = (None, "openai")


def _check_type(section: str, key: str, value: Any, expected: Any) -> None:
    # bool is a subclass of int; keep the distinction for typed keys.
    if expected is int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ConfigError(f"{section}.{key} must be an integer")
        return
    if expected is bool:
        if not isinstance(value, bool):
            raise ConfigError(f"{section}.{key} must be a boolean")
        return
    if expected is float:
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ConfigError(f"{section}.{key} must be a number")
        return
    if isinstance(expected, tuple):
        if not isinstance(value, expected):
            raise ConfigError(f"{section}.{key} has an invalid type")
        return
    if not isinstance(value, expected):
        raise ConfigError(f"{section}.{key} has an invalid type")


def _merge_section(section: str, data: Any, spec: dict[str, Any], target: Any) -> None:
    if data is None:
        return
    if not isinstance(data, dict):
        raise ConfigError(f"configuration section '{section}' must be a mapping")
    for key, value in data.items():
        if key not in spec:
            raise ConfigError(f"unsupported configuration key: {section}.{key}")
        expected = spec[key]
        if isinstance(expected, dict):
            if not isinstance(value, dict):
                raise ConfigError(f"configuration section '{section}.{key}' must be a mapping")
            _merge_section(f"{section}.{key}", value, expected, getattr(target, key))
            continue
        _check_type(section, key, value, expected)
        setattr(target, key, value)


def _validate(config: Config) -> None:
    if config.version != 1:
        raise ConfigError(f"unsupported configuration version: {config.version!r}")
    if config.git.mode not in P0_MODES:
        raise ConfigError(
            f"git.mode must be one of {', '.join(P0_MODES)}; got {config.git.mode!r}"
        )
    if not config.git.base or not isinstance(config.git.base, str):
        raise ConfigError("git.base must be a non-empty ref name")
    for name, (low, high) in ANALYSIS_RANGES.items():
        value = getattr(config.analysis, name)
        if not (low <= value <= high):
            raise ConfigError(f"analysis.{name} must be between {low} and {high}")
    if not (1 <= config.web.port <= 65535):
        raise ConfigError("web.port must be between 1 and 65535")
    if not _is_loopback_host(config.web.host):
        raise ConfigError("web.host must be a loopback address (127.0.0.1, localhost or ::1)")
    if config.storage.evidence_mode not in ("excerpts", "metadata_only"):
        raise ConfigError("storage.evidence_mode must be 'excerpts' or 'metadata_only'")
    if config.storage.retain_days < 0 or config.storage.max_runs < 0:
        raise ConfigError("storage retention values must not be negative")
    threshold = config.analysis.rename_similarity_threshold
    if not (0.0 < threshold <= 1.0):
        raise ConfigError("analysis.rename_similarity_threshold must be in (0, 1]")
    if not config.judge.fallback_on:
        raise ConfigError("judge.fallback_on must not be empty")
    for trigger in config.judge.fallback_on:
        if trigger not in JUDGE_FALLBACK_TRIGGERS:
            raise ConfigError(
                f"judge.fallback_on contains an unknown trigger: {trigger!r} "
                f"(allowed: {', '.join(JUDGE_FALLBACK_TRIGGERS)})"
            )
    for key in (
        "timeout_seconds",
        "run_deadline_seconds",
        "max_attempts",
        "max_input_tokens_per_attempt",
        "max_output_tokens_per_attempt",
        "max_total_tokens",
    ):
        if getattr(config.judge, key) <= 0:
            raise ConfigError(f"judge.{key} must be positive")
    if config.judge.jev.profile not in KNOWN_JEV_PROFILES:
        raise ConfigError(
            "judge.jev.profile must be null, 'fake' or 'http' "
            "(the real JEV HTTP contract is not confirmed yet)"
        )
    if config.judge.llm.protocol not in KNOWN_LLM_PROTOCOLS:
        raise ConfigError("judge.llm.protocol must be null or 'openai'")
    if config.cache.ttl_days < 0 or config.cache.max_bytes < 0:
        raise ConfigError("cache values must not be negative")
    for field_name in ("include", "exclude", "source_roots"):
        values = getattr(config.files, field_name)
        if not all(isinstance(v, str) and v for v in values):
            raise ConfigError(f"files.{field_name} must be a list of non-empty strings")


def _is_loopback_host(host: str) -> bool:
    host = (host or "").strip().lower()
    return host in ("127.0.0.1", "localhost", "::1", "[::1]")


def config_file_path(repo_root: Path) -> Path:
    return Path(repo_root) / CONFIG_FILENAME


def _existing_config_path(repo_root: Path) -> Path | None:
    for path in (config_file_path(repo_root), Path(repo_root) / LEGACY_CONFIG_FILENAME):
        if path.is_file():
            return path
    return None


def _load_config_data(data: Any, source: str) -> Config:
    """Build and validate a Config from already-loaded YAML data."""

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"{source} must contain a YAML mapping")
    for key in data:
        if key not in _SCHEMA:
            raise ConfigError(f"unsupported configuration key: {key!r}")
    config = Config()
    for section, spec in _SCHEMA.items():
        if section == "version":
            if section in data:
                _check_type("root", "version", data[section], int)
                config.version = data[section]
            continue
        if section not in data:
            continue
        _merge_section(section, data[section], spec, getattr(config, section))
    _validate(config)
    return config


def parse_config_text(text: str) -> Config:
    """Strictly parse configuration text without touching the filesystem.

    Used by the Web settings preview/save flow; the caller is responsible for
    path-level errors.  Plain configuration errors are raised as ``ConfigError``.
    """

    try:
        data = yaml.load(text, Loader=_StrictLoader)
    except ConfigError:
        raise
    except yaml.YAMLError as exc:
        raise ConfigError(f"cannot parse YAML: {exc}") from exc
    return _load_config_data(data, "configuration text")


def config_from_dict(data: dict[str, Any]) -> Config:
    """Rebuild a frozen configuration snapshot (task execution)."""

    return _load_config_data(dict(data or {}), "frozen configuration")


def config_to_dict(config: Config) -> dict[str, Any]:
    return config.to_dict()


def load_config(repo_root: Path) -> tuple[Config, Path | None]:
    """Load effective configuration for a repository root."""

    path = _existing_config_path(repo_root)
    config = Config()
    if path is not None:
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise ConfigError(f"cannot read {path}: {exc}") from exc
        if size > 1_000_000:
            raise ConfigError(f"{path} is too large for a project configuration file")
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read {path}: {exc}") from exc
        try:
            config = parse_config_text(raw)
        except ConfigError as exc:
            raise ConfigError(f"{path}: {exc}") from exc
    return config, path


# --------------------------------------------------------------------------
# init template
# --------------------------------------------------------------------------

CONFIG_TEMPLATE = """# PatchPilot project configuration.
# Effective order: command line, this file, built-in defaults.
version: 1

git:
  mode: worktree-net       # worktree-net | staged | working-tree | base
  base: main
  include_untracked: null  # null = mode default

files:
  include: ["**"]
  exclude:
    - "**/.git/**"
    - "**/.venv/**"
    - "**/venv/**"
    - "**/node_modules/**"
    - "**/build/**"
    - "**/dist/**"
  source_roots: ["src", "."]

analysis:
  max_depth: 3
  max_candidates_per_change: 30
  max_candidates_per_run: 500
  max_python_files_per_side: 2000
  max_python_bytes_per_side: 33554432
  max_file_bytes: 262144
  max_diff_lines_per_side: 3000
  max_diff_line_product: 4000000
  rename_similarity_threshold: 0.8
  max_rename_candidates: 200

judge:
  enabled: false           # Legacy field; authorize Judge on each CLI run or Web task
  fallback_on: [unavailable, timeout, invalid_output, uncertain]
  timeout_seconds: 20
  run_deadline_seconds: 90
  max_attempts: 12
  max_input_tokens_per_attempt: 6000
  max_output_tokens_per_attempt: 800
  max_total_tokens: 60000
  jev:
    profile: null          # fake | http (real JEV contract is not confirmed yet)
    model: null
  llm:
    protocol: null         # openai
    model: null

cache:
  ast_enabled: true
  judge_enabled: true
  ttl_days: 7
  max_bytes: 104857600

storage:
  path: null      # relative path below the user state directory
  evidence_mode: excerpts
  max_evidence_bytes_per_run: 2097152
  retain_days: 30
  max_runs: 100

web:
  host: "127.0.0.1"
  port: 8765

logging:
  level: INFO
"""


def init_config(repo_root: Path) -> tuple[Path, bool]:
    """Create the project template.  Returns ``(path, created)``."""

    existing = _existing_config_path(repo_root)
    if existing is not None:
        return existing, False
    path = config_file_path(repo_root)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(CONFIG_TEMPLATE)
    except FileExistsError:
        if path.is_file():
            return path, False
        raise ConfigError(f"cannot create project configuration: {path} is already in use") from None
    except OSError as exc:
        raise ConfigError(f"cannot write {path}: {exc}") from exc
    return path, True


def is_loopback_host(host: str) -> bool:
    return _is_loopback_host(host)


def default_log_level(config: Config) -> int:
    import logging

    level = (config.logging.level or "INFO").upper()
    return getattr(logging, level, logging.INFO)


if sys.version_info < (3, 11):  # pragma: no cover - package metadata enforces this
    raise RuntimeError("PatchPilot requires Python 3.11 or newer")
