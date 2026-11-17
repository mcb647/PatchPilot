"""Import ``coverage json`` output as optional test recommendations evidence.

Coverage data is *not* part of the current run: it is an externally produced
artifact that only proves which code was executed by which test context when
the coverage file was generated.  The importer therefore validates the file
strictly and never executes anything.

Accepted JSON shape (the standard ``coverage json --show-contexts`` format)::

    {
      "meta": {...},                       # optional, ignored
      "files": {
        "pkg/pricing.py": {
          "executed_lines": [2, 3, 7],
          "contexts": {                    # optional
            "tests/test_pricing.py::test_total": [2, 3]
          }
        }
      }
    }

Assumptions kept deliberately narrow and documented here (deviation/holes are
reported to the Lead):

* ``files`` must be an object; every key is a repository-relative POSIX path.
  Absolute paths are accepted only when they resolve inside ``repo_root`` and
  are then normalized to the repo-relative form; anything escaping the repo is
  rejected.
* ``executed_lines`` is an optional list of 1-based positive integers.
* ``contexts`` may be either an object mapping context name -> line list or a
  list of context names (the standard ``--show-contexts`` file form).  The list
  form has no per-context line detail, so the file's ``executed_lines`` are
  attached to every listed context.  Context names are opaque labels except for
  the ``<test path>::<test name>`` convention used for test matching.
* Structural problems, bad JSON, a missing/oversized file and unsafe paths raise
  :class:`CoverageError` with a structured ``reason`` code (never a diagnostic
  object: the CLI/analyze caller decides how to surface it).  ``to_dict()``
  renders ``{code, message, path, line, details}`` which maps 1:1 onto
  ``models.Diagnostic`` fields.
* ``load_coverage(None, ...)`` returns ``None`` meaning "coverage was not
  requested"; every other failure raises.

Only :class:`CoverageEvidence` is consumed by ``recommend.recommend_tests``
(``coverage=...``): it annotates existing recommendations, it never creates new
ones and never changes their strength/depth/sort order.
"""

from __future__ import annotations

import json
import posixpath
import re
import stat
from pathlib import Path
from typing import Any

# Conservative default: a 16 MiB Coverage JSON already covers a very large
# repository; anything bigger is rejected before reading.
DEFAULT_MAX_BYTES = 16 * 1024 * 1024

# Structured failure reasons (stable strings reported to the CLI/Lead).
COVERAGE_MISSING_FILE = "missing_file"
COVERAGE_NOT_A_FILE = "not_a_file"
COVERAGE_TOO_LARGE = "too_large"
COVERAGE_INVALID_JSON = "invalid_json"
COVERAGE_INVALID_STRUCTURE = "invalid_structure"
COVERAGE_INVALID_PATH = "invalid_path"
COVERAGE_PATH_OUTSIDE_REPO = "path_outside_repo"
COVERAGE_REPO_ROOT_MISSING = "repo_root_missing"
COVERAGE_INVALID_MAX_BYTES = "invalid_max_bytes"
COVERAGE_IO_ERROR = "io_error"

COVERAGE_ERROR_REASONS = (
    COVERAGE_MISSING_FILE,
    COVERAGE_NOT_A_FILE,
    COVERAGE_TOO_LARGE,
    COVERAGE_INVALID_JSON,
    COVERAGE_INVALID_STRUCTURE,
    COVERAGE_INVALID_PATH,
    COVERAGE_PATH_OUTSIDE_REPO,
    COVERAGE_REPO_ROOT_MISSING,
    COVERAGE_INVALID_MAX_BYTES,
    COVERAGE_IO_ERROR,
)

# Same test-file convention as ``ast_index`` (test_*.py / *_test.py).
_TEST_FILE_RE = re.compile(r"^(?:test_.*\.py|.*_test\.py)$")

_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:/")


class CoverageError(Exception):
    """Structured Coverage import failure.

    ``reason`` is one of :data:`COVERAGE_ERROR_REASONS`; ``path``/``line`` are
    populated when the failure can be attributed to one input location.
    """

    def __init__(
        self,
        reason: str,
        message: str,
        *,
        path: str | None = None,
        line: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.path = path
        self.line = line
        self.details = dict(details or {})

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.reason,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "details": dict(self.details),
        }

    def __str__(self) -> str:  # pragma: no cover - trivial
        location = f" ({self.path})" if self.path else ""
        return f"{self.reason}: {self.message}{location}"


# --------------------------------------------------------------------------
# path helpers
# --------------------------------------------------------------------------

def _repo_root_path(repo_root: str | Path | None) -> Path:
    if repo_root is None or not str(repo_root).strip():
        raise CoverageError(
            COVERAGE_REPO_ROOT_MISSING,
            "a repository root is required to validate coverage paths",
        )
    try:
        root = Path(repo_root).expanduser().resolve()
    except OSError as exc:  # pragma: no cover - unusual filesystem failure
        raise CoverageError(
            COVERAGE_REPO_ROOT_MISSING,
            f"repository root {repo_root!r} cannot be resolved: {exc}",
        ) from exc
    if not root.is_dir():
        raise CoverageError(
            COVERAGE_REPO_ROOT_MISSING,
            f"repository root {repo_root!r} is not a directory",
        )
    return root


def _normalize_repo_relative(raw: Any, repo_root: Path) -> str:
    """Normalize one coverage path to repo-relative POSIX, or raise."""

    if not isinstance(raw, str):
        raise CoverageError(
            COVERAGE_INVALID_PATH, "coverage path must be a string"
        )
    text = raw.strip()
    if not text or "\x00" in text or "\n" in text or "\r" in text:
        raise CoverageError(
            COVERAGE_INVALID_PATH, f"coverage path {raw!r} is not a usable path"
        )
    text = text.replace("\\", "/")

    if text.startswith("/") or _WINDOWS_DRIVE_RE.match(text):
        try:
            resolved = Path(raw).expanduser().resolve()
        except OSError:
            raise CoverageError(
                COVERAGE_PATH_OUTSIDE_REPO,
                f"coverage path {raw!r} cannot be resolved",
                path=str(raw),
            )
        try:
            relative = resolved.relative_to(repo_root)
        except ValueError:
            raise CoverageError(
                COVERAGE_PATH_OUTSIDE_REPO,
                f"coverage path {raw!r} is outside the repository",
                path=str(raw),
            )
        normalized = relative.as_posix()
    else:
        normalized = posixpath.normpath(text)

    if (
        not normalized
        or normalized in (".", "..")
        or normalized.startswith("../")
        or normalized.startswith("/")
    ):
        raise CoverageError(
            COVERAGE_PATH_OUTSIDE_REPO,
            f"coverage path {raw!r} escapes the repository",
            path=str(raw),
        )
    return normalized


def _normalize_context_path(raw: str, repo_root: Path) -> str | None:
    """Best-effort normalization for context file parts (never raises)."""

    try:
        return _normalize_repo_relative(raw, repo_root)
    except CoverageError:
        return None


def _normalize_query_path(path: Any) -> str:
    """Normalize a path coming from the index/recommendation side."""

    text = str(path or "").strip().replace("\\", "/")
    if not text:
        return ""
    normalized = posixpath.normpath(text)
    if normalized == ".":
        return ""
    return normalized


# --------------------------------------------------------------------------
# structure validation
# --------------------------------------------------------------------------

def _invalid_structure(message: str, *, path: str | None = None) -> CoverageError:
    return CoverageError(COVERAGE_INVALID_STRUCTURE, message, path=path)


def _validate_lines(value: Any, *, path: str, field: str) -> frozenset[int]:
    if value is None:
        return frozenset()
    if not isinstance(value, list):
        raise _invalid_structure(f"{field} must be a list of line numbers", path=path)
    lines: set[int] = set()
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int):
            raise _invalid_structure(
                f"{field} entries must be integers, got {type(item).__name__}",
                path=path,
            )
        if item < 1:
            raise _invalid_structure(
                f"{field} entries must be 1-based positive line numbers", path=path
            )
        lines.add(item)
    return frozenset(lines)


def _parse_contexts(
    raw_contexts: Any,
    executed: frozenset[int],
    *,
    path: str,
) -> dict[str, frozenset[int]]:
    if raw_contexts is None:
        return {}
    contexts: dict[str, frozenset[int]] = {}
    if isinstance(raw_contexts, dict):
        for raw_name, raw_lines in raw_contexts.items():
            if not isinstance(raw_name, str) or not raw_name.strip():
                raise _invalid_structure("context names must be non-empty strings", path=path)
            name = raw_name.strip()
            contexts[name] = contexts.get(name, frozenset()) | _validate_lines(
                raw_lines, path=path, field=f"contexts[{name!r}]"
            )
        return contexts
    if isinstance(raw_contexts, list):
        for item in raw_contexts:
            if not isinstance(item, str) or not item.strip():
                raise _invalid_structure(
                    "contexts list entries must be non-empty strings", path=path
                )
            name = item.strip()
            # List form carries no per-context lines: the file executed lines
            # are the best available proxy (documented module assumption).
            contexts[name] = contexts.get(name, frozenset()) | executed
        return contexts
    raise _invalid_structure("contexts must be an object or a list", path=path)


def _parse_file_entry(
    entry: Any, *, path: str
) -> tuple[frozenset[int], dict[str, frozenset[int]]]:
    if not isinstance(entry, dict):
        raise _invalid_structure("each files entry must be an object", path=path)
    executed = _validate_lines(entry.get("executed_lines"), path=path, field="executed_lines")
    contexts = _parse_contexts(entry.get("contexts"), executed, path=path)
    return executed, contexts


# --------------------------------------------------------------------------
# evidence container
# --------------------------------------------------------------------------

class CoverageEvidence:
    """Indexed, read-only view over one imported Coverage JSON report."""

    __slots__ = ("source_path", "repo_root", "_executed", "_contexts")

    def __init__(
        self,
        *,
        source_path: str,
        repo_root: str,
        executed: dict[str, frozenset[int]],
        contexts: dict[str, dict[str, frozenset[int]]],
    ) -> None:
        self.source_path = source_path
        self.repo_root = repo_root
        self._executed = dict(executed)
        self._contexts = {
            path: {name: frozenset(lines) for name, lines in by_context.items()}
            for path, by_context in contexts.items()
        }

    # -- basic accessors --------------------------------------------------
    @property
    def paths(self) -> list[str]:
        return sorted(set(self._executed) | set(self._contexts))

    def has_path(self, path: str) -> bool:
        normalized = _normalize_query_path(path)
        return normalized in self._executed or normalized in self._contexts

    def executed_lines(self, path: str) -> frozenset[int]:
        return self._executed.get(_normalize_query_path(path), frozenset())

    def contexts_for_path(self, path: str) -> list[str]:
        by_context = self._contexts.get(_normalize_query_path(path), {})
        return sorted(by_context)

    def all_lines(self, path: str) -> frozenset[int]:
        normalized = _normalize_query_path(path)
        lines = set(self._executed.get(normalized, frozenset()))
        for context_lines in self._contexts.get(normalized, {}).values():
            lines.update(context_lines)
        return frozenset(lines)

    # -- contract methods -------------------------------------------------
    def contexts_for(self, path: str, line: int) -> list[str]:
        """Contexts that executed ``line`` of ``path`` (sorted, unique)."""

        by_context = self._contexts.get(_normalize_query_path(path), {})
        if not by_context:
            return []
        return sorted(
            name for name, lines in by_context.items() if line in lines
        )

    def test_contexts(self) -> list[str]:
        """All context names that look like ``<test file>::<test name>``."""

        found = {
            raw
            for by_context in self._contexts.values()
            for raw in by_context
            if _test_context_parts(raw, Path(self.repo_root)) is not None
        }
        return sorted(found)

    # -- recommendation support ------------------------------------------
    def test_contexts_for(self, test_path: str, qualified_name: str) -> list[str]:
        """Matching contexts for one test symbol (sorted, unique).

        A context matches when its file part is the same test file (exact repo
        relative path, or a longer prefixed path ending with it) and its name
        components contain the test function's simple name (parametrized
        contexts such as ``test_x[p1]`` count).  The test path must have at
        least one coverage line record, otherwise no evidence is produced: the
        imported report only proves execution of what it lists.
        """

        normalized = _normalize_query_path(test_path)
        if not normalized or not self.has_path(normalized):
            return []
        if not self.all_lines(normalized):
            return []
        simple = (qualified_name or "").rsplit(".", 1)[-1].strip()
        if not simple:
            return []
        repo_root = Path(self.repo_root)
        matches: list[str] = []
        for raw in self.contexts_for_path(normalized):
            parts = _test_context_parts(raw, repo_root)
            if parts is None:
                continue
            context_path, names = parts
            if context_path != normalized and not context_path.endswith("/" + normalized):
                continue
            if simple in names or any(
                name.startswith(simple + "[") for name in names
            ):
                matches.append(raw)
        return sorted(set(matches))


def _test_context_parts(raw: str, repo_root: Path) -> tuple[str, list[str]] | None:
    """Split a context into ``(test file path, name components)`` if it is testy."""

    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if "::" not in text:
        return None
    file_part, _, rest = text.partition("::")
    if not file_part.strip() or not rest.strip():
        return None
    normalized = _normalize_context_path(file_part.strip(), repo_root)
    if normalized is None:
        return None
    if _TEST_FILE_RE.match(posixpath.basename(normalized)) is None:
        return None
    names = [component.strip() for component in rest.split("::") if component.strip()]
    if not names:
        return None
    if not any(name.startswith("test_") for name in names):
        return None
    return normalized, names


# --------------------------------------------------------------------------
# loader
# --------------------------------------------------------------------------

def load_coverage(
    path: str | Path | None,
    config: Any = None,
    repo_root: str | Path | None = None,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> CoverageEvidence | None:
    """Load one Coverage JSON report and return indexed evidence.

    ``path=None`` (or an empty string) means "no coverage requested" and
    returns ``None``.  ``config`` is accepted for the CONTRACTS-M1 signature
    ``load_coverage(path, config, repo_root)`` but is currently unused: the size
    limit is the explicit ``max_bytes`` argument.  Every other problem raises
    :class:`CoverageError` with a structured reason (see the module docstring).
    """

    if path is None:
        return None
    if isinstance(path, str) and not path.strip():
        return None
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise CoverageError(
            COVERAGE_INVALID_MAX_BYTES,
            f"max_bytes must be a positive integer, got {max_bytes!r}",
        )

    root = _repo_root_path(repo_root)
    source = Path(path)
    try:
        info = source.stat()
    except FileNotFoundError:
        raise CoverageError(
            COVERAGE_MISSING_FILE,
            f"coverage file {str(path)!r} does not exist",
            path=str(path),
        )
    except OSError as exc:
        raise CoverageError(
            COVERAGE_IO_ERROR,
            f"coverage file {str(path)!r} cannot be inspected: {exc}",
            path=str(path),
        )
    if not stat.S_ISREG(info.st_mode):
        raise CoverageError(
            COVERAGE_NOT_A_FILE,
            f"coverage path {str(path)!r} is not a regular file",
            path=str(path),
        )
    if info.st_size > max_bytes:
        raise CoverageError(
            COVERAGE_TOO_LARGE,
            f"coverage file is {info.st_size} bytes, above the {max_bytes} byte limit",
            path=str(path),
            details={"size_bytes": int(info.st_size), "max_bytes": max_bytes},
        )

    try:
        with open(source, "rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as exc:
        raise CoverageError(
            COVERAGE_IO_ERROR,
            f"coverage file {str(path)!r} cannot be read: {exc}",
            path=str(path),
        )
    if len(data) > max_bytes:
        raise CoverageError(
            COVERAGE_TOO_LARGE,
            f"coverage file grew above the {max_bytes} byte limit while reading",
            path=str(path),
            details={"size_bytes": len(data), "max_bytes": max_bytes},
        )

    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CoverageError(
            COVERAGE_INVALID_JSON,
            f"coverage file is not valid UTF-8: {exc.reason}",
            path=str(path),
            details={"offset": int(exc.start)},
        )
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CoverageError(
            COVERAGE_INVALID_JSON,
            f"coverage file is not valid JSON: {exc.msg}",
            path=str(path),
            line=int(exc.lineno),
            details={"column": int(exc.colno), "offset": int(exc.pos)},
        )

    if not isinstance(document, dict):
        raise _invalid_structure("coverage JSON root must be an object", path=str(path))
    files = document.get("files")
    if not isinstance(files, dict):
        raise _invalid_structure(
            "coverage JSON must contain a 'files' object", path=str(path)
        )

    executed_by_path: dict[str, frozenset[int]] = {}
    contexts_by_path: dict[str, dict[str, frozenset[int]]] = {}
    for raw_path, entry in files.items():
        normalized = _normalize_repo_relative(raw_path, root)
        executed, contexts = _parse_file_entry(entry, path=normalized)
        # Duplicate spellings of the same file ("./x.py" vs "x.py") merge.
        executed_by_path[normalized] = (
            executed_by_path.get(normalized, frozenset()) | executed
        )
        merged = contexts_by_path.setdefault(normalized, {})
        for name, lines in contexts.items():
            merged[name] = merged.get(name, frozenset()) | lines

    return CoverageEvidence(
        source_path=str(path),
        repo_root=str(root),
        executed=executed_by_path,
        contexts=contexts_by_path,
    )
