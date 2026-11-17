"""Read-only capture of Git comparison endpoints ("snapshots").

Every Git invocation in this module is a read-only plumbing command executed
with an argument array (``shell=False``) and NUL separated path output.  The
module never executes repository code, never follows symbolic links, never
writes to the index/refs/working tree and validates every repository-relative
path before the working tree is read.

The four P0 modes map to the following endpoints::

    worktree-net   HEAD tree   -> working tree (untracked files included)
    staged         HEAD tree   -> index stage 0
    working-tree   index       -> working tree (tracked files only by default)
    base REF       merge-base  -> HEAD tree

P1 adds two commit-object-only endpoints.  They never read the index or the
working tree; a dirty checkout cannot change their result::

    commit REV [parent N]   parent commit tree -> REV tree (empty side for a root)
    range A..B              A commit tree      -> B commit tree
    range A...B             merge-base(A, B)   -> B commit tree
"""

from __future__ import annotations

import hashlib
import io
import os
import stat
import subprocess
import threading
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from .config import Config, file_selected
from .models import (
    ALL_MODES,
    MODE_BASE,
    MODE_COMMIT,
    MODE_RANGE,
    MODE_STAGED,
    MODE_WORKING_TREE,
    MODE_WORKTREE_NET,
    SIDE_AFTER,
    SIDE_BEFORE,
    Diagnostic,
    Snapshot,
    SnapshotEntry,
    SnapshotSide,
    diag,
    digest_of,
    repo_display_name,
    repo_id_for,
)

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

_GIT_TIMEOUT_SECONDS = 120
_READ_CHUNK = 1 << 16
_GIT_TEXT_BYTES = bytes(range(32, 127)) + bytes(range(128, 256)) + b"\b\t\x1b\f\n"
_EOL_ATTRIBUTES = ("text", "crlf", "eol", "filter", "working-tree-encoding", "ident")
_GIT_CONFIG_ARGS = (
    "-c",
    "core.quotepath=false",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "diff.external=",
)


class SnapshotError(Exception):
    """Raised when a comparison endpoint cannot be captured safely."""


# ---------------------------------------------------------------------------
# Git plumbing helpers
# ---------------------------------------------------------------------------


def _git_environment() -> dict[str, str]:
    """Environment for read-only Git calls.

    Optional locks are disabled so that read-only commands cannot rewrite the
    index, replacement objects are ignored and lazy object fetching is disabled
    so a partial clone cannot trigger network access while reading a snapshot.
    """

    env = dict(os.environ)
    for name in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_COMMON_DIR",
    ):
        env.pop(name, None)
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    env["GIT_NO_LAZY_FETCH"] = "1"
    return env


def _stderr_text(proc: subprocess.CompletedProcess[bytes]) -> str:
    return proc.stderr.decode("utf-8", "replace").strip()


def _run_git(
    root: Path, *args: str, input_bytes: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    """Run a read-only Git command and return the raw result."""

    command = ["git", *_GIT_CONFIG_ARGS, *args]
    try:
        return subprocess.run(
            command,
            cwd=str(root),
            input=input_bytes,
            capture_output=True,
            env=_git_environment(),
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:  # pragma: no cover - environment guard
        raise SnapshotError("git executable was not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - hung git
        raise SnapshotError(f"git {' '.join(args)} timed out after {_GIT_TIMEOUT_SECONDS}s") from exc
    except OSError as exc:
        raise SnapshotError(f"cannot run git in {root}: {exc}") from exc


def _run_git_ok(root: Path, *args: str, context: str) -> bytes:
    proc = _run_git(root, *args)
    if proc.returncode != 0:
        raise SnapshotError(f"{context}: {_stderr_text(proc) or 'git exited with an error'}")
    return proc.stdout


# ---------------------------------------------------------------------------
# path helpers
# ---------------------------------------------------------------------------


def _decode_path(raw: bytes) -> str:
    return raw.decode("utf-8", "surrogateescape")


def _validate_relative_path(path: str) -> None:
    """Reject repository relative paths that could escape or confuse joins."""

    if not path:
        raise SnapshotError("git returned an empty repository path")
    if "\x00" in path:
        raise SnapshotError("git returned a path containing a NUL byte")
    if path.startswith(("/", "\\")) or path.startswith("//"):
        raise SnapshotError(f"git returned an absolute path: {path!r}")
    if "\\" in path:
        raise SnapshotError(f"git returned a path with a backslash separator: {path!r}")
    if len(path) >= 2 and path[1] == ":" and path[0].isalpha():
        raise SnapshotError(f"git returned a path with a drive letter: {path!r}")
    for part in path.split("/"):
        if part in ("", ".", ".."):
            raise SnapshotError(f"git returned an unsafe repository path: {path!r}")


def _is_within(child: str | Path, parent: str | Path) -> bool:
    child_real = os.path.normcase(os.path.realpath(str(child)))
    parent_real = os.path.normcase(os.path.realpath(str(parent)))
    if child_real == parent_real:
        return True
    separator = os.sep
    return child_real.startswith(parent_real + separator)


def _worktree_path(root: Path, path: str) -> Path:
    """Resolve and validate one repository relative path for a worktree read."""

    _validate_relative_path(path)
    target = root.joinpath(*path.split("/"))
    if not _is_within(target, root):
        raise SnapshotError(f"repository path escapes the working tree: {path!r}")
    return target


def _is_python_path(path: str) -> bool:
    return path.endswith(".py")


def _path_is_regular(path: Path) -> tuple[bool, bool]:
    """Return ``(exists, is_symlink)`` without following a final symlink."""

    try:
        st = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False, False
    except OSError:
        return False, False
    return True, stat.S_ISLNK(st.st_mode)


# ---------------------------------------------------------------------------
# repository, refs and endpoint enumeration
# ---------------------------------------------------------------------------


def _resolve_repo_root(repo_root: Path) -> Path:
    try:
        candidate = Path(repo_root).expanduser().resolve()
    except OSError as exc:
        raise SnapshotError(f"cannot resolve repository path {repo_root}: {exc}") from exc
    if not candidate.exists():
        raise SnapshotError(f"repository path does not exist: {candidate}")
    if not candidate.is_dir():
        raise SnapshotError(f"repository path is not a directory: {candidate}")
    proc = _run_git(candidate, "rev-parse", "--show-toplevel")
    if proc.returncode != 0:
        raise SnapshotError(f"not a Git working tree: {candidate}: {_stderr_text(proc) or 'rev-parse failed'}")
    raw_top = proc.stdout.decode("utf-8", "surrogateescape").strip()
    if not raw_top:
        raise SnapshotError(f"git did not report a working tree for {candidate}")
    top = Path(raw_top).resolve()
    if not _is_within(candidate, top):
        raise SnapshotError(f"{candidate} is not located inside the Git working tree {top}")
    return top


def _resolve_refs(root: Path) -> tuple[str | None, str | None, bool]:
    """Return ``(head_oid, branch, detached)``; an unborn HEAD gives ``None``."""

    proc = _run_git(root, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
    head_oid = proc.stdout.decode("utf-8", "replace").strip() if proc.returncode == 0 else None
    branch_proc = _run_git(root, "symbolic-ref", "--quiet", "--short", "HEAD")
    branch = None
    if branch_proc.returncode == 0:
        text = branch_proc.stdout.decode("utf-8", "surrogateescape").strip()
        branch = text or None
    if head_oid is None:
        # An unborn branch keeps HEAD symbolic; anything else is a hard error.
        full = _run_git(root, "symbolic-ref", "--quiet", "HEAD")
        if full.returncode != 0:
            raise SnapshotError(f"cannot resolve HEAD: {_stderr_text(proc) or 'invalid HEAD'}")
    detached = head_oid is not None and branch is None
    return head_oid, branch, detached


def _head_oid(root: Path) -> str | None:
    proc = _run_git(root, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", "replace").strip() or None


def _resolve_commit_ref(root: Path, ref: str, context: str) -> str:
    """Resolve ``ref`` to one commit OID (``REV^{commit}``), fixed immediately."""

    proc = _run_git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    oid = proc.stdout.decode("utf-8", "replace").strip() if proc.returncode == 0 else ""
    if proc.returncode != 0 or not oid:
        raise SnapshotError(f"{context}: {ref}")
    return oid


def _merge_base_between(
    root: Path,
    left_ref: str,
    left_oid: str,
    right_ref: str,
    right_oid: str,
) -> str:
    """Return the unique merge base of two commits, or raise a SnapshotError."""

    proc = _run_git(root, "merge-base", "--all", left_oid, right_oid)
    if proc.returncode != 0:
        raise SnapshotError(f"no common ancestor between {left_ref} and {right_ref}")
    lines = [line.strip() for line in proc.stdout.decode("utf-8", "replace").splitlines() if line.strip()]
    if not lines:
        raise SnapshotError(f"no common ancestor between {left_ref} and {right_ref}")
    if len(lines) > 1:
        raise SnapshotError(
            f"multiple merge bases between {left_ref} and {right_ref}; this history is ambiguous"
        )
    return lines[0]


def _merge_base_oid(root: Path, base_ref: str, head_oid: str) -> str:
    base_oid = _resolve_commit_ref(root, base_ref, "base ref not found")
    return _merge_base_between(root, base_ref, base_oid, "HEAD", head_oid)


def _commit_parents(root: Path, commit_oid: str, commit_ref: str) -> list[str]:
    """Return the ordered (1-based) parent OIDs of one commit object."""

    proc = _run_git(root, "rev-list", "--parents", "-n", "1", commit_oid)
    if proc.returncode != 0:
        raise SnapshotError(
            f"cannot read parents of {commit_ref}: {_stderr_text(proc) or 'rev-list failed'}"
        )
    fields = proc.stdout.decode("utf-8", "replace").split()
    if not fields or fields[0] != commit_oid:
        raise SnapshotError(f"cannot read parents of {commit_ref}")
    return fields[1:]


def _select_commit_parent(
    commit_ref: str,
    commit_oid: str,
    parents: Sequence[str],
    parent_index: int | None,
) -> tuple[int, str]:
    """Pick the parent used as the "before" endpoint.

    Returns ``(0, "")`` for a root commit.  A merge commit requires an explicit
    1-based ``parent_index``; an out-of-range index is always an error.
    """

    if not parents:
        if parent_index is not None:
            raise SnapshotError(
                f"{commit_ref} ({_short(commit_oid)}) is a root commit and has no parents; "
                f"parent index {parent_index} is out of range"
            )
        return 0, ""
    count = len(parents)
    if parent_index is None:
        if count > 1:
            raise SnapshotError(
                f"{commit_ref} ({_short(commit_oid)}) is a merge commit with {count} parents; "
                f"pass parent_index (1..{count}) to choose the comparison base"
            )
        return 1, parents[0]
    if not 1 <= parent_index <= count:
        raise SnapshotError(
            f"parent index {parent_index} is out of range for {commit_ref} "
            f"({_short(commit_oid)}): expected 1..{count}"
        )
    return parent_index, parents[parent_index - 1]


def _parse_range_spec(spec: str) -> tuple[str, str, bool]:
    """Split ``A..B`` / ``A...B`` into ``(A, B, three_dot)``.

    Both endpoints must be non-empty.  Git ref names cannot contain ``..``, so
    the first separator is always the range operator; anything else is a
    malformed spec rather than a (never resolvable) ref name.
    """

    if ".." not in spec:
        raise SnapshotError(f"invalid range spec {spec!r}: expected A..B or A...B")
    left, rest = spec.split("..", 1)
    three_dot = rest.startswith(".")
    right = rest[1:] if three_dot else rest
    if not left or not right:
        raise SnapshotError(f"invalid range spec {spec!r}: both endpoints are required")
    if right.startswith(".") or ".." in right:
        raise SnapshotError(f"invalid range spec {spec!r}: unexpected extra range separators")
    return left, right, three_dot


def _ensure_no_sparse_checkout(root: Path) -> None:
    proc = _run_git(root, "config", "--get", "--type=bool", "core.sparseCheckout")
    value = proc.stdout.decode("utf-8", "replace").strip().lower()
    if proc.returncode == 0 and value == "true":
        raise SnapshotError(
            "sparse checkout is not supported for worktree modes: missing files cannot be "
            "distinguished from deletions"
        )


def _tree_blobs(root: Path, rev: str) -> dict[str, tuple[str, str]]:
    """Return ``{path: (mode, object_oid)}`` for one tree-ish.

    Submodule entries (mode ``160000``) are kept in the mapping so both
    endpoints stay symmetric; they are reported as unreadable ``gitlink``
    entries instead of being followed.
    """

    proc = _run_git(root, "ls-tree", "-r", "-z", "--full-tree", rev)
    if proc.returncode != 0:
        raise SnapshotError(f"cannot read tree {rev}: {_stderr_text(proc) or 'ls-tree failed'}")
    present: dict[str, tuple[str, str]] = {}
    for record in proc.stdout.split(b"\x00"):
        if not record:
            continue
        try:
            meta, raw_path = record.split(b"\t", 1)
        except ValueError as exc:  # pragma: no cover - defensive
            raise SnapshotError(f"cannot parse git ls-tree output for {rev}") from exc
        parts = meta.split()
        if len(parts) != 3:
            raise SnapshotError(f"cannot parse git ls-tree entry in {rev}")
        mode = parts[0].decode("ascii", "replace")
        object_type = parts[1].decode("ascii", "replace")
        object_id = parts[2].decode("ascii", "replace")
        path = _decode_path(raw_path)
        _validate_relative_path(path)
        if object_type == "blob" or mode == "160000":
            present[path] = (mode, object_id)
    return present


@dataclass
class _IndexState:
    entries: dict[str, tuple[str, str]] = field(default_factory=dict)  # stage 0
    records: list[tuple[str, str, str, str]] = field(default_factory=list)  # all stages
    unmerged: bool = False
    gitlinks: list[str] = field(default_factory=list)


def _read_index(root: Path) -> _IndexState:
    proc = _run_git(root, "ls-files", "-s", "-z")
    if proc.returncode != 0:
        raise SnapshotError(f"cannot read the index: {_stderr_text(proc) or 'ls-files failed'}")
    state = _IndexState()
    for record in proc.stdout.split(b"\x00"):
        if not record:
            continue
        try:
            meta, raw_path = record.split(b"\t", 1)
        except ValueError as exc:  # pragma: no cover - defensive
            raise SnapshotError("cannot parse git ls-files output") from exc
        parts = meta.split()
        if len(parts) != 3:
            raise SnapshotError("cannot parse git ls-files entry")
        mode = parts[0].decode("ascii", "replace")
        object_id = parts[1].decode("ascii", "replace")
        stage = parts[2].decode("ascii", "replace")
        path = _decode_path(raw_path)
        _validate_relative_path(path)
        state.records.append((path, mode, object_id, stage))
        if stage != "0":
            state.unmerged = True
            continue
        state.entries[path] = (mode, object_id)
        if mode == "160000":
            state.gitlinks.append(path)
    state.gitlinks = sorted(set(state.gitlinks))
    return state


def _untracked_paths(root: Path) -> list[str]:
    proc = _run_git(root, "ls-files", "-o", "-z", "--exclude-standard")
    if proc.returncode != 0:
        raise SnapshotError(f"cannot list untracked files: {_stderr_text(proc) or 'ls-files failed'}")
    paths: list[str] = []
    for record in proc.stdout.split(b"\x00"):
        if not record:
            continue
        path = _decode_path(record)
        _validate_relative_path(path)
        paths.append(path)
    return sorted(set(paths))


def _changed_cached_names(root: Path, ita_flag: str) -> set[str]:
    proc = _run_git(
        root,
        "diff",
        "--cached",
        "--name-only",
        "-z",
        "--no-renames",
        "--no-ext-diff",
        ita_flag,
    )
    if proc.returncode != 0:
        raise SnapshotError(
            f"git does not support {ita_flag}, which is required to distinguish intent-to-add "
            f"index entries: {_stderr_text(proc) or 'git diff failed'}"
        )
    paths: set[str] = set()
    for record in proc.stdout.split(b"\x00"):
        if not record:
            continue
        path = _decode_path(record)
        _validate_relative_path(path)
        paths.add(path)
    return paths


def _intent_to_add_paths(root: Path) -> set[str]:
    """Paths that are only placeholders created by ``git add -N``.

    Git >= 2.55 keeps intent-to-add entries at stage 0 with the empty blob OID,
    indistinguishable from a genuinely staged empty file by OID alone.  The two
    experimental diff flags expose the difference: visible minus invisible is
    exactly the set of placeholder entries.
    """

    visible = _changed_cached_names(root, "--ita-visible-in-index")
    hidden = _changed_cached_names(root, "--ita-invisible-in-index")
    return visible - hidden


# ---------------------------------------------------------------------------
# reading Git blobs
# ---------------------------------------------------------------------------


@dataclass
class _Blob:
    size: int
    sha256: str
    data: bytes | None
    has_crlf: bool


def _read_git_blobs(
    root: Path,
    oids: Iterable[str],
    max_file_bytes: int,
    retain_oids: set[str],
) -> dict[str, _Blob | None]:
    """Read blobs through one ``git cat-file --batch`` process.

    Content is streamed and hashed; bytes are only retained when the caller
    needs the text (small Python files).  ``None`` marks an object git reported
    as missing.
    """

    unique = sorted(set(oids))
    if not unique:
        return {}
    payload = ("".join(oid + "\n" for oid in unique)).encode("ascii", "strict")
    command = ["git", *_GIT_CONFIG_ARGS, "cat-file", "--batch"]
    try:
        proc = subprocess.Popen(
            command,
            cwd=str(root),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
        )
    except OSError as exc:  # pragma: no cover - environment guard
        raise SnapshotError(f"cannot run git cat-file: {exc}") from exc
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None

    def _feed() -> None:
        try:
            proc.stdin.write(payload)
            proc.stdin.close()
        except (OSError, ValueError):  # pragma: no cover - git exited early
            pass

    feeder = threading.Thread(target=_feed, name="patchpilot-cat-file", daemon=True)
    feeder.start()
    results: dict[str, _Blob | None] = {}
    try:
        for oid in unique:
            header = proc.stdout.readline()
            if not header:
                raise SnapshotError("git cat-file terminated before all objects were read")
            fields = header.rstrip(b"\n").split(b" ")
            if len(fields) == 2 and fields[1] == b"missing":
                results[oid] = None
                continue
            if len(fields) != 3:
                raise SnapshotError("cannot parse git cat-file batch header")
            try:
                size = int(fields[2])
            except ValueError as exc:
                raise SnapshotError("cannot parse git cat-file object size") from exc
            digest = hashlib.sha256()
            has_crlf = False
            previous_cr = False
            retained: bytearray | None = None
            if oid in retain_oids and size <= max_file_bytes:
                retained = bytearray()
            remaining = size
            while remaining > 0:
                chunk = proc.stdout.read(min(_READ_CHUNK, remaining))
                if not chunk:
                    raise SnapshotError("git cat-file returned a truncated object")
                digest.update(chunk)
                if not has_crlf:
                    has_crlf = b"\r\n" in chunk or (previous_cr and chunk.startswith(b"\n"))
                    previous_cr = chunk.endswith(b"\r")
                if retained is not None:
                    retained.extend(chunk)
                remaining -= len(chunk)
            proc.stdout.read(1)  # trailing newline
            results[oid] = _Blob(
                size=size,
                sha256=digest.hexdigest(),
                data=bytes(retained) if retained is not None else None,
                has_crlf=has_crlf,
            )
        feeder.join(timeout=_GIT_TIMEOUT_SECONDS)
        stderr = proc.stderr.read()
        return_code = proc.wait(timeout=_GIT_TIMEOUT_SECONDS)
    except Exception:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):  # pragma: no cover - defensive
            pass
        raise
    if return_code != 0:
        raise SnapshotError(
            "git cat-file failed: " + stderr.decode("utf-8", "replace").strip()
        )
    return results


# ---------------------------------------------------------------------------
# reading the working tree
# ---------------------------------------------------------------------------


def _decode_python(data: bytes) -> str:
    encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
    text = data.decode(encoding)
    return text.replace("\r\n", "\n").replace("\r", "\n")


@dataclass
class _WorktreeFile:
    size: int
    sha256: str
    data: bytes | None
    lf_sha256: str | None
    text_for_auto_eol: bool


def _read_worktree_regular(
    target: Path, max_file_bytes: int, retain: bool
) -> _WorktreeFile:
    """Stream raw bytes alongside a comparison digest with CRLF converted to LF."""

    digest = hashlib.sha256()
    lf_digest = hashlib.sha256()
    pending_cr = b""
    last_byte = b""
    has_crlf = has_lone_cr = has_nul = False
    printable = nonprintable = 0
    retained: bytearray | None = bytearray() if retain else None
    total = 0
    with open(target, "rb") as handle:
        while True:
            chunk = handle.read(_READ_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            last_byte = chunk[-1:]
            part = pending_cr + chunk
            pending_cr = b""
            if part.endswith(b"\r"):
                part, pending_cr = part[:-1], b"\r"
            normalized = part.replace(b"\r\n", b"\n")
            lf_digest.update(normalized)
            has_crlf |= len(normalized) != len(part)
            has_lone_cr |= b"\r" in normalized
            has_nul |= b"\x00" in normalized
            controls = len(normalized.translate(None, _GIT_TEXT_BYTES))
            printable += len(normalized) - normalized.count(b"\n") - controls
            nonprintable += controls
            if retained is not None:
                retained.extend(chunk)
                if len(retained) > max_file_bytes:
                    retained = None
    if pending_cr:
        lf_digest.update(pending_cr)
        has_lone_cr = True
    if last_byte == b"\x1a":
        nonprintable -= 1
    return _WorktreeFile(
        size=total,
        sha256=digest.hexdigest(),
        data=bytes(retained) if retained is not None else None,
        lf_sha256=lf_digest.hexdigest() if has_crlf else None,
        text_for_auto_eol=not (has_lone_cr or has_nul or nonprintable > printable // 128),
    )


def _worktree_eol_matches(
    root: Path,
    matches: dict[str, bool],
    before: SnapshotSide,
    index_entries: dict[str, tuple[str, str]],
) -> set[str]:
    """Confirm CRLF-only matches using Git attributes, without clean filters."""
    if not matches:
        return set()
    paths = b"".join(path.encode("utf-8", "surrogateescape") + b"\0" for path in sorted(matches))
    result = _run_git(root, "check-attr", "-z", "--stdin", *_EOL_ATTRIBUTES, input_bytes=paths)
    if result.returncode != 0:
        raise SnapshotError(f"cannot read Git text attributes: {_stderr_text(result)}")
    fields = result.stdout.split(b"\0")
    if not fields or fields.pop() != b"" or len(fields) % 3:
        raise SnapshotError("cannot parse Git text attributes")
    attributes: dict[str, dict[str, bytes]] = {}
    for raw_path, name, value in zip(fields[::3], fields[1::3], fields[2::3]):
        attributes.setdefault(_decode_path(raw_path), {})[name.decode("ascii")] = value
    if attributes.keys() != matches.keys() or any(
        attrs.keys() != set(_EOL_ATTRIBUTES) for attrs in attributes.values()
    ):
        raise SnapshotError("Git returned incomplete text attributes")

    autocrlf = _run_git(root, "config", "--get", "core.autocrlf")
    use_auto = autocrlf.returncode == 0 and autocrlf.stdout.strip().lower() == b"input"
    if autocrlf.returncode == 0 and not use_auto:
        enabled = _run_git(root, "config", "--type=bool", "--get", "core.autocrlf")
        use_auto = enabled.returncode == 0 and enabled.stdout.strip() == b"true"

    equivalent = set()
    check_index: dict[str, str] = {}
    for path, text_for_auto in matches.items():
        attrs = attributes[path]
        text = attrs["text"]
        if text not in (b"set", b"unset", b"auto", b"input"):
            text = attrs["crlf"]
        if text == b"unset" or any(
            attrs[name] not in (b"unspecified", b"unset")
            for name in ("filter", "working-tree-encoding", "ident")
        ):
            continue
        if text != b"auto" and (
            text in (b"set", b"input") or attrs["eol"] in (b"lf", b"crlf")
        ):
            equivalent.add(path)
        elif text_for_auto and (text == b"auto" or use_auto):
            indexed = index_entries.get(path)
            if indexed and indexed[0] in ("100644", "100755") and indexed[1] != before.entries[path].git_oid:
                check_index[path] = indexed[1]
            else:
                equivalent.add(path)

    # For auto text, Git preserves existing CRLF in the index. Only worktree-net
    # can compare against a different blob, so check those index objects separately.
    indexed_blobs = _read_git_blobs(root, check_index.values(), 0, set())
    for path, oid in check_index.items():
        blob = indexed_blobs.get(oid)
        if blob is not None and not blob.has_crlf:
            equivalent.add(path)
    return equivalent


# ---------------------------------------------------------------------------
# side construction
# ---------------------------------------------------------------------------


class _ContentCollector:
    """Collect decoded Python text while enforcing the per-side budgets."""

    def __init__(self, side: str, config: Config, diagnostics: list[Diagnostic]) -> None:
        self.side = side
        self.contents: dict[str, str] = {}
        self.diagnostics = diagnostics
        self.max_files = config.analysis.max_python_files_per_side
        self.max_bytes = config.analysis.max_python_bytes_per_side
        self.count = 0
        self.total_bytes = 0
        self.limit: str | None = None
        self.limit_value: int | None = None
        self.skipped = 0

    def add(self, path: str, text: str, size: int) -> None:
        if self.limit is not None:
            self.skipped += 1
            return
        if self.count >= self.max_files:
            self.limit = "max_python_files_per_side"
            self.limit_value = self.max_files
            self.skipped += 1
            return
        if self.total_bytes + size > self.max_bytes:
            self.limit = "max_python_bytes_per_side"
            self.limit_value = self.max_bytes
            self.skipped += 1
            return
        self.contents[path] = text
        self.count += 1
        self.total_bytes += size

    def finish(self) -> None:
        if self.limit is None:
            return
        self.diagnostics.append(
            diag(
                "python_limit",
                f"stopped collecting Python contents on the {self.side} side: {self.limit} reached",
                severity="warning",
                details={
                    "side": self.side,
                    "limit": self.limit,
                    "value": self.limit_value,
                    "skipped": self.skipped,
                },
            )
        )


def _new_entry(path: str, side: str) -> SnapshotEntry:
    return SnapshotEntry(side=side, path=path, is_python=_is_python_path(path))


def _manifest_digest(entries: dict[str, SnapshotEntry]) -> str:
    rows = [
        [entry.path, entry.status, entry.content_sha256, entry.git_oid, entry.size]
        for entry in sorted(entries.values(), key=lambda item: item.path)
    ]
    return digest_of(rows)


def _add_entry_diagnostic(
    diagnostics: list[Diagnostic],
    code: str,
    message: str,
    severity: str,
    path: str,
    side: str,
    **details: object,
) -> None:
    diagnostics.append(
        diag(
            code,
            message,
            severity=severity,
            path=path,
            details={"side": side, **details},
        )
    )


def _build_blob_side(
    root: Path,
    side: str,
    all_paths: Sequence[str],
    present: dict[str, tuple[str, str]],
    config: Config,
    diagnostics: list[Diagnostic],
) -> SnapshotSide:
    max_file_bytes = config.analysis.max_file_bytes
    collector = _ContentCollector(side, config, diagnostics)
    retain_oids: set[str] = set()
    read_oids: list[str] = []
    for path, (mode, oid) in present.items():
        if mode in ("120000", "160000"):
            continue
        read_oids.append(oid)
        if _is_python_path(path):
            retain_oids.add(oid)
    blobs = _read_git_blobs(root, read_oids, max_file_bytes, retain_oids)

    entries: dict[str, SnapshotEntry] = {}
    for path in sorted(all_paths):
        entry = _new_entry(path, side)
        source = present.get(path)
        if source is None:
            entry.status = "missing"
            entries[path] = entry
            continue
        mode, oid = source
        entry.git_oid = oid
        if mode == "120000":
            entry.status = "unreadable"
            entry.detail = "symlink"
            _add_entry_diagnostic(
                diagnostics,
                "symlink_entry",
                f"symbolic link is not followed: {path}",
                "info",
                path,
                side,
            )
            entries[path] = entry
            continue
        if mode == "160000":
            entry.status = "unreadable"
            entry.detail = "gitlink"
            _add_entry_diagnostic(
                diagnostics,
                "gitlink_skipped",
                f"submodule entry is not analysed: {path}",
                "info",
                path,
                side,
            )
            entries[path] = entry
            continue
        blob = blobs.get(oid)
        if blob is None:
            entry.status = "unreadable"
            entry.detail = "object_missing"
            _add_entry_diagnostic(
                diagnostics,
                "object_missing",
                f"git object for {path} is not available",
                "warning",
                path,
                side,
                oid=oid,
            )
            entries[path] = entry
            continue
        entry.size = blob.size
        entry.content_sha256 = blob.sha256
        if blob.size > max_file_bytes:
            entry.status = "too_large"
            entries[path] = entry
            continue
        entry.status = "present"
        if entry.is_python:
            data = blob.data if blob.data is not None else b""
            try:
                text = _decode_python(data)
            except (SyntaxError, LookupError, UnicodeError) as exc:
                entry.status = "decode_error"
                entry.detail = f"{type(exc).__name__}: {exc}"
            else:
                collector.add(path, text, blob.size)
        entries[path] = entry
    collector.finish()
    return SnapshotSide(
        side=side,
        entries=entries,
        contents=dict(collector.contents),
        manifest_digest=_manifest_digest(entries),
    )


def _build_worktree_side(
    root: Path,
    side: str,
    all_paths: Sequence[str],
    worktree_candidates: set[str],
    gitlinks: dict[str, str],
    config: Config,
    diagnostics: list[Diagnostic],
    before: SnapshotSide,
    index_entries: dict[str, tuple[str, str]],
) -> SnapshotSide:
    max_file_bytes = config.analysis.max_file_bytes
    collector = _ContentCollector(side, config, diagnostics)
    entries: dict[str, SnapshotEntry] = {}
    eol_matches: dict[str, bool] = {}
    for path in sorted(all_paths):
        entry = _new_entry(path, side)
        if path not in worktree_candidates:
            entry.status = "missing"
            entries[path] = entry
            continue
        if path in gitlinks:
            entry.status = "unreadable"
            entry.detail = "gitlink"
            entry.git_oid = gitlinks[path]
            _add_entry_diagnostic(
                diagnostics,
                "gitlink_skipped",
                f"submodule entry is not analysed: {path}",
                "info",
                path,
                side,
            )
            entries[path] = entry
            continue
        target = root.joinpath(*path.split("/"))
        exists, is_link = _path_is_regular(target)
        if not exists:
            entry.status = "missing"
            entries[path] = entry
            continue
        if is_link:
            entry.status = "unreadable"
            entry.detail = "symlink"
            _add_entry_diagnostic(
                diagnostics,
                "symlink_entry",
                f"symbolic link is not followed: {path}",
                "info",
                path,
                side,
            )
            entries[path] = entry
            continue
        try:
            target = _worktree_path(root, path)
            stat_result = os.lstat(target)
        except SnapshotError:
            raise
        except OSError:
            entry.status = "unreadable"
            entry.detail = "stat_error"
            entries[path] = entry
            continue
        if not stat.S_ISREG(stat_result.st_mode):
            entry.status = "unreadable"
            entry.detail = "not_regular_file"
            entries[path] = entry
            continue
        retain = entry.is_python and stat_result.st_size <= max_file_bytes
        try:
            working_file = _read_worktree_regular(target, max_file_bytes, retain)
        except OSError:
            entry.status = "unreadable"
            entry.detail = "read_error"
            entries[path] = entry
            continue
        entry.size = working_file.size
        entry.content_sha256 = working_file.sha256
        previous = before.entries.get(path)
        if working_file.lf_sha256 and previous and previous.content_sha256 == working_file.lf_sha256:
            eol_matches[path] = working_file.text_for_auto_eol
        if working_file.size > max_file_bytes:
            entry.status = "too_large"
            entries[path] = entry
            continue
        entry.status = "present"
        if entry.is_python:
            payload = working_file.data if working_file.data is not None else b""
            try:
                text = _decode_python(payload)
            except (SyntaxError, LookupError, UnicodeError) as exc:
                entry.status = "decode_error"
                entry.detail = f"{type(exc).__name__}: {exc}"
            else:
                collector.add(path, text, working_file.size)
        entries[path] = entry
    collector.finish()
    return SnapshotSide(
        side=side,
        entries=entries,
        contents=dict(collector.contents),
        manifest_digest=_manifest_digest(entries),
        eol_equivalent_paths=_worktree_eol_matches(root, eol_matches, before, index_entries),
    )


# ---------------------------------------------------------------------------
# drift detection
# ---------------------------------------------------------------------------


def _signature_stat(root: Path, path: str) -> tuple[object, ...]:
    target = root.joinpath(*path.split("/"))
    try:
        resolved = target.resolve()
    except OSError:  # pragma: no cover - defensive
        return ("unresolvable",)
    if not _is_within(resolved, root):
        return ("escape",)
    try:
        st = os.lstat(target)
    except (FileNotFoundError, NotADirectoryError):
        return ("missing",)
    except OSError:
        return ("stat_error",)
    return ("stat", st.st_mode, st.st_size, st.st_mtime_ns)


def _worktree_signature(root: Path, include_untracked: bool) -> tuple[object, ...]:
    """Cheap fingerprint of everything the worktree endpoint depends on."""

    head = _head_oid(root)
    index = _read_index(root)
    untracked = tuple(_untracked_paths(root)) if include_untracked else ()
    paths = sorted({record[0] for record in index.records} | set(untracked))
    stats = tuple((path, _signature_stat(root, path)) for path in paths)
    return (
        head,
        tuple(sorted(index.records)),
        untracked,
        stats,
    )


# ---------------------------------------------------------------------------
# capture
# ---------------------------------------------------------------------------


def _include_untracked(config: Config, mode: str) -> bool:
    override = config.git.include_untracked
    if override is not None:
        return bool(override)
    return mode == MODE_WORKTREE_NET


def _short(oid: str) -> str:
    return oid[:7]


def _capture_attempt(
    root: Path,
    config: Config,
    mode: str,
    base_ref: str | None,
    commit_ref: str | None = None,
    range_spec: str | None = None,
    parent_index: int | None = None,
) -> tuple[Snapshot, bool]:
    """Capture one attempt.  Returns ``(snapshot, drifted)``."""

    head_oid, branch, detached = _resolve_refs(root)
    diagnostics: list[Diagnostic] = []
    uses_worktree = mode in (MODE_WORKTREE_NET, MODE_WORKING_TREE)
    if uses_worktree:
        _ensure_no_sparse_checkout(root)
    include_untracked = _include_untracked(config, mode) if uses_worktree else False

    signature_before: tuple[object, ...] | None = None
    if uses_worktree:
        signature_before = _worktree_signature(root, include_untracked)
        if signature_before[0] != head_oid:
            # HEAD moved between resolution and the fingerprint; force a retry.
            signature_before = ("stale-head", signature_before)

    before_present: dict[str, tuple[str, str]] = {}
    after_present: dict[str, tuple[str, str]] = {}
    before_candidates: set[str] = set()
    after_candidates: set[str] = set()
    worktree_after: set[str] | None = None
    worktree_gitlinks: dict[str, str] = {}

    if mode == MODE_BASE:
        if head_oid is None:
            raise SnapshotError("base mode requires a repository with at least one commit")
        assert base_ref is not None
        merge_base = _merge_base_oid(root, base_ref, head_oid)
        before_present = _tree_blobs(root, merge_base)
        after_present = _tree_blobs(root, head_oid)
        before_candidates = set(before_present)
        after_candidates = set(after_present)
        endpoint_before = f"merge-base({base_ref}, HEAD) ({_short(merge_base)})"
        endpoint_after = f"HEAD ({_short(head_oid)})"
    elif mode == MODE_COMMIT:
        # Commit endpoints read Git objects only: the index and the working
        # tree are never consulted, so a dirty checkout cannot change them.
        assert commit_ref is not None
        commit_oid = _resolve_commit_ref(root, commit_ref, "commit ref not found")
        parents = _commit_parents(root, commit_oid, commit_ref)
        parent_number, parent_oid = _select_commit_parent(
            commit_ref, commit_oid, parents, parent_index
        )
        if parent_number == 0:
            endpoint_before = "empty (root commit)"
        else:
            before_present = _tree_blobs(root, parent_oid)
            before_candidates = set(before_present)
            # ``<REV> parent N (<short parent OID>)`` keeps the chosen base
            # explicit and starts with the revision label (see CONTRACTS-P1).
            endpoint_before = (
                f"{commit_ref} parent {parent_number} ({_short(parent_oid)})"
            )
        after_present = _tree_blobs(root, commit_oid)
        after_candidates = set(after_present)
        endpoint_after = f"{commit_ref} ({_short(commit_oid)})"
    elif mode == MODE_RANGE:
        # Range endpoints are fixed commit OIDs; no workspace state is read.
        assert range_spec is not None
        left_ref, right_ref, three_dot = _parse_range_spec(range_spec)
        left_oid = _resolve_commit_ref(root, left_ref, "range endpoint not found")
        right_oid = _resolve_commit_ref(root, right_ref, "range endpoint not found")
        if three_dot:
            before_oid = _merge_base_between(root, left_ref, left_oid, right_ref, right_oid)
            endpoint_before = (
                f"range: merge-base({left_ref}, {right_ref}) ({_short(before_oid)})"
            )
        else:
            before_oid = left_oid
            endpoint_before = f"range: {left_ref} ({_short(left_oid)})"
        before_present = _tree_blobs(root, before_oid)
        after_present = _tree_blobs(root, right_oid)
        before_candidates = set(before_present)
        after_candidates = set(after_present)
        endpoint_after = f"range: {right_ref} ({_short(right_oid)})"
    elif mode == MODE_STAGED:
        index = _read_index(root)
        if index.unmerged:
            raise SnapshotError(
                "unmerged index (unresolved conflicts) cannot be used as a staged endpoint"
            )
        intent_to_add = _intent_to_add_paths(root)
        if head_oid is not None:
            before_present = _tree_blobs(root, head_oid)
        after_present = {
            path: value for path, value in index.entries.items() if path not in intent_to_add
        }
        before_candidates = set(before_present)
        after_candidates = set(index.entries)
        endpoint_before = f"HEAD ({_short(head_oid)})" if head_oid else "empty"
        endpoint_after = "index"
    elif mode == MODE_WORKING_TREE:
        index = _read_index(root)
        if index.unmerged:
            raise SnapshotError(
                "unmerged index (unresolved conflicts) cannot be used as a working-tree endpoint"
            )
        intent_to_add = _intent_to_add_paths(root)
        before_present = {
            path: value for path, value in index.entries.items() if path not in intent_to_add
        }
        before_candidates = set(index.entries)
        untracked = _untracked_paths(root) if include_untracked else []
        worktree_after = set(index.entries) | set(untracked)
        after_candidates = set(worktree_after)
        worktree_gitlinks = {
            path: oid for path, (mode_value, oid) in index.entries.items() if mode_value == "160000"
        }
        endpoint_before = "index"
        endpoint_after = "worktree"
    else:  # MODE_WORKTREE_NET
        if head_oid is not None:
            before_present = _tree_blobs(root, head_oid)
        before_candidates = set(before_present)
        index = _read_index(root)
        untracked = _untracked_paths(root) if include_untracked else []
        # An unmerged path has no stage 0 entry; the working tree file still
        # exists (with conflict markers), so every index record path is a
        # worktree candidate in this mode.
        index_paths = {record[0] for record in index.records}
        worktree_after = index_paths | set(untracked)
        after_candidates = set(worktree_after)
        worktree_gitlinks = {
            path: oid for path, (mode_value, oid) in index.entries.items() if mode_value == "160000"
        }
        endpoint_before = f"HEAD ({_short(head_oid)})" if head_oid else "empty"
        endpoint_after = "worktree"

    union = before_candidates | after_candidates
    selected = sorted(path for path in union if file_selected(path, config.files))
    selected_set = set(selected)

    before_side = _build_blob_side(
        root, SIDE_BEFORE, selected, before_present, config, diagnostics
    )
    if worktree_after is None:
        after_side = _build_blob_side(
            root, SIDE_AFTER, selected, after_present, config, diagnostics
        )
    else:
        after_side = _build_worktree_side(
            root,
            SIDE_AFTER,
            selected,
            worktree_after & selected_set,
            worktree_gitlinks,
            config,
            diagnostics,
            before_side,
            index.entries,
        )

    drifted = False
    if uses_worktree:
        signature_after = _worktree_signature(root, include_untracked)
        drifted = signature_after != signature_before

    snapshot = Snapshot(
        mode=mode,
        repo_root=str(root),
        repo_id=repo_id_for(root),
        display_name=repo_display_name(root),
        branch=branch,
        detached=detached,
        endpoint_before=endpoint_before,
        endpoint_after=endpoint_after,
        before=before_side,
        after=after_side,
        config_digest=config.digest(),
        diagnostics=diagnostics,
    )
    return snapshot, drifted


def capture(
    repo_root: Path,
    config: Config,
    mode: str | None = None,
    base_ref: str | None = None,
    *,
    commit_ref: str | None = None,
    range_spec: str | None = None,
    parent_index: int | None = None,
) -> Snapshot:
    """Capture one comparison snapshot from a Git working tree.

    Raises :class:`SnapshotError` for repository/ref/index/setup problems.
    A concurrent working-tree change is retried once; if it persists the
    snapshot is returned with an ``snapshot_changed`` error diagnostic.

    ``commit_ref``/``parent_index`` select ``MODE_COMMIT`` (a parent commit
    tree against the commit tree) and ``range_spec`` selects ``MODE_RANGE``
    (``A..B`` or ``A...B``); both read committed Git objects only.  The P0
    call forms keep working unchanged.
    """

    root = _resolve_repo_root(Path(repo_root))
    chosen_mode = mode if mode is not None else config.git.mode
    if chosen_mode not in ALL_MODES:
        raise SnapshotError(
            f"unsupported git mode: {chosen_mode!r} (expected one of {', '.join(ALL_MODES)})"
        )
    base_name: str | None = None
    commit_name: str | None = None
    range_name: str | None = None
    if chosen_mode == MODE_BASE:
        base_name = base_ref or config.git.base
        if not base_name:
            raise SnapshotError("base mode requires a base ref")
    elif chosen_mode == MODE_COMMIT:
        if commit_ref is None or not str(commit_ref).strip():
            raise SnapshotError("commit mode requires a commit ref")
        commit_name = str(commit_ref).strip()
    elif chosen_mode == MODE_RANGE:
        if range_spec is None or not str(range_spec).strip():
            raise SnapshotError("range mode requires a range spec (A..B or A...B)")
        range_name = str(range_spec).strip()
    if parent_index is not None and (
        isinstance(parent_index, bool) or not isinstance(parent_index, int)
    ):
        raise SnapshotError("parent index must be an integer (1 based)")
    snapshot: Snapshot | None = None
    for _attempt in range(2):
        snapshot, drifted = _capture_attempt(
            root,
            config,
            chosen_mode,
            base_name,
            commit_name,
            range_name,
            parent_index,
        )
        if not drifted:
            return snapshot
    assert snapshot is not None
    snapshot.diagnostics.append(
        diag(
            "snapshot_changed",
            "the working tree changed while the snapshot was captured; the returned content "
            "may be inconsistent",
            severity="error",
            details={"attempts": 2},
        )
    )
    return snapshot
