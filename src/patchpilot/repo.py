"""Repository root resolution shared by the CLI and the web dashboard."""

from __future__ import annotations

import subprocess
from pathlib import Path


class RepoError(Exception):
    """Raised when a directory is not inside a usable Git working tree."""


def run_git(repo_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run a Git command without a shell, with a clean, prompt-free env."""

    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        env=_git_env(),
    )


def _git_env() -> dict[str, str]:
    import os

    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env.pop("GIT_DIR", None)
    env.pop("GIT_WORK_TREE", None)
    return env


def resolve_repo_root(start: Path | str) -> Path:
    """Resolve ``start`` to the top level of its Git working tree."""

    path = Path(start).expanduser()
    try:
        path = path.resolve()
    except OSError as exc:
        raise RepoError(f"cannot resolve path {start!r}: {exc}") from exc
    if not path.exists():
        raise RepoError(f"path does not exist: {path}")
    if not path.is_dir():
        raise RepoError(f"not a directory: {path}")
    result = run_git(path, "rev-parse", "--show-toplevel")
    top = (result.stdout or "").strip()
    if result.returncode != 0 or not top:
        raise RepoError(
            f"{path} is not inside a Git repository "
            "(run `git init` first or pass --repo)"
        )
    root = Path(top)
    try:
        return root.resolve()
    except OSError as exc:  # pragma: no cover - defensive
        raise RepoError(f"cannot resolve repository root: {exc}") from exc
