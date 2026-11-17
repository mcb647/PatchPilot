"""PatchPilot command line interface.

Exit codes are part of the contract:

* 0 -- analysis completed (including "no changes" / "no candidates")
* 1 -- runtime failure
* 2 -- invalid arguments or configuration
* 3 -- partial results were saved and can be inspected
* 4 -- requested run does not exist
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__, analyze as analyze_mod, config as config_mod, models, reports, storage
from .config import ConfigError
from .repo import RepoError, resolve_repo_root

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_PARTIAL = 3
EXIT_NOT_FOUND = 4

PROG = "patchpilot"


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Trace the static impact of Python changes and keep an auditable "
            "local history of every analysis."
        ),
        epilog=(
            "examples:\n"
            "  patchpilot init\n"
            "  patchpilot analyze\n"
            "  patchpilot analyze --staged --format json\n"
            "  patchpilot analyze --base main\n"
            "  patchpilot history --limit 10\n"
            "  patchpilot show <run-id> --format markdown\n"
            "  patchpilot web\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--repo",
        metavar="PATH",
        default=None,
        help="repository (or a directory inside it); defaults to the current directory",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    repo_parent = argparse.ArgumentParser(add_help=False)
    repo_parent.add_argument(
        "--repo",
        metavar="PATH",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )

    init_parser = subparsers.add_parser(
        "init", parents=[repo_parent], help="write a project configuration template"
    )
    init_parser.set_defaults(handler=_cmd_init)

    analyze_parser = subparsers.add_parser(
        "analyze",
        parents=[repo_parent],
        help="compare two endpoints, trace impact and store the run",
    )
    mode_group = analyze_parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--staged",
        action="store_true",
        help="compare HEAD -> index (staged changes only)",
    )
    mode_group.add_argument(
        "--working-tree",
        action="store_true",
        help="compare index -> working tree",
    )
    mode_group.add_argument(
        "--base",
        metavar="REF",
        default=None,
        help="compare merge-base(REF, HEAD) -> HEAD (committed branch changes)",
    )
    mode_group.add_argument(
        "--commit",
        metavar="REV",
        default=None,
        help="compare the parent of REV -> REV (use --parent N for merge commits)",
    )
    mode_group.add_argument(
        "--range",
        metavar="A..B",
        default=None,
        help="compare A..B or merge-base(A,B)..B when written as A...B",
    )
    analyze_parser.add_argument(
        "--parent",
        type=int,
        default=None,
        metavar="N",
        help="1-based parent number for --commit on a merge commit",
    )
    analyze_parser.add_argument(
        "--judge",
        action="store_true",
        help="explicitly allow this run to ask the configured Judge adapters",
    )
    analyze_parser.add_argument(
        "--coverage",
        metavar="PATH",
        default=None,
        help="import a Coverage JSON report and attach matching test context evidence",
    )
    analyze_parser.add_argument(
        "--include-untracked",
        action="store_true",
        help="with --working-tree, also include untracked (non-ignored) files",
    )
    analyze_parser.add_argument(
        "--format",
        choices=("summary", "json", "markdown"),
        default="summary",
        help="stdout format (default: summary)",
    )
    analyze_parser.set_defaults(handler=_cmd_analyze)

    history_parser = subparsers.add_parser(
        "history", parents=[repo_parent], help="list stored runs for this repository"
    )
    history_parser.add_argument(
        "action",
        nargs="?",
        choices=("list", "prune"),
        default="list",
        help="list runs (default) or prune old runs",
    )
    history_parser.add_argument(
        "--limit", type=int, default=20, help="number of runs to show (1-100)"
    )
    history_parser.add_argument(
        "--offset", type=int, default=0, help="pagination offset (default: 0)"
    )
    history_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="with prune: show what would be deleted without changing the database",
    )
    history_parser.add_argument(
        "--apply",
        action="store_true",
        help="with prune: actually delete the selected runs",
    )
    history_parser.add_argument(
        "--retain-days",
        type=int,
        default=None,
        help="with prune: keep runs newer than this many days (default: config)",
    )
    history_parser.add_argument(
        "--max-runs",
        type=int,
        default=None,
        help="with prune: keep at most this many runs (default: config)",
    )
    history_parser.add_argument(
        "--format",
        choices=("summary", "json", "markdown"),
        default="summary",
        help="stdout format (default: summary)",
    )
    history_parser.set_defaults(handler=_cmd_history)

    show_parser = subparsers.add_parser(
        "show", parents=[repo_parent], help="read a stored run from the local database"
    )
    show_parser.add_argument("run_id", help="run identifier reported by analyze/history")
    show_parser.add_argument(
        "--format",
        choices=("summary", "json", "markdown"),
        default="summary",
        help="stdout format (default: summary)",
    )
    show_parser.set_defaults(handler=_cmd_show)

    web_parser = subparsers.add_parser(
        "web", parents=[repo_parent], help="serve the read-only local dashboard"
    )
    web_parser.add_argument("--host", default=None, help="loopback address (default: 127.0.0.1)")
    web_parser.add_argument("--port", type=int, default=None, help="port (default: 8765)")
    web_parser.set_defaults(handler=_cmd_web)

    return parser


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    _configure_streams()
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.handler(args) or 0)
    except ConfigError as exc:
        _error(str(exc))
        return EXIT_USAGE
    except RepoError as exc:
        _error(str(exc))
        return EXIT_USAGE
    except storage.StorageError as exc:
        _error(f"local history is unavailable: {exc}")
        return EXIT_FAILED
    except KeyboardInterrupt:  # pragma: no cover - interactive
        return EXIT_FAILED


def _configure_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):  # pragma: no cover - unusual streams
                pass


def _error(message: str) -> None:
    print(f"{PROG}: error: {message}", file=sys.stderr)


def _hint(message: str) -> None:
    print(message, file=sys.stderr)


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------


def _repo_root(args: argparse.Namespace) -> Path:
    start = Path(getattr(args, "repo", None) or Path.cwd())
    return resolve_repo_root(start)


def _load_config(repo_root: Path):
    return config_mod.load_config(repo_root)


def _db_path(config, repo_root: Path) -> Path:
    return config_mod.resolve_db_path(config, models.repo_id_for(repo_root))


def _open_store(config, repo_root: Path, read_only: bool) -> storage.Storage:
    db_path = _db_path(config, repo_root)
    store = storage.Storage(
        db_path,
        read_only=read_only,
        evidence_mode=config.storage.evidence_mode,
        max_evidence_bytes_per_run=config.storage.max_evidence_bytes_per_run,
    )
    if not read_only:
        store.initialize()
    return store


def _write_stdout(text: str) -> None:
    if not text.endswith("\n"):
        text += "\n"
    sys.stdout.write(text)
    sys.stdout.flush()


def _write_json(data: dict) -> None:
    _write_stdout(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False))


# --------------------------------------------------------------------------
# init
# --------------------------------------------------------------------------


def _cmd_init(args: argparse.Namespace) -> int:
    repo_root = _repo_root(args)
    path, created = config_mod.init_config(repo_root)
    if created:
        _write_stdout(f"Created {path}")
        _write_stdout("Edit it to pin the comparison mode, file rules or storage path.")
    else:
        _write_stdout(f"Configuration already exists at {path} (left unchanged).")
    return EXIT_OK


# --------------------------------------------------------------------------
# analyze
# --------------------------------------------------------------------------


def _cmd_analyze(args: argparse.Namespace) -> int:
    repo_root = _repo_root(args)
    config, config_path = _load_config(repo_root)
    if config_path is None:
        _hint(f"No project configuration found at {config_mod.config_file_path(repo_root)}; using built-in defaults.")

    mode: str | None = None
    base_ref: str | None = None
    commit_ref: str | None = None
    range_spec: str | None = None
    if args.staged:
        mode = models.MODE_STAGED
    elif args.working_tree:
        mode = models.MODE_WORKING_TREE
        if args.include_untracked:
            config.git.include_untracked = True
    elif args.base is not None:
        mode = models.MODE_BASE
        base_ref = args.base
    elif args.commit is not None:
        mode = models.MODE_COMMIT
        commit_ref = args.commit
    elif args.range is not None:
        mode = models.MODE_RANGE
        range_spec = args.range
    if args.include_untracked and mode != models.MODE_WORKING_TREE:
        raise ConfigError("--include-untracked is only valid together with --working-tree")
    if args.parent is not None:
        if mode != models.MODE_COMMIT:
            raise ConfigError("--parent is only valid together with --commit")
        if args.parent < 1:
            raise ConfigError("--parent must be a positive 1-based parent number")

    def progress(message: str) -> None:
        _hint(message)

    coverage = None
    if args.coverage:
        try:
            from . import coverage_data
        except Exception as exc:  # noqa: BLE001 - optional P1 capability
            raise ConfigError(
                f"--coverage is unavailable in this build: {type(exc).__name__}: {exc}"
            ) from exc
        try:
            coverage = coverage_data.load_coverage(
                Path(args.coverage), repo_root=repo_root
            )
        except coverage_data.CoverageError as exc:
            raise ConfigError(f"--coverage: {exc}") from exc

    outcome = analyze_mod.run_analysis(
        repo_root,
        config,
        mode=mode,
        base_ref=base_ref,
        commit_ref=commit_ref,
        range_spec=range_spec,
        parent_index=args.parent,
        judge=bool(args.judge),
        coverage=coverage,
        progress=progress,
    )

    if outcome.error:
        _hint(f"analysis did not complete cleanly: {outcome.error}")

    if args.format == "json":
        if outcome.detail is not None:
            _write_json(reports.build_json_report(outcome.detail))
        else:
            _write_json(
                {
                    "schema_version": models.SCHEMA_VERSION,
                    "error": outcome.error or "analysis failed",
                    "run": outcome.run.to_dict(),
                }
            )
    elif args.format == "markdown":
        if outcome.detail is not None:
            _write_stdout(reports.render_markdown(outcome.detail))
        else:
            _write_stdout(
                f"# PatchPilot Run {outcome.run.run_id}\n\n"
                f"Analysis failed: {outcome.error or 'unknown error'}\n"
            )
    else:
        if outcome.detail is not None:
            _write_stdout(reports.render_summary(outcome.detail))
        else:
            _write_stdout(
                f"Run {outcome.run.run_id} failed: {outcome.error or 'unknown error'}"
            )
    return outcome.exit_code


# --------------------------------------------------------------------------
# history
# --------------------------------------------------------------------------


def _cmd_history(args: argparse.Namespace) -> int:
    if not 1 <= args.limit <= 100:
        raise ConfigError("--limit must be between 1 and 100")
    if args.offset < 0:
        raise ConfigError("--offset must not be negative")
    repo_root = _repo_root(args)
    config, _ = _load_config(repo_root)
    repo_id = models.repo_id_for(repo_root)
    db_path = _db_path(config, repo_root)

    if getattr(args, "action", "list") == "prune":
        return _cmd_history_prune(args, config, db_path, repo_id)

    summaries: list = []
    total = 0
    if db_path.exists():
        store = storage.Storage(db_path, read_only=True)
        try:
            summaries, total = store.list_runs(repo_id, limit=args.limit, offset=args.offset)
        finally:
            store.close()

    if args.format == "json":
        _write_json(reports.build_history_json(summaries, total, args.limit, args.offset))
    elif args.format == "markdown":
        _write_stdout(reports.render_history_markdown(summaries, total, args.limit, args.offset))
    else:
        _write_stdout(reports.render_history_summary(summaries, total, args.limit, args.offset))
    return EXIT_OK


def _cmd_history_prune(
    args: argparse.Namespace,
    config,
    db_path: Path,
    repo_id: str,
) -> int:
    if bool(args.dry_run) == bool(getattr(args, "apply", False)):
        raise ConfigError("history prune requires exactly one of --dry-run or --apply")
    retain_days = args.retain_days if args.retain_days is not None else config.storage.retain_days
    max_runs = args.max_runs if args.max_runs is not None else config.storage.max_runs
    if retain_days < 0 or max_runs < 0:
        raise ConfigError("--retain-days and --max-runs must not be negative")
    dry_run = bool(args.dry_run)
    if not db_path.exists():
        if args.format == "json":
            _write_json(
                {
                    "schema_version": models.SCHEMA_VERSION,
                    "dry_run": dry_run,
                    "total_before": 0,
                    "retained": 0,
                    "to_delete": [],
                    "deleted": [],
                    "running_skipped": [],
                }
            )
        else:
            _write_stdout("No history database exists for this repository; nothing to prune.")
        return EXIT_OK

    store = storage.Storage(db_path, read_only=dry_run)
    try:
        if not dry_run:
            store.initialize()
        report = store.prune_runs(
            repo_id=repo_id, retain_days=retain_days, max_runs=max_runs, dry_run=dry_run
        )
    finally:
        store.close()

    if args.format == "json":
        _write_json(
            {
                "schema_version": models.SCHEMA_VERSION,
                "dry_run": report.dry_run,
                "total_before": report.total_before,
                "retained": report.retained,
                "to_delete": list(report.to_delete),
                "deleted": list(report.deleted),
                "running_skipped": list(report.running_skipped),
            }
        )
    elif args.format == "markdown":
        lines = [
            "# PatchPilot history prune",
            "",
            f"- dry run: {'yes' if report.dry_run else 'no'}",
            f"- runs before: {report.total_before}",
            f"- retained: {report.retained}",
            f"- would delete: {len(report.to_delete)}",
            f"- deleted: {len(report.deleted)}",
            f"- running skipped: {len(report.running_skipped)}",
        ]
        _write_stdout("\n".join(lines) + "\n")
    else:
        verb = "Would delete" if dry_run else "Deleted"
        _write_stdout(
            f"History prune ({'dry run' if dry_run else 'apply'}): "
            f"{report.total_before} run(s) -> {report.retained} kept, "
            f"{verb.lower()} {len(report.to_delete) if dry_run else len(report.deleted)}."
        )
        for run_id in report.to_delete if dry_run else report.deleted:
            _write_stdout(f"  {run_id}")
        if report.running_skipped:
            _hint(f"kept {len(report.running_skipped)} interrupted running run(s)")
    return EXIT_OK


# --------------------------------------------------------------------------
# show
# --------------------------------------------------------------------------


def _cmd_show(args: argparse.Namespace) -> int:
    run_id = args.run_id
    if not models.is_valid_run_id(run_id):
        raise ConfigError(f"invalid run id: {run_id!r}")
    repo_root = _repo_root(args)
    config, _ = _load_config(repo_root)
    db_path = _db_path(config, repo_root)
    if not db_path.exists():
        _error(f"run {run_id} was not found (no local history database at {db_path})")
        return EXIT_NOT_FOUND

    store = storage.Storage(db_path, read_only=True)
    try:
        try:
            detail = store.load_run(run_id)
        except storage.StorageError:
            _error(f"run {run_id} was not found")
            return EXIT_NOT_FOUND
        if detail.run.repo_id != models.repo_id_for(repo_root):
            _error(f"run {run_id} was not found")
            return EXIT_NOT_FOUND
    finally:
        store.close()

    if args.format == "json":
        _write_json(reports.build_json_report(detail))
    elif args.format == "markdown":
        _write_stdout(reports.render_markdown(detail))
    else:
        _write_stdout(reports.render_summary(detail))
    return EXIT_OK


# --------------------------------------------------------------------------
# web
# --------------------------------------------------------------------------


def _cmd_web(args: argparse.Namespace) -> int:
    repo_root = _repo_root(args)
    config, _ = _load_config(repo_root)
    host = args.host or config.web.host
    port = args.port if args.port is not None else config.web.port
    if not config_mod.is_loopback_host(host):
        raise ConfigError("web host must be a loopback address (127.0.0.1, localhost or ::1)")
    if not 1 <= port <= 65535:
        raise ConfigError("web port must be between 1 and 65535")

    repo_id = models.repo_id_for(repo_root)
    db_path = _db_path(config, repo_root)

    from .web.app import create_app  # imported lazily to keep the CLI snappy

    app = create_app(
        db_path,
        repo_id,
        repo_root=repo_root,
        enable_worker=True,
        listen_port=port,
    )
    display_host = "[::1]" if host in ("::1", "[::1]") else host
    url = f"http://{display_host}:{port}/"
    _hint(f"PatchPilot dashboard: {url}")
    _hint(f"History database: {db_path}")
    try:
        import uvicorn

        uvicorn.run(app, host=host.strip("[]"), port=port, log_level="info")
    except OSError as exc:
        _error(f"could not start the dashboard on {host}:{port}: {exc}")
        return EXIT_FAILED
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - module entry
    sys.exit(main())
