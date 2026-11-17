# PatchPilot

**English** | [简体中文](README.zh-CN.md)

**Trace the impact of Python changes.**

PatchPilot helps developers and AI coding agents see what changed, which code may depend on it, and which tests are worth running. It links each finding to the relevant file and line, and saves the report in a local dashboard.

## Quick start

Requires Python 3.11+ and Git. Install from the PatchPilot checkout.

```sh
python -m pip install .
```

In the Git repository you want to analyze, run these commands.

```sh
patchpilot analyze
patchpilot web
```

Open [the local dashboard](http://127.0.0.1:8765/) to see the report, browse saved analyses, or start another analysis. Select a relationship in the impact graph to see the call site. You can change project settings from the dashboard or use `patchpilot init` to create a configuration file.

## Choose what to compare

| What you want to inspect | Command |
| --- | --- |
| All local changes since `HEAD` | `patchpilot analyze` |
| Only staged changes | `patchpilot analyze --staged` |
| Only unstaged changes | `patchpilot analyze --working-tree` |
| Changes committed on your branch since it diverged from `main` | `patchpilot analyze --base main` |
| The latest commit | `patchpilot analyze --commit HEAD` |
| The difference between two commits or refs | `patchpilot analyze --range A..B` |

## Read the results

- **File changes** show the lines, functions, and classes that changed.
- **Impact clues** link changed code to callers and other dependencies. A static relationship tells you where to look. Dynamic Python calls can leave gaps in the report.
- **Suggested tests** help you choose what to run. Start with tests that reach a change through a known call path. Suggestions based on names or imports are weaker clues.

PatchPilot leaves test execution to you or your agent. Use test results to confirm whether behavior changed.

## Use with a coding agent

Install the CLI, then add the [PatchPilot Skill](skills/patchpilot/SKILL.md) using your agent's skill installation instructions. After a Python edit, ask the agent to check what the change might affect and which tests to run.

Automation can read JSON, and saved reports can be exported as Markdown.

```sh
patchpilot analyze --format json
patchpilot history
patchpilot show RUN_ID --format markdown
```

## Local data

The dashboard listens on your machine, and reports are stored in local SQLite. Reports can contain diff excerpts. Set `storage.evidence_mode` to `metadata_only` to omit diff text from saved analysis records.

Static analysis works without a model or API key. If you configure a Judge provider and explicitly enable it for a run, selected code evidence may be sent to that provider.

## License

[MIT](LICENSE)
