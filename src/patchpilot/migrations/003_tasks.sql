-- PatchPilot M1 database schema migration, version 2 -> 3.
--
-- Adds the local analysis task queue used by the Web dashboard / worker.
-- Applied by ``Storage.initialize()`` after migration 002 on databases that
-- report ``PRAGMA user_version = 2``; the ``user_version`` gate makes sure the
-- statements below run exactly once per database, so ``ALTER TABLE ... ADD
-- COLUMN`` needs no ``IF NOT EXISTS`` guard.
--
-- ``storage.py`` stamps the new ``user_version`` after this script succeeds, so
-- do not change it here.

CREATE TABLE analysis_tasks (
    task_id              TEXT PRIMARY KEY,
    repo_id              TEXT NOT NULL,
    repo_root            TEXT NOT NULL,
    status               TEXT NOT NULL,
    mode                 TEXT NOT NULL,
    base_ref             TEXT,
    commit_ref           TEXT,
    range_spec           TEXT,
    parent_index         INTEGER,
    judge                INTEGER NOT NULL DEFAULT 0,
    include_untracked    INTEGER NOT NULL DEFAULT 0,
    request_json         TEXT NOT NULL DEFAULT '{}',
    config_digest        TEXT NOT NULL DEFAULT '',
    config_json          TEXT NOT NULL DEFAULT '{}',
    stages_json          TEXT NOT NULL DEFAULT '[]',
    diagnostics_json     TEXT NOT NULL DEFAULT '[]',
    error_code           TEXT,
    task_key             TEXT,
    run_id               TEXT
                         REFERENCES analysis_runs (run_id) ON DELETE SET NULL,
    worker_token         TEXT,
    worker_heartbeat_at  TEXT,
    created_at           TEXT NOT NULL,
    started_at           TEXT,
    finished_at          TEXT
);

CREATE INDEX idx_analysis_tasks_repo_status
    ON analysis_tasks (repo_id, status, created_at);

-- Idempotency key: only non-empty keys are unique per repository.
CREATE UNIQUE INDEX idx_analysis_tasks_repo_key
    ON analysis_tasks (repo_id, task_key)
    WHERE task_key IS NOT NULL;

-- A repository may run at most one task at a time; enforced by the database so
-- two workers can never both win a claim.
CREATE UNIQUE INDEX idx_analysis_tasks_single_running
    ON analysis_tasks (repo_id)
    WHERE status = 'running';

CREATE INDEX idx_analysis_tasks_run ON analysis_tasks (run_id);

ALTER TABLE analysis_runs
    ADD COLUMN task_id TEXT NULL REFERENCES analysis_tasks (task_id);

CREATE INDEX idx_analysis_runs_task ON analysis_runs (task_id);
