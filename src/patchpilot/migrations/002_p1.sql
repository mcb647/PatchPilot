-- PatchPilot P1 database schema migration, version 1 -> 2.
--
-- Applied by ``Storage.initialize()`` after migration 001 on databases that
-- still report ``PRAGMA user_version = 1``.  SQLite has no
-- ``ALTER TABLE ... ADD COLUMN IF NOT EXISTS``; the ``user_version`` gate makes
-- sure every statement below runs exactly once per database.
--
-- ``storage.py`` stamps the new ``user_version`` after this script succeeds, so
-- do not change it here.

ALTER TABLE symbol_changes ADD COLUMN details_json TEXT NOT NULL DEFAULT '{}';

CREATE TABLE judge_attempts (
    run_id                  TEXT NOT NULL
                            REFERENCES analysis_runs (run_id) ON DELETE CASCADE,
    candidate_id            TEXT NOT NULL,
    attempt_no              INTEGER NOT NULL,
    attempt_id              TEXT NOT NULL,
    adapter                 TEXT NOT NULL,
    model                   TEXT,
    started_at              TEXT NOT NULL,
    duration_ms             INTEGER NOT NULL DEFAULT 0,
    context_digest          TEXT NOT NULL DEFAULT '',
    context_bytes           INTEGER NOT NULL DEFAULT 0,
    context_tokens_estimate INTEGER NOT NULL DEFAULT 0,
    cache_hit               INTEGER NOT NULL DEFAULT 0,
    valid                   INTEGER NOT NULL DEFAULT 0,
    error_category          TEXT,
    fallback_reason         TEXT,
    request_id              TEXT,
    context_summary_json    TEXT NOT NULL DEFAULT '{}',
    usage_json              TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (run_id, candidate_id, attempt_no)
);

CREATE INDEX idx_judge_attempts_candidate
    ON judge_attempts (run_id, candidate_id, attempt_no);

CREATE TABLE judge_verdicts (
    run_id          TEXT NOT NULL
                    REFERENCES analysis_runs (run_id) ON DELETE CASCADE,
    candidate_id    TEXT NOT NULL,
    attempt_no      INTEGER NOT NULL,
    verdict         TEXT NOT NULL,
    reason          TEXT NOT NULL,
    adapter         TEXT NOT NULL,
    model           TEXT,
    evidence_json   TEXT NOT NULL DEFAULT '[]',
    conditions_json TEXT NOT NULL DEFAULT '[]',
    uncertainty     TEXT,
    schema_version  INTEGER NOT NULL DEFAULT 1,
    validated_at    TEXT NOT NULL,
    PRIMARY KEY (run_id, candidate_id),
    FOREIGN KEY (run_id, candidate_id, attempt_no)
        REFERENCES judge_attempts (run_id, candidate_id, attempt_no)
        ON DELETE CASCADE
);

CREATE INDEX idx_judge_verdicts_verdict ON judge_verdicts (run_id, verdict);

CREATE TABLE ast_cache (
    cache_key   TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL DEFAULT 0,
    value_json  TEXT NOT NULL
);

CREATE INDEX idx_ast_cache_expires ON ast_cache (expires_at);

CREATE TABLE judge_cache (
    cache_key      TEXT PRIMARY KEY,
    adapter        TEXT NOT NULL DEFAULT '',
    model          TEXT,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    size_bytes     INTEGER NOT NULL DEFAULT 0,
    value_json     TEXT NOT NULL
);

CREATE INDEX idx_judge_cache_expires ON judge_cache (expires_at);
