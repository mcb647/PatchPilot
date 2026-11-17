-- PatchPilot P0 database schema, version 1.
--
-- One analysis is one row in ``analysis_runs``; every other row of this schema
-- belongs to exactly that run.  Composite primary/foreign keys ``(run_id, ...)``
-- make a reference into a different run impossible, while single-column
-- ``run_id`` foreign keys cascade on run deletion (used by future pruning).
--
-- List-shaped evidence (hunks, changed lines, diagnostics, edge ids, candidate
-- ids, metrics) is stored as versioned JSON text; scalar identity and lookup
-- columns are real columns so queries stay index friendly.
--
-- ``storage.py`` stamps ``PRAGMA user_version`` after this script succeeds, so
-- the script itself only creates objects and must not change ``user_version``.

CREATE TABLE analysis_runs (
    run_id                  TEXT PRIMARY KEY,
    repo_id                 TEXT NOT NULL,
    display_name            TEXT NOT NULL,
    repo_root               TEXT NOT NULL,
    branch                  TEXT,
    detached                INTEGER NOT NULL DEFAULT 0,
    mode                    TEXT NOT NULL,
    endpoint_before         TEXT NOT NULL,
    endpoint_after          TEXT NOT NULL,
    started_at              TEXT NOT NULL,
    finished_at             TEXT,
    status                  TEXT NOT NULL,
    summary                 TEXT NOT NULL,
    config_digest           TEXT NOT NULL DEFAULT '',
    analyzer_version        TEXT NOT NULL DEFAULT '',
    snapshot_format_version INTEGER NOT NULL DEFAULT 1,
    schema_version          INTEGER NOT NULL DEFAULT 1,
    metrics_json            TEXT NOT NULL DEFAULT '{}',
    diagnostics_json        TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX idx_analysis_runs_repo_started
    ON analysis_runs (repo_id, started_at DESC, run_id DESC);

CREATE TABLE snapshot_entries (
    run_id          TEXT NOT NULL
                    REFERENCES analysis_runs (run_id) ON DELETE CASCADE,
    side            TEXT NOT NULL,
    path            TEXT NOT NULL,
    status          TEXT NOT NULL,
    content_sha256  TEXT,
    git_oid         TEXT,
    size            INTEGER,
    is_python       INTEGER NOT NULL DEFAULT 0,
    detail          TEXT,
    PRIMARY KEY (run_id, side, path)
);

CREATE TABLE changes (
    run_id                  TEXT NOT NULL
                            REFERENCES analysis_runs (run_id) ON DELETE CASCADE,
    change_id               TEXT NOT NULL,
    kind                    TEXT NOT NULL,
    old_path                TEXT,
    new_path                TEXT,
    old_sha256              TEXT,
    new_sha256              TEXT,
    rename_basis            TEXT,
    analysis_status         TEXT NOT NULL,
    old_changed_lines_json  TEXT NOT NULL DEFAULT '[]',
    new_changed_lines_json  TEXT NOT NULL DEFAULT '[]',
    hunks_json              TEXT NOT NULL DEFAULT '[]',
    diff_truncated          INTEGER NOT NULL DEFAULT 0,
    diagnostics_json        TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (run_id, change_id)
);

CREATE INDEX idx_changes_new_path ON changes (run_id, new_path);
CREATE INDEX idx_changes_old_path ON changes (run_id, old_path);

CREATE TABLE symbols (
    run_id          TEXT NOT NULL
                    REFERENCES analysis_runs (run_id) ON DELETE CASCADE,
    symbol_id       TEXT NOT NULL,
    side            TEXT NOT NULL,
    path            TEXT NOT NULL,
    module          TEXT NOT NULL DEFAULT '',
    qualified_name  TEXT NOT NULL DEFAULT '',
    kind            TEXT NOT NULL,
    parent_id       TEXT,
    start_line      INTEGER NOT NULL,
    end_line        INTEGER NOT NULL,
    def_line        INTEGER NOT NULL,
    decorator_start INTEGER,
    is_test         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, symbol_id)
);

CREATE INDEX idx_symbols_side_path ON symbols (run_id, side, path, start_line);

CREATE TABLE symbol_changes (
    run_id                  TEXT NOT NULL
                            REFERENCES analysis_runs (run_id) ON DELETE CASCADE,
    symbol_change_id        TEXT NOT NULL,
    change_id               TEXT NOT NULL,
    kind                    TEXT NOT NULL,
    reason                  TEXT NOT NULL,
    old_symbol_id           TEXT,
    new_symbol_id           TEXT,
    structure_changed       INTEGER NOT NULL DEFAULT 1,
    old_changed_lines_json  TEXT NOT NULL DEFAULT '[]',
    new_changed_lines_json  TEXT NOT NULL DEFAULT '[]',
    diagnostics_json        TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (run_id, symbol_change_id),
    FOREIGN KEY (run_id, change_id)
        REFERENCES changes (run_id, change_id) ON DELETE CASCADE,
    FOREIGN KEY (run_id, old_symbol_id)
        REFERENCES symbols (run_id, symbol_id),
    FOREIGN KEY (run_id, new_symbol_id)
        REFERENCES symbols (run_id, symbol_id)
);

CREATE INDEX idx_symbol_changes_change ON symbol_changes (run_id, change_id);

CREATE TABLE call_edges (
    run_id          TEXT NOT NULL
                    REFERENCES analysis_runs (run_id) ON DELETE CASCADE,
    edge_id         TEXT NOT NULL,
    side            TEXT NOT NULL,
    caller_id       TEXT NOT NULL,
    callee_id       TEXT,
    path            TEXT NOT NULL,
    line            INTEGER NOT NULL,
    col             INTEGER NOT NULL,
    edge_kind       TEXT NOT NULL,
    resolution      TEXT NOT NULL,
    reason          TEXT,
    target          TEXT,
    callee_module   TEXT,
    PRIMARY KEY (run_id, edge_id),
    FOREIGN KEY (run_id, caller_id)
        REFERENCES symbols (run_id, symbol_id),
    FOREIGN KEY (run_id, callee_id)
        REFERENCES symbols (run_id, symbol_id)
);

CREATE INDEX idx_call_edges_callee ON call_edges (run_id, side, callee_id);
CREATE INDEX idx_call_edges_caller ON call_edges (run_id, side, caller_id);

CREATE TABLE impact_candidates (
    run_id              TEXT NOT NULL
                        REFERENCES analysis_runs (run_id) ON DELETE CASCADE,
    candidate_id        TEXT NOT NULL,
    symbol_change_id    TEXT NOT NULL,
    seed_symbol_id      TEXT NOT NULL,
    candidate_symbol_id TEXT NOT NULL,
    side                TEXT NOT NULL,
    min_depth           INTEGER NOT NULL,
    edge_ids_json       TEXT NOT NULL DEFAULT '[]',
    evidence            TEXT NOT NULL DEFAULT '',
    truncated           INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, candidate_id),
    FOREIGN KEY (run_id, symbol_change_id)
        REFERENCES symbol_changes (run_id, symbol_change_id) ON DELETE CASCADE,
    FOREIGN KEY (run_id, seed_symbol_id)
        REFERENCES symbols (run_id, symbol_id),
    FOREIGN KEY (run_id, candidate_symbol_id)
        REFERENCES symbols (run_id, symbol_id)
);

CREATE INDEX idx_impact_candidates_change
    ON impact_candidates (run_id, symbol_change_id, min_depth, candidate_id);

CREATE TABLE test_recommendations (
    run_id              TEXT NOT NULL
                        REFERENCES analysis_runs (run_id) ON DELETE CASCADE,
    side                TEXT NOT NULL,
    test_path           TEXT NOT NULL,
    qualified_name      TEXT NOT NULL DEFAULT '',
    candidate_ids_json  TEXT NOT NULL DEFAULT '[]',
    min_depth           INTEGER NOT NULL DEFAULT 1,
    strength            TEXT NOT NULL,
    evidence            TEXT NOT NULL DEFAULT '',
    exists_in_after     INTEGER NOT NULL DEFAULT 1,
    test_symbol_id      TEXT,
    PRIMARY KEY (run_id, side, test_path, qualified_name),
    FOREIGN KEY (run_id, test_symbol_id)
        REFERENCES symbols (run_id, symbol_id)
);

CREATE INDEX idx_test_recommendations_strength
    ON test_recommendations (run_id, strength);
