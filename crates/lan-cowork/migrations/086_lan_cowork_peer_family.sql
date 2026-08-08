-- LAN Cowork peer-family schema for standalone (Python-absent) deployments.
-- Byte/column-identical to core/schema_core/schema_sql_integrations.py after all
-- Python migrations (peers pubkey/x25519_pk come from migration 83). Applied ONLY
-- in standalone mode (see schema::apply_standalone_schema); NOT part of the
-- unconditional MIGRATIONS array — in hybrid, Python solely owns these tables and
-- their schema_version; creating them from Rust too would double-own the schema
-- (version desync during the migration period). standalone == Python absent, so
-- there Rust is the sole owner.
CREATE TABLE IF NOT EXISTS peers (
    peer_id           TEXT PRIMARY KEY,
    name              TEXT,
    api_host          TEXT,
    api_port          INTEGER,
    token             TEXT,
    token_expires_at  INTEGER,
    token_issued_at   INTEGER,
    pubkey            BLOB,
    x25519_pk         BLOB,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    last_reached_at   INTEGER,
    last_attempted_at INTEGER
);

CREATE TABLE IF NOT EXISTS peer_tokens (
    peer_id    TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    issued_at  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    source     TEXT NOT NULL DEFAULT 'pairing',
    note       TEXT
);
CREATE INDEX IF NOT EXISTS idx_peer_tokens_expires ON peer_tokens(expires_at) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS peer_pairing_requests (
    request_id      TEXT PRIMARY KEY,
    peer_id         TEXT NOT NULL,
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL,
    pin_hash        TEXT,
    pin_expires_at  INTEGER,
    verify_attempts INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    pubkey          BLOB,
    x25519_pk       BLOB,
    commit_hash     BLOB,
    sas             TEXT,
    source_ip       TEXT
);
CREATE INDEX IF NOT EXISTS idx_pairing_status ON peer_pairing_requests(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_pairing_peer_id ON peer_pairing_requests(peer_id, status);

CREATE TABLE IF NOT EXISTS lan_cowork_identity (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS import_session (
    id                 TEXT PRIMARY KEY,
    peer_id            TEXT NOT NULL,
    peer_name          TEXT NOT NULL,
    mode               TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending',
    last_seen_rowid    INTEGER,
    snapshot_max_rowid INTEGER,
    total_files        INTEGER,
    done_files         INTEGER NOT NULL DEFAULT 0,
    import_folder      TEXT NOT NULL,
    options            TEXT NOT NULL DEFAULT '{"include_favorites":false,"merge_metadata":false}',
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS import_file_id_map (
    session_id     TEXT NOT NULL REFERENCES import_session(id) ON DELETE CASCADE,
    remote_peer_id TEXT NOT NULL,
    remote_file_id INTEGER NOT NULL,
    local_file_id  INTEGER NOT NULL,
    status         TEXT NOT NULL DEFAULT 'done',
    PRIMARY KEY (session_id, remote_peer_id, remote_file_id)
);

CREATE TABLE IF NOT EXISTS import_collection_id_map (
    session_id           TEXT NOT NULL REFERENCES import_session(id) ON DELETE CASCADE,
    remote_peer_id       TEXT NOT NULL,
    remote_collection_id INTEGER NOT NULL,
    local_collection_id  INTEGER NOT NULL,
    PRIMARY KEY (session_id, remote_peer_id, remote_collection_id)
);
