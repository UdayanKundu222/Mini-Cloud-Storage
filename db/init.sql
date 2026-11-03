-- Runs once, the first time the Postgres volume is created.

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user'
                  CHECK (role IN ('admin', 'user', 'viewer')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Only metadata lives here; the bytes live in MinIO under object_key.
CREATE TABLE files (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL,
    object_key    TEXT NOT NULL UNIQUE,
    size_bytes    BIGINT NOT NULL,
    mime_type     TEXT NOT NULL,
    visibility    TEXT NOT NULL DEFAULT 'private'
                  CHECK (visibility IN ('private', 'shared')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_files_owner ON files(owner_id);
CREATE INDEX idx_files_visibility ON files(visibility);
