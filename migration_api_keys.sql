-- API keys for programmatic access (alternative to the session cookie).
-- Only the SHA-256 hash of each key is stored; the raw key is shown once at creation.
CREATE TABLE IF NOT EXISTS api_keys (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL,
  name         TEXT,
  key_hash     TEXT NOT NULL UNIQUE,
  prefix       TEXT,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER,
  expires_at   INTEGER,
  disabled     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
