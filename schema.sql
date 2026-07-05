-- schema.sql
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  pass_salt TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',     -- 'user' | 'admin'
  alias_limit INTEGER NOT NULL DEFAULT 3,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reset_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS aliases (
  local_part TEXT NOT NULL,             -- contoh: "sipar" untuk sipar@domain
  domain TEXT NOT NULL,                 -- contoh: "mazaya.codes"
  user_id TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(local_part, domain),      -- kombinasi local_part + domain harus unik
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS emails (
  id TEXT PRIMARY KEY,
  local_part TEXT NOT NULL,
  domain TEXT NOT NULL,
  user_id TEXT NOT NULL,
  from_addr TEXT NOT NULL,
  to_addr TEXT NOT NULL,
  subject TEXT,
  date TEXT,
  text TEXT,
  html TEXT,
  raw_key TEXT,                          -- key object di R2 (nullable)
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(local_part, domain) REFERENCES aliases(local_part, domain) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS allowed_domains (
  domain TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS email_attachments (
  id TEXT PRIMARY KEY,
  email_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  filename TEXT,
  mime_type TEXT NOT NULL,
  content_id TEXT,
  disposition TEXT,
  inline INTEGER NOT NULL DEFAULT 0,
  size INTEGER NOT NULL,
  r2_key TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(email_id) REFERENCES emails(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_emails_user_created ON emails(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_emails_alias_created ON emails(local_part, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_attachments_email ON email_attachments(email_id);
CREATE INDEX IF NOT EXISTS idx_email_attachments_user ON email_attachments(user_id);
