-- Adds attachment metadata support for inline images/barcodes.
-- File bytes are stored in R2 via the MAIL_R2 binding.

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

CREATE INDEX IF NOT EXISTS idx_email_attachments_email ON email_attachments(email_id);
CREATE INDEX IF NOT EXISTS idx_email_attachments_user ON email_attachments(user_id);
