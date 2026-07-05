-- Migration script for adding multi-domain support
-- Run this to update existing aliases table

-- Step 1: Create new aliases table with domain support
CREATE TABLE IF NOT EXISTS aliases_new (
  local_part TEXT NOT NULL,
  domain TEXT NOT NULL DEFAULT 'mazayaa.tech',  -- default to primary domain
  user_id TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(local_part, domain),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Step 2: Copy existing data (set domain to mazaya.codes for all existing aliases)
INSERT INTO aliases_new (local_part, domain, user_id, disabled, created_at)
SELECT local_part, 'mazayaa.tech', user_id, disabled, created_at
FROM aliases;

-- Step 3: Drop old table
DROP TABLE aliases;

-- Step 4: Rename new table
ALTER TABLE aliases_new RENAME TO aliases;

-- Step 5: Update emails table
CREATE TABLE IF NOT EXISTS emails_new (
  id TEXT PRIMARY KEY,
  local_part TEXT NOT NULL,
  domain TEXT NOT NULL DEFAULT 'mazayaa.tech',
  user_id TEXT NOT NULL,
  from_addr TEXT NOT NULL,
  to_addr TEXT NOT NULL,
  subject TEXT,
  date TEXT,
  text TEXT,
  html TEXT,
  raw_key TEXT,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(local_part, domain) REFERENCES aliases(local_part, domain) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Step 6: Copy existing emails (extract domain from to_addr or default to mazaya.codes)
INSERT INTO emails_new (id, local_part, domain, user_id, from_addr, to_addr, subject, date, text, html, raw_key, size, created_at)
SELECT 
  id, 
  local_part, 
  COALESCE(
    CASE 
      WHEN to_addr LIKE '%@%' THEN LOWER(SUBSTR(to_addr, INSTR(to_addr, '@') + 1))
      ELSE 'mazayaa.tech' 
    END,
    'mazayaa.tech'
  ) as domain,
  user_id, 
  from_addr, 
  to_addr, 
  subject, 
  date, 
  text, 
  html, 
  raw_key, 
  size, 
  created_at
FROM emails;

-- Step 7: Drop old emails table
DROP TABLE emails;

-- Step 8: Rename new emails table
ALTER TABLE emails_new RENAME TO emails;

-- Step 9: Recreate indexes
CREATE INDEX IF NOT EXISTS idx_emails_user_created ON emails(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_emails_alias_created ON emails(local_part, created_at DESC);


