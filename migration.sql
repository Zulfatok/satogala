-- Domain repair migration.
-- Target domain: satogala.biz.id
-- The deploy workflow verifies this target matches DOMAIN in wrangler.toml.
-- This migration is idempotent and never drops/rebuilds tables.

-- Create the configured-domain alias first so email foreign keys can be moved safely.
-- If the target alias already belongs to another user, INSERT OR IGNORE leaves the
-- legacy row untouched instead of risking an ownership change.
INSERT OR IGNORE INTO aliases (local_part, domain, user_id, disabled, created_at)
SELECT
  local_part,
  'satogala.biz.id',
  user_id,
  disabled,
  created_at
FROM aliases
WHERE LOWER(domain) IN ('mazayaa.tech', 'mazaya.codes', '__primary_domain__');

-- Move legacy email rows only when the matching configured-domain alias belongs
-- to the same user. Existing correct domains are not changed.
UPDATE emails
SET domain = 'satogala.biz.id'
WHERE LOWER(domain) IN ('mazayaa.tech', 'mazaya.codes', '__primary_domain__')
  AND EXISTS (
    SELECT 1
    FROM aliases AS target
    WHERE target.local_part = emails.local_part
      AND target.domain = 'satogala.biz.id'
      AND target.user_id = emails.user_id
  );

-- Remove a legacy alias only after its replacement exists for the same owner and
-- no email row still references the legacy address.
DELETE FROM aliases
WHERE LOWER(domain) IN ('mazayaa.tech', 'mazaya.codes', '__primary_domain__')
  AND EXISTS (
    SELECT 1
    FROM aliases AS target
    WHERE target.local_part = aliases.local_part
      AND target.domain = 'satogala.biz.id'
      AND target.user_id = aliases.user_id
  )
  AND NOT EXISTS (
    SELECT 1
    FROM emails
    WHERE emails.local_part = aliases.local_part
      AND LOWER(emails.domain) = LOWER(aliases.domain)
  );
