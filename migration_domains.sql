-- Migration script for dashboard-managed allowed domains
CREATE TABLE IF NOT EXISTS allowed_domains (
  domain TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);