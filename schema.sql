-- login D1 schema.
--   npx wrangler d1 create login
--   npx wrangler d1 execute login --remote --file=./schema.sql

CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,   -- 'google:1234…' / 'apple:0011…' — namespaced, subs can collide
  provider    TEXT NOT NULL,
  email       TEXT,
  name        TEXT,
  picture     TEXT,
  daily_limit INTEGER,            -- NULL = use DEFAULT_DAILY_LIMIT; set to raise or cut off one user
  blocked     INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS users_email ON users (email);

CREATE TABLE IF NOT EXISTS usage (
  user_id    TEXT NOT NULL,
  day        TEXT NOT NULL,       -- 'YYYY-MM-DD', UTC
  count      INTEGER NOT NULL DEFAULT 0,
  in_tokens  INTEGER NOT NULL DEFAULT 0,
  out_tokens INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, day)
);
CREATE INDEX IF NOT EXISTS usage_day ON usage (day);

-- Handy once you are live:
--   Today's heaviest users
--     SELECT u.email, s.count, s.in_tokens, s.out_tokens FROM usage s
--     JOIN users u ON u.id = s.user_id
--     WHERE s.day = date('now') ORDER BY s.count DESC LIMIT 20;
--   Give someone a bigger allowance
--     UPDATE users SET daily_limit = 500 WHERE email = 'someone@example.com';
--   Cut off an abuser
--     UPDATE users SET blocked = 1 WHERE id = 'google:1234…';
--   Prune old usage rows (safe any time)
--     DELETE FROM usage WHERE day < date('now', '-90 days');
