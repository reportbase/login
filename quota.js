/* quota.js — who exists, and how much they have used today.
   ---------------------------------------------------------------------------
   Backed by D1 (SQLite at the edge) for one reason: the increment has to be
   ATOMIC. With many consumers, "read the count, add one, write it back" is a
   race that hands out free requests to anyone who taps twice quickly. A single
   UPSERT … RETURNING does it in one statement, so the number the Worker acts
   on is the number that was actually stored.

   Two tables, deliberately boring:
     users  — one row per person, created on first login. daily_limit is NULL
              for "use the global default", or a number to override one user
              (raise it for a paying customer, drop it to 0 to cut someone off).
     usage  — one row per user per UTC day. Old rows are harmless; a scheduled
              cleanup is in the README if the table ever gets big enough to care.

   Days are UTC. Local-midnight resets would need a per-user timezone and would
   still be wrong for travellers; a fixed reset is easier to explain in-product
   ("resets at midnight UTC") than one that drifts. */

export const dayKey = (now = Date.now()) => new Date(now).toISOString().slice(0, 10);

/* Called on every successful login. Returns the stored user row, so a
   per-user daily_limit override survives across logins. */
export async function upsertUser(db, user){
  await db.prepare(
    `INSERT INTO users (id, provider, email, name, picture, created_at, last_seen)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
     ON CONFLICT(id) DO UPDATE SET
       email = COALESCE(excluded.email, users.email),
       name = COALESCE(excluded.name, users.name),
       picture = COALESCE(excluded.picture, users.picture),
       last_seen = excluded.last_seen`)
    .bind(user.sub, user.provider, user.email, user.name, user.picture, Date.now())
    .run();
  return await db.prepare('SELECT * FROM users WHERE id = ?1').bind(user.sub).first();
}

export async function getUser(db, id){
  return await db.prepare('SELECT * FROM users WHERE id = ?1').bind(id).first();
}

/* Read-only: what the account looks like right now, for /auth/me and for
   showing "12 of 50 left today" in the UI. */
export async function getQuota(db, id, defaultLimit, now = Date.now()){
  const day = dayKey(now);
  const [u, row] = await Promise.all([
    db.prepare('SELECT daily_limit, blocked FROM users WHERE id = ?1').bind(id).first(),
    db.prepare('SELECT count FROM usage WHERE user_id = ?1 AND day = ?2').bind(id, day).first(),
  ]);
  const limit = (u && u.daily_limit != null) ? u.daily_limit : defaultLimit;
  const used = (row && row.count) || 0;
  return { day, used, limit, remaining: Math.max(0, limit - used),
           blocked: !!(u && u.blocked),
           // TOMORROW's midnight. Using `day` here named the midnight that has
           // already passed, which reads as "your allowance reset hours ago".
           resetsAt: dayKey(now + 86400000) + 'T00:00:00Z' };
}

/* Atomically claim ONE request. Returns { ok, used, limit, remaining }.
   The increment happens first and is rolled back conceptually by simply
   letting the count exceed the limit — we never decrement, because a user who
   hammers a blocked endpoint should not get free retries by racing. Their
   count sits above the limit until midnight, which is the correct outcome. */
export async function consume(db, id, defaultLimit, now = Date.now()){
  const day = dayKey(now);
  const u = await db.prepare('SELECT daily_limit, blocked FROM users WHERE id = ?1').bind(id).first();
  if (!u) return { ok: false, reason: 'no_such_user', used: 0, limit: 0, remaining: 0 };
  if (u.blocked) return { ok: false, reason: 'blocked', used: 0, limit: 0, remaining: 0 };
  const limit = u.daily_limit != null ? u.daily_limit : defaultLimit;

  const row = await db.prepare(
    `INSERT INTO usage (user_id, day, count) VALUES (?1, ?2, 1)
     ON CONFLICT(user_id, day) DO UPDATE SET count = count + 1
     RETURNING count`).bind(id, day).first();
  const used = (row && row.count) || 1;
  return { ok: used <= limit, reason: used <= limit ? null : 'quota_exceeded',
           used, limit, remaining: Math.max(0, limit - used), day };
}

/* Best-effort spend telemetry. Not the limit — the limit is request count,
   which is what the user was told — but you cannot price a plan without
   knowing what a day of "50 messages" actually costs you. */
export async function recordTokens(db, id, day, inTok, outTok){
  try {
    await db.prepare(
      `UPDATE usage SET in_tokens = in_tokens + ?3, out_tokens = out_tokens + ?4
       WHERE user_id = ?1 AND day = ?2`)
      .bind(id, day, inTok | 0, outTok | 0).run();
  } catch { /* telemetry must never break a request */ }
}
