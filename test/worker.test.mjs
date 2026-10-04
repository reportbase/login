/* Runs the Worker handler directly against a stubbed Anthropic and a real
   in-memory SQLite standing in for D1. No wrangler, no network. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleRequest, originAllowed, redirectAllowed, memoryLimit, _resetMemoryLimit } from '../worker.js';
import { signJWT, verifyJWT, mintSession, b64uEncode, emailAllowed } from '../auth.js';
import { makeD1 } from './d1.mjs';

const ORIGIN = 'https://tangent.fit';
const SECRET = 'test-session-secret';
const APP = 'https://tangent.fit/app';

function baseEnv(db){
  return {
    ANTHROPIC_API_KEY: 'sk-ant-secret',
    SESSION_SECRET: SECRET,
    ALLOWED_ORIGINS: ORIGIN + ',https://*.tangent.fit',
    DEFAULT_DAILY_LIMIT: '3',
    BURST_PER_MIN: '0',
    GOOGLE_CLIENT_ID: 'gid.apps.googleusercontent.com',
    GOOGLE_CLIENT_SECRET: 'gsecret',
    DB: db,
  };
}
const CTX = { waitUntil: p => { if (p && p.catch) p.catch(() => {}); } };

function stubUpstream(reply){
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init, headers: new Headers(init.headers) });
    return typeof reply === 'function' ? reply(String(url), init)
      : new Response(JSON.stringify({ content: [], usage: { input_tokens: 7, output_tokens: 11 } }),
          { status: 200, headers: { 'content-type': 'application/json' } });
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}

/* A provider id_token. decodeJWT never checks the signature (see auth.js on
   why that is correct here), so the third segment is filler. */
function idToken(claims){
  const seg = o => b64uEncode(new TextEncoder().encode(JSON.stringify(o)));
  return seg({ alg: 'RS256' }) + '.' + seg(claims) + '.' + b64uEncode(new Uint8Array([1, 2, 3]));
}

const post = (body, token, headers = {}, path = '/v1/messages') =>
  new Request('https://gw.workers.dev' + path, {
    method: 'POST',
    headers: {
      origin: ORIGIN, 'content-type': 'application/json',
      ...(token ? { authorization: 'Bearer ' + token } : {}), ...headers,
    },
    body: JSON.stringify(body),
  });

async function signedIn(env, sub = 'google:42'){
  await env.DB.prepare(
    `INSERT INTO users (id, provider, email, name, picture, created_at, last_seen)
     VALUES (?1,'google','u@tangent.fit','U',NULL,?2,?2)`).bind(sub, Date.now()).run();
  return mintSession(env, { sub, email: 'u@tangent.fit', name: 'U', picture: null });
}

/* ── Primitives ─────────────────────────────────────────────────────────── */

test('session tokens survive a round trip and reject tampering or expiry', async () => {
  const t = await signJWT({ sub: 'google:1', k: 'session' }, SECRET, 60);
  assert.equal((await verifyJWT(t, SECRET)).sub, 'google:1');
  assert.equal(await verifyJWT(t, 'other-secret'), null, 'signed with a different key');
  const parts = t.split('.');
  const forged = parts[0] + '.' + b64uEncode(new TextEncoder().encode(
    JSON.stringify({ sub: 'google:ADMIN', k: 'session', exp: 9e9 }))) + '.' + parts[2];
  assert.equal(await verifyJWT(forged, SECRET), null, 'payload swapped, signature stale');
  const expired = await signJWT({ k: 'session' }, SECRET, -10);
  assert.equal(await verifyJWT(expired, SECRET), null);
  assert.equal(await verifyJWT('nonsense', SECRET), null);
  assert.equal(await verifyJWT(null, SECRET), null);
});

test('origin and redirect matching', () => {
  const rules = ['https://tangent.fit', 'https://*.tangent.fit'];
  assert.equal(originAllowed('https://tangent.fit', rules), true);
  assert.equal(originAllowed('https://app.tangent.fit', rules), true);
  assert.equal(originAllowed('https://evil-tangent.fit', rules), false);
  assert.equal(originAllowed('http://tangent.fit', rules), false, 'scheme counts');
  assert.equal(redirectAllowed('https://tangent.fit/app?x=1', rules), true);
  assert.equal(redirectAllowed('https://evil.com/steal', rules), false, 'open redirect blocked');
  assert.equal(redirectAllowed('not a url', rules), false);
});

/* ── Login ──────────────────────────────────────────────────────────────── */

test('login redirects to the provider and refuses an unlisted redirect_uri', async () => {
  const db = makeD1();
  const env = baseEnv(db);
  const go = q => handleRequest(new Request('https://gw.workers.dev/auth/login?' + q), env, CTX);

  const ok = await go('provider=google&redirect_uri=' + encodeURIComponent(APP));
  assert.equal(ok.status, 302);
  const loc = new URL(ok.headers.get('location'));
  assert.equal(loc.origin + loc.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.equal(loc.searchParams.get('client_id'), 'gid.apps.googleusercontent.com');
  assert.equal(loc.searchParams.get('redirect_uri'), 'https://gw.workers.dev/auth/callback/google');
  assert.match(loc.searchParams.get('scope'), /email/);
  const state = await verifyJWT(loc.searchParams.get('state'), SECRET);
  assert.equal(state.k, 'oauth_state');
  assert.equal(state.r, APP, 'the state remembers where to send them back');

  const evil = await go('provider=google&redirect_uri=' + encodeURIComponent('https://evil.com/x'));
  assert.equal(evil.status, 400, 'must not become an open redirect');
  const unknown = await go('provider=facebook&redirect_uri=' + encodeURIComponent(APP));
  assert.equal(unknown.status, 400);
  const unconfigured = await handleRequest(
    new Request('https://gw.workers.dev/auth/login?provider=apple&redirect_uri=' + encodeURIComponent(APP)),
    env, CTX);
  assert.equal(unconfigured.status, 400, 'Apple keys are not set in this env');
  db._close();
});

test('callback exchanges the code, creates the user, and hands back a session', async () => {
  const db = makeD1();
  const env = baseEnv(db);
  const up = stubUpstream(url => {
    assert.equal(url, 'https://oauth2.googleapis.com/token');
    return new Response(JSON.stringify({ id_token: idToken({
      iss: 'https://accounts.google.com', aud: env.GOOGLE_CLIENT_ID,
      sub: '11223344', email: 'someone@gmail.com', email_verified: true, name: 'Some One' }) }),
      { status: 200, headers: { 'content-type': 'application/json' } });
  });
  try {
    const state = await signJWT({ r: APP, m: 'redirect', k: 'oauth_state' }, SECRET, 600);
    const res = await handleRequest(
      new Request('https://gw.workers.dev/auth/callback/google?code=abc&state=' + encodeURIComponent(state)),
      env, CTX);
    assert.equal(res.status, 302);
    const to = new URL(res.headers.get('location'));
    assert.equal(to.origin + to.pathname, APP);
    const token = new URLSearchParams(to.hash.slice(1)).get('claude_gateway_token');
    assert.ok(token, 'token comes back in the FRAGMENT, which never reaches a server log');
    const s = await verifyJWT(token, SECRET);
    assert.equal(s.sub, 'google:11223344', 'provider-namespaced id');
    assert.equal(s.email, 'someone@gmail.com');

    const row = await db.prepare('SELECT * FROM users WHERE id = ?1').bind('google:11223344').first();
    assert.equal(row.email, 'someone@gmail.com');
    assert.equal(row.provider, 'google');
  } finally { up.restore(); db._close(); }
});

test('callback rejects a bad state, a wrong audience, and an unverified email', async () => {
  const db = makeD1();
  const env = baseEnv(db);
  const good = { iss: 'https://accounts.google.com', aud: env.GOOGLE_CLIENT_ID, sub: '9', email: 'x@y.z', email_verified: true };
  const state = await signJWT({ r: APP, m: 'redirect', k: 'oauth_state' }, SECRET, 600);
  const call = (tokenClaims, st = state) => {
    const up = stubUpstream(() => new Response(JSON.stringify({ id_token: idToken(tokenClaims) }),
      { status: 200, headers: { 'content-type': 'application/json' } }));
    return handleRequest(new Request(
      'https://gw.workers.dev/auth/callback/google?code=abc&state=' + encodeURIComponent(st)), env, CTX)
      .finally(() => up.restore());
  };
  const forgedState = await signJWT({ r: 'https://evil.com', m: 'redirect', k: 'oauth_state' }, 'wrong-secret', 600);
  assert.equal((await call(good, forgedState)).status, 400, 'state must be signed by us');

  const wrongAud = await call({ ...good, aud: 'someone-elses-client-id' });
  assert.equal(wrongAud.status, 302, 'errors go back to the app, not a raw 500');
  assert.match(new URL(wrongAud.headers.get('location')).hash, /claude_gateway_error/);

  const unverified = await call({ ...good, email_verified: false });
  assert.match(new URL(unverified.headers.get('location')).hash, /claude_gateway_error/);
  db._close();
});

test('popup mode posts the token only to the app origin', async () => {
  const db = makeD1();
  const env = baseEnv(db);
  const up = stubUpstream(() => new Response(JSON.stringify({ id_token: idToken({
    iss: 'https://accounts.google.com', aud: env.GOOGLE_CLIENT_ID, sub: '5', email: 'p@q.r', email_verified: true }) }),
    { status: 200, headers: { 'content-type': 'application/json' } }));
  try {
    const state = await signJWT({ r: APP, m: 'popup', k: 'oauth_state' }, SECRET, 600);
    const res = await handleRequest(new Request(
      'https://gw.workers.dev/auth/callback/google?code=abc&state=' + encodeURIComponent(state)), env, CTX);
    const body = await res.text();
    assert.match(body, /postMessage/);
    assert.match(body, /"https:\/\/tangent\.fit"/, 'targetOrigin is the app, never "*"');
    assert.match(body, /claude-gateway-auth/);
  } finally { up.restore(); db._close(); }
});

/* ── The gate ───────────────────────────────────────────────────────────── */

test('no session means no service, and the key is never spent', async () => {
  const db = makeD1();
  const up = stubUpstream();
  try {
    const env = baseEnv(db);
    const res = await handleRequest(post({ model: 'm', messages: [] }, null), env, CTX);
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error.type, 'unauthenticated');
    assert.equal(up.calls.length, 0, 'anonymous traffic must not reach Anthropic');

    const forged = await signJWT({ sub: 'google:42', k: 'session' }, 'not-our-secret', 600);
    assert.equal((await handleRequest(post({ model: 'm', messages: [] }, forged), env, CTX)).status, 401);
    assert.equal(up.calls.length, 0);
  } finally { up.restore(); db._close(); }
});

test('a signed-in user is proxied, with the key injected and their own credentials stripped', async () => {
  const db = makeD1();
  const env = baseEnv(db);
  const token = await signedIn(env);
  const up = stubUpstream();
  try {
    const res = await handleRequest(
      post({ model: 'claude-haiku-4-5', max_tokens: 10, messages: [] }, token,
           { 'x-api-key': 'sk-ant-ATTACKER' }), env, CTX);
    assert.equal(res.status, 200);
    assert.equal(up.calls[0].headers.get('x-api-key'), 'sk-ant-secret');
    assert.equal(up.calls[0].url, 'https://api.anthropic.com/v1/messages');
    // The session must not be forwarded to Anthropic as if it were a credential.
    assert.equal(up.calls[0].headers.get('authorization'), null);
    assert.equal(res.headers.get('x-gateway-quota-used'), '1');
    assert.equal(res.headers.get('x-gateway-quota-limit'), '3');
    assert.equal(res.headers.get('x-gateway-quota-remaining'), '2');
  } finally { up.restore(); db._close(); }
});

test('the daily quota is per user, atomic, and does not leak between users', async () => {
  const db = makeD1();
  const env = baseEnv(db);                       // DEFAULT_DAILY_LIMIT = 3
  const a = await signedIn(env, 'google:aaa');
  const b = await signedIn(env, 'google:bbb');
  const up = stubUpstream();
  try {
    for (let i = 1; i <= 3; i++){
      const r = await handleRequest(post({ model: 'm', messages: [] }, a), env, CTX);
      assert.equal(r.status, 200, 'call ' + i);
      assert.equal(r.headers.get('x-gateway-quota-remaining'), String(3 - i));
    }
    const blocked = await handleRequest(post({ model: 'm', messages: [] }, a), env, CTX);
    assert.equal(blocked.status, 429);
    const j = await blocked.json();
    assert.equal(j.error.type, 'quota_exceeded');
    assert.match(j.error.message, /resets at midnight UTC/);
    assert.equal(blocked.headers.get('access-control-allow-origin'), ORIGIN, 'the app must be able to read this');
    assert.equal(up.calls.length, 3, 'the refused call never reached Anthropic');

    // Ten simultaneous requests must not sneak past a spent allowance.
    const burst = await Promise.all(Array.from({ length: 10 },
      () => handleRequest(post({ model: 'm', messages: [] }, a), env, CTX)));
    assert.ok(burst.every(r => r.status === 429), 'no free requests from racing');
    assert.equal(up.calls.length, 3);

    const other = await handleRequest(post({ model: 'm', messages: [] }, b), env, CTX);
    assert.equal(other.status, 200, 'one user burning their quota must not affect another');
  } finally { up.restore(); db._close(); }
});

test('a per-user limit override and a block both take effect', async () => {
  const db = makeD1();
  const env = baseEnv(db);
  const token = await signedIn(env, 'google:vip');
  const up = stubUpstream();
  try {
    await db.prepare('UPDATE users SET daily_limit = 5 WHERE id = ?1').bind('google:vip').run();
    for (let i = 0; i < 5; i++){
      assert.equal((await handleRequest(post({ model: 'm', messages: [] }, token), env, CTX)).status, 200);
    }
    assert.equal((await handleRequest(post({ model: 'm', messages: [] }, token), env, CTX)).status, 429);

    await db.prepare('UPDATE users SET blocked = 1 WHERE id = ?1').bind('google:vip').run();
    const res = await handleRequest(post({ model: 'm', messages: [] }, token), env, CTX);
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error.type, 'account_blocked');
  } finally { up.restore(); db._close(); }
});

test('/auth/me reports the user and what is left today', async () => {
  const db = makeD1();
  const env = baseEnv(db);
  const token = await signedIn(env, 'google:me');
  const up = stubUpstream();
  try {
    await handleRequest(post({ model: 'm', messages: [] }, token), env, CTX);
    const res = await handleRequest(new Request('https://gw.workers.dev/auth/me',
      { headers: { origin: ORIGIN, authorization: 'Bearer ' + token } }), env, CTX);
    const j = await res.json();
    assert.equal(j.user.id, 'google:me');
    assert.equal(j.quota.used, 1);
    assert.equal(j.quota.limit, 3);
    assert.equal(j.quota.remaining, 2);

    const anon = await handleRequest(new Request('https://gw.workers.dev/auth/me',
      { headers: { origin: ORIGIN } }), env, CTX);
    assert.equal(anon.status, 401);
  } finally { up.restore(); db._close(); }
});

/* ── CORS, policy, transport ────────────────────────────────────────────── */

test('preflight allows the Authorization header, and denials explain themselves', async () => {
  const db = makeD1();
  const env = baseEnv(db);
  const ok = await handleRequest(new Request('https://gw.workers.dev/v1/messages',
    { method: 'OPTIONS', headers: { origin: ORIGIN } }), env, CTX);
  assert.equal(ok.status, 204);
  assert.match(ok.headers.get('access-control-allow-headers'), /authorization/,
    'without this every authenticated call fails preflight');
  assert.match(ok.headers.get('access-control-expose-headers'), /x-gateway-quota-remaining/);

  const no = await handleRequest(new Request('https://gw.workers.dev/v1/messages',
    { method: 'OPTIONS', headers: { origin: 'https://evil.com' } }), env, CTX);
  assert.equal(no.status, 403);
  assert.equal(no.headers.get('access-control-allow-origin'), null);
  assert.match(no.headers.get('x-gateway-denied'), /not in ALLOWED_ORIGINS/);
  db._close();
});

test('burst limit fires before any database work', async () => {
  _resetMemoryLimit();
  const db = makeD1();
  const env = { ...baseEnv(db), BURST_PER_MIN: '2' };
  const up = stubUpstream();
  try {
    const mk = () => new Request('https://gw.workers.dev/v1/messages', {
      method: 'POST',
      headers: { origin: ORIGIN, 'content-type': 'application/json', 'cf-connecting-ip': '5.5.5.5' },
      body: '{"model":"m","messages":[]}' });
    // Unauthenticated, so these would be 401 — the burst limit must win first.
    assert.equal((await handleRequest(mk(), env, CTX)).status, 401);
    assert.equal((await handleRequest(mk(), env, CTX)).status, 401);
    const third = await handleRequest(mk(), env, CTX);
    assert.equal(third.status, 429);
    assert.ok(Number(third.headers.get('retry-after')) > 0);
  } finally { up.restore(); db._close(); }
});

test('model allowlist, token cap and body size still apply to signed-in users', async () => {
  const db = makeD1();
  const env = { ...baseEnv(db), ALLOWED_MODELS: 'claude-haiku-4-5', MAX_TOKENS_CAP: '100' };
  const token = await signedIn(env, 'google:pol');
  const up = stubUpstream();
  try {
    const bad = await handleRequest(post({ model: 'claude-opus-4', messages: [] }, token), env, CTX);
    assert.equal(bad.status, 400);
    assert.equal(up.calls.length, 0);

    await handleRequest(post({ model: 'claude-haiku-4-5', max_tokens: 99999, messages: [] }, token), env, CTX);
    assert.equal(JSON.parse(up.calls[0].init.body).max_tokens, 100, 'clamped, not rejected');

    const big = await handleRequest(
      post({ model: 'claude-haiku-4-5', messages: [{ role: 'user', content: 'x'.repeat(5000) }] }, token),
      { ...env, MAX_BODY_BYTES: '100' }, CTX);
    assert.equal(big.status, 413);
  } finally { up.restore(); db._close(); }
});

test('SSE streams through and usage is counted off a tee, not the user copy', async () => {
  const db = makeD1();
  const env = baseEnv(db);
  const token = await signedIn(env, 'google:sse');
  let pushed = 0;
  const body = new ReadableStream({
    async start(c){
      const e = new TextEncoder();
      c.enqueue(e.encode('data: {"type":"message_start","message":{"usage":{"input_tokens":12}}}\n\n')); pushed++;
      await new Promise(r => setTimeout(r, 50));
      c.enqueue(e.encode('data: {"type":"message_delta","usage":{"output_tokens":34}}\n\n')); pushed++;
      c.close();
    },
  });
  const up = stubUpstream(() => new Response(body,
    { status: 200, headers: { 'content-type': 'text/event-stream' } }));
  const waits = [];
  try {
    const res = await handleRequest(post({ model: 'm', messages: [], stream: true }, token), env,
      { waitUntil: p => waits.push(p) });
    assert.match(res.headers.get('content-type'), /text\/event-stream/);
    const rd = res.body.getReader();
    const first = await rd.read();
    assert.match(new TextDecoder().decode(first.value), /message_start/);
    assert.equal(pushed, 1, 'the user is reading while upstream is still producing');
    for (;;){ const { done } = await rd.read(); if (done) break; }
    await Promise.all(waits);
    const row = await db.prepare('SELECT in_tokens, out_tokens FROM usage WHERE user_id = ?1').bind('google:sse').first();
    assert.equal(row.in_tokens, 12);
    assert.equal(row.out_tokens, 34);
  } finally { up.restore(); db._close(); }
});

test('upstream failures pass through without eating the quota silently', async () => {
  const db = makeD1();
  const env = baseEnv(db);
  const token = await signedIn(env, 'google:err');
  const up = stubUpstream(() => { throw new Error('connect ECONNREFUSED'); });
  try {
    const res = await handleRequest(post({ model: 'm', messages: [] }, token), env, CTX);
    assert.equal(res.status, 502);
    assert.equal(res.headers.get('access-control-allow-origin'), ORIGIN);
    // The request WAS counted — documented behaviour, so a retry storm against
    // a broken upstream cannot be used to bypass the limit.
    assert.equal(res.headers.get('x-gateway-quota-used'), '1');
  } finally { up.restore(); db._close(); }
});

test('health reports what is configured without leaking secrets', async () => {
  const db = makeD1();
  const res = await handleRequest(new Request('https://gw.workers.dev/health',
    { headers: { origin: ORIGIN } }), baseEnv(db), CTX);
  const j = await res.json();
  assert.equal(j.keyConfigured, true);
  assert.equal(j.sessionSecretConfigured, true);
  assert.equal(j.databaseBound, true);
  assert.deepEqual(j.providers, ['google'], 'apple is not configured in this env');
  assert.equal(j.yourOriginAllowed, true);
  const s = JSON.stringify(j);
  assert.ok(!s.includes('sk-ant-secret') && !s.includes(SECRET), 'no secret may appear');
  db._close();
});

test('memoryLimit rolls over when its window expires', () => {
  _resetMemoryLimit();
  const t = 1_000_000;
  assert.equal(memoryLimit('k', 2, 60000, t).ok, true);
  assert.equal(memoryLimit('k', 2, 60000, t + 1).ok, true);
  assert.equal(memoryLimit('k', 2, 60000, t + 2).ok, false);
  assert.equal(memoryLimit('k', 2, 60000, t + 60001).ok, true);
});

/* ── Dev sign-in stub ───────────────────────────────────────────────────── */

test('dev sign-in mints a real session without touching any provider', async () => {
  const db = makeD1();
  const env = { ...baseEnv(db), DEV_AUTH: 'true' };
  const up = stubUpstream();               // must stay untouched: no provider call
  try {
    const res = await handleRequest(new Request(
      'https://gw.workers.dev/auth/login?provider=dev&redirect_uri=' + encodeURIComponent(APP)), env, CTX);
    assert.equal(res.status, 302);
    assert.equal(up.calls.length, 0, 'the whole point: no round trip to Google');
    const to = new URL(res.headers.get('location'));
    assert.equal(to.origin + to.pathname, APP);
    const token = new URLSearchParams(to.hash.slice(1)).get('claude_gateway_token');
    const s = await verifyJWT(token, SECRET);
    assert.equal(s.sub, 'dev:dev@example.test');
    assert.equal(s.k, 'session', 'an ordinary session, not a special case downstream');

    // And it is a real user row, so quota applies exactly as it will in production.
    const row = await db.prepare('SELECT * FROM users WHERE id = ?1').bind('dev:dev@example.test').first();
    assert.equal(row.provider, 'dev');
    assert.equal(row.email, 'dev@example.test');
  } finally { up.restore(); db._close(); }
});

test('?as= gives you distinct people, which is how you test a per-user quota', async () => {
  const db = makeD1();
  const env = { ...baseEnv(db), DEV_AUTH: 'true' };   // DEFAULT_DAILY_LIMIT = 3
  const up = stubUpstream();
  try {
    const login = async as => {
      const res = await handleRequest(new Request('https://gw.workers.dev/auth/login?provider=dev&as='
        + encodeURIComponent(as) + '&redirect_uri=' + encodeURIComponent(APP)), env, CTX);
      return new URLSearchParams(new URL(res.headers.get('location')).hash.slice(1)).get('claude_gateway_token');
    };
    const alice = await login('alice');
    const bob = await login('bob@tangent.fit');
    assert.equal((await verifyJWT(alice, SECRET)).sub, 'dev:alice@example.test', 'bare names get a domain');
    assert.equal((await verifyJWT(bob, SECRET)).sub, 'dev:bob@tangent.fit', 'a full address is kept');

    for (let i = 0; i < 3; i++){
      assert.equal((await handleRequest(post({ model: 'm', messages: [] }, alice), env, CTX)).status, 200);
    }
    assert.equal((await handleRequest(post({ model: 'm', messages: [] }, alice), env, CTX)).status, 429,
      'alice is out for the day');
    assert.equal((await handleRequest(post({ model: 'm', messages: [] }, bob), env, CTX)).status, 200,
      'bob is unaffected — quotas really are per person');
  } finally { up.restore(); db._close(); }
});

test('dev sign-in is off unless DEV_AUTH is exactly "true", and still respects the redirect allowlist', async () => {
  const db = makeD1();
  const go = (env, redirect = APP) => handleRequest(new Request(
    'https://gw.workers.dev/auth/login?provider=dev&redirect_uri=' + encodeURIComponent(redirect)), env, CTX);

  assert.equal((await go(baseEnv(db))).status, 400, 'absent');
  assert.equal((await go({ ...baseEnv(db), DEV_AUTH: 'false' })).status, 400);
  assert.equal((await go({ ...baseEnv(db), DEV_AUTH: '1' })).status, 400, 'only the exact string enables it');
  assert.equal((await go({ ...baseEnv(db), DEV_AUTH: 'true' })).status, 302);
  // Enabling the stub must not weaken the open-redirect guard.
  assert.equal((await go({ ...baseEnv(db), DEV_AUTH: 'true' }, 'https://evil.com/x')).status, 400);
  db._close();
});

test('health shouts when the dev stub is live, and stays quiet when it is not', async () => {
  const db = makeD1();
  const on = await (await handleRequest(new Request('https://gw.workers.dev/health',
    { headers: { origin: ORIGIN } }), { ...baseEnv(db), DEV_AUTH: 'true' }, CTX)).json();
  assert.equal(on.devAuth, true);
  assert.match(on.warning, /DEV_AUTH is ON/);
  assert.ok(on.providers.includes('dev'));

  const off = await (await handleRequest(new Request('https://gw.workers.dev/health',
    { headers: { origin: ORIGIN } }), baseEnv(db), CTX)).json();
  assert.equal(off.devAuth, undefined);
  assert.equal(off.warning, undefined);
  assert.ok(!off.providers.includes('dev'));
  db._close();
});

test('quota reset time names tomorrow, not the midnight already gone', async () => {
  const db = makeD1();
  const env = baseEnv(db);
  const token = await signedIn(env, 'google:clock');
  const res = await handleRequest(new Request('https://gw.workers.dev/auth/me',
    { headers: { origin: ORIGIN, authorization: 'Bearer ' + token } }), env, CTX);
  const { quota } = await res.json();
  const today = new Date().toISOString().slice(0, 10);
  const tomorrow = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
  assert.equal(quota.day, today);
  assert.equal(quota.resetsAt, tomorrow + 'T00:00:00Z');
  assert.ok(new Date(quota.resetsAt).getTime() > Date.now(), 'a reset time in the past is a lie');
  db._close();
});

test('login with no provider picks the best configured one', async () => {
  const db = makeD1();
  const go = env => handleRequest(new Request(
    'https://gw.workers.dev/auth/login?redirect_uri=' + encodeURIComponent(APP)), env, CTX);

  // Google present -> Google.
  const g = await go(baseEnv(db));
  assert.match(g.headers.get('location'), /accounts\.google\.com/);

  // Only the dev stub -> dev, and it must issue a session, not an error page.
  const devOnly = { ...baseEnv(db), DEV_AUTH: 'true' };
  delete devOnly.GOOGLE_CLIENT_ID; delete devOnly.GOOGLE_CLIENT_SECRET;
  const d = await go(devOnly);
  assert.equal(d.status, 302);
  const tok = new URLSearchParams(new URL(d.headers.get('location')).hash.slice(1)).get('claude_gateway_token');
  assert.ok(await verifyJWT(tok, SECRET), 'a usable session with no provider named');
  db._close();
});

test('health reports a version and feature list', async () => {
  const db = makeD1();
  const j = await (await handleRequest(new Request('https://gw.workers.dev/health',
    { headers: { origin: ORIGIN } }), baseEnv(db), CTX)).json();
  assert.match(j.version, /^\d{4}-\d{2}-\d{2}\.\d+$/);
  assert.ok(j.features.includes('provider-auto-select'),
    'the feature that tells you an old deployment from a current one');
  db._close();
});

/* ── Access control ─────────────────────────────────────────────────────── */

test('emailAllowed: exact addresses, whole domains, and open-by-default', () => {
  assert.equal(emailAllowed('a@b.com', []), true, 'empty list = unrestricted');
  assert.equal(emailAllowed('tom@tangent.fit', ['tom@tangent.fit']), true);
  assert.equal(emailAllowed('TOM@Tangent.Fit', ['tom@tangent.fit']), true, 'case-insensitive');
  assert.equal(emailAllowed('eve@evil.com', ['tom@tangent.fit']), false);
  assert.equal(emailAllowed('anyone@tangent.fit', ['@tangent.fit']), true, 'whole domain');
  assert.equal(emailAllowed('anyone@nottangent.fit', ['@tangent.fit']), false,
    'a domain rule must not match a longer look-alike host');
  assert.equal(emailAllowed('', ['@tangent.fit']), false, 'no address cannot pass a restricted list');
  assert.equal(emailAllowed('x@y.z', ['*']), true);
});

test('an off-list Google account is refused and leaves no row behind', async () => {
  const db = makeD1();
  const env = { ...baseEnv(db), ALLOWED_EMAILS: '@tangent.fit,friend@gmail.com' };
  const state = await signJWT({ r: APP, m: 'redirect', k: 'oauth_state' }, SECRET, 600);
  const login = claims => {
    const up = stubUpstream(() => new Response(JSON.stringify({ id_token: idToken({
      iss: 'https://accounts.google.com', aud: env.GOOGLE_CLIENT_ID, email_verified: true, ...claims }) }),
      { status: 200, headers: { 'content-type': 'application/json' } }));
    return handleRequest(new Request('https://gw.workers.dev/auth/callback/google?code=c&state='
      + encodeURIComponent(state)), env, CTX).finally(() => up.restore());
  };

  const off = await login({ sub: '1', email: 'stranger@gmail.com' });
  assert.match(new URL(off.headers.get('location')).hash, /claude_gateway_error/);
  assert.equal(await db.prepare('SELECT COUNT(*) c FROM users').first().then(r => r.c), 0,
    'a refused sign-in must not create an account');

  const onDomain = await login({ sub: '2', email: 'tom@tangent.fit' });
  assert.match(new URL(onDomain.headers.get('location')).hash, /claude_gateway_token/);
  const named = await login({ sub: '3', email: 'friend@gmail.com' });
  assert.match(new URL(named.headers.get('location')).hash, /claude_gateway_token/);
  assert.equal(await db.prepare('SELECT COUNT(*) c FROM users').first().then(r => r.c), 2);
  db._close();
});

test('DEV_AUTH_TOKEN gates the stub, and an allowlist does NOT', async () => {
  const db = makeD1();
  const go = (env, q = '') => handleRequest(new Request(
    'https://gw.workers.dev/auth/login?provider=dev' + q + '&redirect_uri=' + encodeURIComponent(APP)), env, CTX);

  // The point of the token: without it the stub is open to anyone who finds it.
  const tokenEnv = { ...baseEnv(db), DEV_AUTH: 'true', DEV_AUTH_TOKEN: 's3cret' };
  assert.equal((await go(tokenEnv)).status, 400, 'no token, no entry');
  assert.equal((await go(tokenEnv, '&token=wrong')).status, 400);
  assert.equal((await go(tokenEnv, '&token=s3cret')).status, 302);

  // And the correction that prompted all this: an email allowlist cannot make
  // the stub safe, because the stub never proves who anyone is. Naming an
  // allowlisted address is all it takes.
  const listEnv = { ...baseEnv(db), DEV_AUTH: 'true', ALLOWED_EMAILS: 'tom@tangent.fit' };
  const impersonated = await go(listEnv, '&as=' + encodeURIComponent('tom@tangent.fit'));
  assert.equal(impersonated.status, 302,
    'documents the hazard: with DEV_AUTH on, anyone can claim any identity');
  const tok = new URLSearchParams(new URL(impersonated.headers.get('location')).hash.slice(1))
    .get('claude_gateway_token');
  assert.equal((await verifyJWT(tok, SECRET)).email, 'tom@tangent.fit');
  db._close();
});

test('health reports whether signup is restricted and the stub is gated', async () => {
  const db = makeD1();
  const open_ = await (await handleRequest(new Request('https://gw.workers.dev/health',
    { headers: { origin: ORIGIN } }), baseEnv(db), CTX)).json();
  assert.equal(open_.signupRestricted, false);
  assert.equal(open_.devAuthTokenRequired, undefined);

  const shut = await (await handleRequest(new Request('https://gw.workers.dev/health',
    { headers: { origin: ORIGIN } }),
    { ...baseEnv(db), ALLOWED_EMAILS: '@tangent.fit', DEV_AUTH_TOKEN: 'x' }, CTX)).json();
  assert.equal(shut.signupRestricted, true);
  assert.equal(shut.devAuthTokenRequired, true);
  assert.ok(shut.features.includes('email-allowlist'));
  db._close();
});

/* The deployed allowlist itself, read from wrangler.toml rather than a copy in
   this file, so a change there is what gets tested. The owner's GitHub Pages
   site signs in (games, draw and 3d live there); other people's github.io
   sites, and look-alike hosts, do not. */
test('wrangler.toml allows the GitHub Pages site and no other github.io', async () => {
  const { readFileSync } = await import('node:fs');
  const toml = readFileSync(new URL('../wrangler.toml', import.meta.url), 'utf8');
  const m = toml.match(/^ALLOWED_ORIGINS\s*=\s*"([^"]*)"/m);
  assert.ok(m, 'ALLOWED_ORIGINS not found in wrangler.toml');
  const rules = m[1].split(',').map(s => s.trim()).filter(Boolean);
  assert.equal(originAllowed('https://reportbase.github.io', rules), true);
  assert.equal(redirectAllowed('https://reportbase.github.io/3d/3d.html', rules), true);
  assert.equal(redirectAllowed('https://reportbase.github.io/draw/draw.html?lab=1', rules), true);
  assert.equal(originAllowed('https://tangent.fit', rules), true);
  assert.equal(originAllowed('https://someone-else.github.io', rules), false);
  assert.equal(originAllowed('https://reportbase.github.io.evil.com', rules), false);
  assert.equal(originAllowed('http://reportbase.github.io', rules), false);
  assert.ok(!rules.some(r => /\*\.github\.io$/.test(r)), 'never allow *.github.io');
  // Public pages sign in here now, so the no-password dev stub must stay off.
  assert.match(toml, /^DEV_AUTH\s*=\s*"false"/m, 'DEV_AUTH must be "false" in the deployed config');
});
