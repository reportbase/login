/* login — a Claude API gateway for a CONSUMER app, on Cloudflare.
   ---------------------------------------------------------------------------
   The problem it solves: you want many members of the public to use a Claude
   feature in your app, without shipping an API key and without one person (or
   one script) draining your account.

   Every request to /v1/* must carry a session token belonging to a real signed-in
   person, and every request costs that person one of their daily allowance.

     browser ──login──▶ Google / Apple ──▶ /auth/callback ──▶ session token
     browser ──Bearer session token──▶ /v1/messages ──▶ quota ──▶ Anthropic

   The layers, in the order a request meets them:
     1. CORS preflight            — answered without touching anything else.
     2. Origin allowlist          — which of YOUR apps may call, for browsers.
     3. Burst rate limit (per IP) — blunt anti-script measure, pre-auth.
     4. Session                   — who is this, really. No session, no service.
     5. Daily quota (per user)    — atomic in D1; this is the real cost control.
     6. Body policy               — model allowlist, max_tokens cap, size cap.
     7. Proxy with the key injected, streaming untouched.

   Notes worth keeping:
   - Nothing awaits the response body. Anthropic's SSE must arrive token by
     token; token accounting happens on a tee'd copy inside waitUntil.
   - Client-supplied x-api-key / authorization-as-credential never go upstream.
     The Authorization header is OURS: it carries the session, not a Claude key.
   - The origin allowlist is a hygiene filter, not the security boundary. With
     a public app anyone can replay a request; the session and the per-user
     quota are what actually bound your bill. See README §Security. */

import {
  PROVIDERS, providerConfigured, makeState, readState, authorizeUrl,
  exchangeCode, mintSession, readSession, devAuthEnabled, devUser, emailAllowed,
} from './auth.js';
import { upsertUser, getQuota, consume, recordTokens, dayKey } from './quota.js';

/* Bump when behaviour changes. /health reports it, so "did my deploy land?"
   is answerable directly instead of being inferred from a failing request. */
const GATEWAY_VERSION = '2026-08-06.5';
const GATEWAY_FEATURES = ['provider-auto-select', 'dev-stub', 'daily-quota', 'resets-tomorrow',
  'email-allowlist', 'dev-auth-token'];

const UPSTREAM = 'https://api.anthropic.com';
const DEFAULT_ANTHROPIC_VERSION = '2023-06-01';
const DEFAULT_PATHS = '/v1/messages,/v1/messages/count_tokens,/v1/models';

const FORWARD_HEADERS = ['content-type', 'anthropic-version', 'anthropic-beta', 'accept'];

const EXPOSE_HEADERS = [
  'request-id',
  'retry-after',
  'x-gateway-quota-used',
  'x-gateway-quota-limit',
  'x-gateway-quota-remaining',
].join(', ');

const csv = s => String(s || '').split(',').map(x => x.trim()).filter(Boolean);
const num = (v, dflt) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : dflt; };

/* ── Origin matching ─────────────────────────────────────────────────────── */
export function originAllowed(origin, allowed){
  if (!allowed.length) return false;
  if (allowed.includes('*')) return true;
  if (!origin) return false;
  if (allowed.includes(origin)) return true;
  for (const rule of allowed){
    if (!rule.startsWith('http') || !rule.includes('://*.')) continue;
    const [scheme, rest] = rule.split('://');
    const suffix = rest.slice(1);
    if (origin.startsWith(scheme + '://') && origin.endsWith(suffix)){
      const host = origin.slice(scheme.length + 3);
      if (host.length > suffix.length) return true;
    }
  }
  return false;
}
/* Where we are willing to send a freshly minted session token. Same list as
   the CORS allowlist: an open redirect here would hand someone's session to
   whatever site they were tricked into starting the login from. */
export function redirectAllowed(url, allowed){
  try { return originAllowed(new URL(url).origin, allowed); } catch { return false; }
}

/* ── Burst limit (per IP, pre-auth) ──────────────────────────────────────── */
const _mem = new Map();
export function memoryLimit(key, limit, windowMs, now = Date.now()){
  let e = _mem.get(key);
  if (!e || now >= e.resetAt){ e = { count: 0, resetAt: now + windowMs }; _mem.set(key, e); }
  e.count++;
  if (_mem.size > 5000){ for (const [k, v] of _mem) if (now >= v.resetAt) _mem.delete(k); }
  return { ok: e.count <= limit, remaining: Math.max(0, limit - e.count),
           retryAfter: Math.max(1, Math.ceil((e.resetAt - now) / 1000)) };
}
export function _resetMemoryLimit(){ _mem.clear(); }

async function checkBurst(request, env){
  const limit = num(env.BURST_PER_MIN, 20);
  if (limit <= 0) return { ok: true };
  const ip = request.headers.get('cf-connecting-ip') || 'no-ip';
  if (env.RATE_LIMITER && typeof env.RATE_LIMITER.limit === 'function'){
    const { success } = await env.RATE_LIMITER.limit({ key: ip });
    return { ok: !!success, retryAfter: 60 };
  }
  return memoryLimit('ip:' + ip, limit, 60000);
}

/* ── CORS ────────────────────────────────────────────────────────────────── */
function corsHeaders(origin){
  return {
    'access-control-allow-origin': origin || 'null',
    'vary': 'Origin',
    'access-control-allow-methods': 'POST, GET, OPTIONS',
    // 'authorization' is the session token. Without it here, every call fails preflight.
    'access-control-allow-headers': 'authorization, content-type, anthropic-version, anthropic-beta, accept',
    'access-control-max-age': '86400',
    'access-control-expose-headers': EXPOSE_HEADERS,
  };
}
function deniedHeaders(origin){
  return {
    'vary': 'Origin',
    // ASCII only: header values are ByteString, and a stray em dash throws.
    'x-gateway-denied': 'origin ' + (origin || '(none sent)')
      + ' is not in ALLOWED_ORIGINS - add it in wrangler.toml and redeploy',
  };
}
function json(status, obj, origin, extra){
  return new Response(JSON.stringify(obj), { status,
    headers: { 'content-type': 'application/json', ...corsHeaders(origin), ...(extra || {}) } });
}
function fail(status, type, message, origin, extra){
  return json(status, { type: 'error', error: { type, message } }, origin, extra);
}
const html = (body, status = 200) => new Response(body,
  { status, headers: { 'content-type': 'text/html; charset=utf-8' } });

/* A login that fails should say so on a page, not as raw JSON: the user is
   looking at a browser tab, not a network inspector. */
function authError(msg, appRedirect, mode){
  const safe = String(msg).replace(/[<&]/g, c => (c === '<' ? '&lt;' : '&amp;'));
  if (mode === 'popup'){
    return html(`<!doctype html><meta charset="utf-8"><title>Sign-in failed</title>
<body style="font:14px system-ui;padding:2rem;color:#333">
<p><b>Sign-in failed.</b></p><p>${safe}</p>
<script>try{window.opener&&window.opener.postMessage(
  {type:'claude-gateway-auth',ok:false,error:${JSON.stringify(String(msg))}},'*');}catch(e){}
setTimeout(()=>window.close(),2500);</script></body>`, 400);
  }
  if (appRedirect){
    const u = new URL(appRedirect);
    u.hash = 'claude_gateway_error=' + encodeURIComponent(msg);
    return Response.redirect(u.toString(), 302);
  }
  return html(`<!doctype html><meta charset="utf-8"><body style="font:14px system-ui;padding:2rem">
<p><b>Sign-in failed.</b></p><p>${safe}</p></body>`, 400);
}

/* Hand a finished session back to the app: postMessage for a popup, URL
   fragment for a redirect. Shared by the OAuth callback and the dev stub so
   both exercise exactly the same handoff. */
function deliverSession(token, appRedirect, mode){
  if (mode === 'popup'){
    const target = JSON.stringify(new URL(appRedirect).origin);
    return html(`<!doctype html><meta charset="utf-8"><title>Signed in</title>
<body style="font:14px system-ui;padding:2rem;color:#333">Signed in. You can close this window.
<script>try{window.opener&&window.opener.postMessage(
  {type:'claude-gateway-auth',ok:true,token:${JSON.stringify(token)}},${target});}catch(e){}
window.close();</script></body>`);
  }
  const u = new URL(appRedirect);
  // Fragment, not query: fragments are not sent to servers and stay out of logs.
  u.hash = 'claude_gateway_token=' + encodeURIComponent(token);
  return Response.redirect(u.toString(), 302);
}

/* ── Token accounting ────────────────────────────────────────────────────
   Runs on a tee'd copy of the response so the user's stream is never delayed.
   Usage counts appear in message_start (input) and message_delta (output) for
   SSE, and in the usage object for a plain JSON reply. Best effort throughout:
   this informs pricing, it does not gate anything. */
async function countUsage(stream, db, userId, day){
  try {
    const rd = stream.getReader();
    const dec = new TextDecoder();
    let buf = '', inTok = 0, outTok = 0;
    for (;;){
      const { done, value } = await rd.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      if (buf.length > 65536) buf = buf.slice(-8192);   // usage lines are small and early/late
      for (const m of buf.matchAll(/"input_tokens":\s*(\d+)/g)) inTok = Math.max(inTok, +m[1]);
      for (const m of buf.matchAll(/"output_tokens":\s*(\d+)/g)) outTok = Math.max(outTok, +m[1]);
    }
    if (inTok || outTok) await recordTokens(db, userId, day, inTok, outTok);
  } catch { /* telemetry never breaks a request */ }
}

/* ── Router ──────────────────────────────────────────────────────────────── */
export async function handleRequest(request, env, ctx){
  const url = new URL(request.url);
  const origin = request.headers.get('origin');
  const allowed = csv(env.ALLOWED_ORIGINS);
  const path = url.pathname;

  if (request.method === 'OPTIONS'){
    if (!originAllowed(origin, allowed)) return new Response(null, { status: 403, headers: deniedHeaders(origin) });
    return new Response(null, { status: 204, headers: corsHeaders(origin) });
  }

  if (path === '/health' || path === '/'){
    return json(200, {
      ok: true,
      service: 'login',
      version: GATEWAY_VERSION,
      features: GATEWAY_FEATURES,
      keyConfigured: !!env.ANTHROPIC_API_KEY,
      sessionSecretConfigured: !!env.SESSION_SECRET,
      databaseBound: !!env.DB,
      providers: [
        ...Object.keys(PROVIDERS).filter(p => providerConfigured(p, env)),
        ...(devAuthEnabled(env) ? ['dev'] : []),
      ],
      // Deliberately shouted: DEV_AUTH lets anyone who can reach an allowlisted
      // origin mint a session for any identity they name. Never ship it on.
      devAuth: devAuthEnabled(env) || undefined,
      warning: devAuthEnabled(env)
        ? 'DEV_AUTH is ON - anyone can sign in as anyone. Set DEV_AUTH="false" before real users.'
        : undefined,
      allowedOrigins: allowed.length,
      yourOrigin: origin || null,
      yourOriginAllowed: originAllowed(origin, allowed),
      signupRestricted: csv(env.ALLOWED_EMAILS).length > 0,
      devAuthTokenRequired: !!env.DEV_AUTH_TOKEN || undefined,
      defaultDailyLimit: num(env.DEFAULT_DAILY_LIMIT, 50),
      burstPerMin: num(env.BURST_PER_MIN, 20),
    }, originAllowed(origin, allowed) ? origin : null);
  }

  /* ── Auth ─────────────────────────────────────────────────────────────── */
  if (path === '/auth/providers'){
    return json(200, { providers: [
      ...Object.keys(PROVIDERS).filter(p => providerConfigured(p, env)),
      ...(devAuthEnabled(env) ? ['dev'] : []),
    ] },
      originAllowed(origin, allowed) ? origin : null);
  }

  /* Step 1 — send the user to the provider. This is a top-level navigation,
     not a fetch, so there is no Origin to check; the redirect_uri allowlist is
     what keeps it honest. */
  if (path === '/auth/login'){
    // No provider named? Pick the best one configured. This exists so a client
    // never has to ask /auth/providers first — an await before window.open
    // costs the user gesture and the browser silently blocks the popup.
    const provider = url.searchParams.get('provider') || (
      providerConfigured('google', env) ? 'google'
      : providerConfigured('apple', env) ? 'apple'
      : devAuthEnabled(env) ? 'dev'
      : 'google');
    const appRedirect = url.searchParams.get('redirect_uri') || '';
    const mode = url.searchParams.get('mode') === 'popup' ? 'popup' : 'redirect';

    /* Dev stub: skip the identity provider entirely and issue a real session.
       Everything downstream stays genuine, so the app can be finished before
       any Google credentials exist. See devUser() in auth.js. */
    if (provider === 'dev'){
      if (!devAuthEnabled(env)) return authError('Dev sign-in is off. Set DEV_AUTH="true" in wrangler.toml.', '', mode);
      /* With DEV_AUTH_TOKEN set, the stub survives on a public deployment: it
         still proves nothing about identity, but you have to know the secret
         to reach it. Without the token it is open to anyone who finds the URL,
         which is only acceptable before you have users. */
      if (env.DEV_AUTH_TOKEN && url.searchParams.get('token') !== env.DEV_AUTH_TOKEN){
        return authError('Dev sign-in requires the correct ?token= on this deployment.', '', mode);
      }
      if (!env.SESSION_SECRET) return authError('Gateway is missing SESSION_SECRET.', '', mode);
      if (!env.DB) return authError('Gateway has no database bound (D1 binding DB).', '', mode);
      if (!appRedirect || !redirectAllowed(appRedirect, allowed)){
        return authError('redirect_uri is missing or its origin is not in ALLOWED_ORIGINS.', '', mode);
      }
      const u = devUser(url.searchParams.get('as'));
      try { await upsertUser(env.DB, u); }
      catch (e){ return authError('Could not create the dev account: ' + String((e && e.message) || e), appRedirect, mode); }
      return deliverSession(await mintSession(env, u), appRedirect, mode);
    }

    if (!PROVIDERS[provider]) return authError('Unknown provider: ' + provider, '', mode);
    if (!providerConfigured(provider, env)) return authError('Sign in with ' + provider + ' is not configured on this gateway.', '', mode);
    if (!env.SESSION_SECRET) return authError('Gateway is missing SESSION_SECRET.', '', mode);
    if (!appRedirect || !redirectAllowed(appRedirect, allowed)){
      return authError('redirect_uri is missing or its origin is not in ALLOWED_ORIGINS.', '', mode);
    }
    const cb = url.origin + '/auth/callback/' + provider;
    const state = await makeState(env, { r: appRedirect, m: mode });
    return Response.redirect(authorizeUrl(provider, env, cb, state), 302);
  }

  /* Step 2 — the provider bounces back. Google GETs; Apple POSTs a form
     because we asked for scopes. Both carry code + state. */
  if (path.startsWith('/auth/callback/')){
    const provider = path.slice('/auth/callback/'.length);
    let code = url.searchParams.get('code');
    let state = url.searchParams.get('state');
    let providerError = url.searchParams.get('error');
    if (request.method === 'POST'){
      const form = new URLSearchParams(await request.text());
      code = form.get('code') || code;
      state = form.get('state') || state;
      providerError = form.get('error') || providerError;
    }
    const st = await readState(env, state);
    const appRedirect = st ? st.r : '';
    const mode = st ? st.m : 'redirect';
    if (!PROVIDERS[provider]) return authError('Unknown provider.', appRedirect, mode);
    if (!st) return authError('Login state expired or invalid — please try again.', '', mode);
    if (providerError) return authError('Provider reported: ' + providerError, appRedirect, mode);
    if (!code) return authError('No authorization code returned.', appRedirect, mode);
    if (!env.DB) return authError('Gateway has no database bound (D1 binding DB).', appRedirect, mode);

    let user;
    try {
      user = await exchangeCode(provider, env, code, url.origin + '/auth/callback/' + provider);
    } catch (e){
      return authError(String((e && e.message) || e), appRedirect, mode);
    }
    if (String(env.REQUIRE_VERIFIED_EMAIL || 'true') === 'true' && user.email && !user.emailVerified){
      return authError('That account has an unverified email address.', appRedirect, mode);
    }
    // Who is allowed an account. Checked after the provider has proved who they
    // are, and before any row exists — a refused sign-in leaves no trace in D1.
    if (!emailAllowed(user.email, csv(env.ALLOWED_EMAILS))){
      return authError('This is a private deployment and ' + (user.email || 'that account')
        + ' is not on its access list.', appRedirect, mode);
    }
    try { await upsertUser(env.DB, user); }
    catch (e){ return authError('Could not create your account: ' + String((e && e.message) || e), appRedirect, mode); }

    const token = await mintSession(env, user);
    // The opener's origin is already allowlisted (we checked redirect_uri).
    return deliverSession(token, appRedirect, mode);
  }

  /* Who am I, and what is left today. The app's "you have 12 messages left"
     line comes from here. */
  if (path === '/auth/me'){
    const corsOrigin = originAllowed(origin, allowed) ? origin : null;
    if (!originAllowed(origin, allowed)) return fail(403, 'forbidden',
      'Origin not in ALLOWED_ORIGINS.', null, deniedHeaders(origin));
    const s = await readSession(env, request);
    if (!s) return fail(401, 'unauthenticated', 'Sign in to continue.', corsOrigin);
    if (!env.DB) return fail(500, 'configuration_error', 'No D1 binding on this Worker.', corsOrigin);
    const q = await getQuota(env.DB, s.sub, num(env.DEFAULT_DAILY_LIMIT, 50));
    return json(200, { user: { id: s.sub, email: s.email, name: s.name, picture: s.picture },
                       quota: q }, corsOrigin);
  }

  /* ── API proxy ────────────────────────────────────────────────────────── */
  if (!originAllowed(origin, allowed)){
    const noOriginOk = String(env.ALLOW_NO_ORIGIN || '') === 'true' && !origin;
    if (!noOriginOk){
      return fail(403, 'forbidden',
        origin ? 'Origin ' + origin + ' is not in ALLOWED_ORIGINS. Add it in wrangler.toml and redeploy.'
               : 'This gateway requires a browser Origin. Set ALLOW_NO_ORIGIN=true to permit direct calls.',
        null, deniedHeaders(origin));
    }
  }

  const paths = csv(env.ALLOWED_PATHS || DEFAULT_PATHS);
  if (!paths.includes(path)) return fail(404, 'not_found', 'No route for ' + path + ' on this gateway.', origin);
  if (request.method !== 'POST' && request.method !== 'GET'){
    return fail(405, 'method_not_allowed', request.method + ' is not supported here.', origin);
  }
  if (!env.ANTHROPIC_API_KEY){
    return fail(500, 'configuration_error',
      'ANTHROPIC_API_KEY is not set. Run: wrangler secret put ANTHROPIC_API_KEY', origin);
  }

  // 3 — burst limit before we do any work, including database work.
  const burst = await checkBurst(request, env);
  if (!burst.ok){
    return fail(429, 'rate_limit_error', 'Too many requests — slow down.', origin,
      { 'retry-after': String(burst.retryAfter || 60) });
  }

  // 4 — session. This is the gate; everything before it is hygiene.
  const session = await readSession(env, request);
  if (!session){
    return fail(401, 'unauthenticated', 'Sign in to use this feature.', origin);
  }
  if (!env.DB) return fail(500, 'configuration_error', 'No D1 binding on this Worker.', origin);

  // 5 — daily quota, atomically claimed.
  const q = await consume(env.DB, session.sub, num(env.DEFAULT_DAILY_LIMIT, 50));
  const quotaHeaders = {
    'x-gateway-quota-used': String(q.used),
    'x-gateway-quota-limit': String(q.limit),
    'x-gateway-quota-remaining': String(q.remaining),
  };
  if (!q.ok){
    if (q.reason === 'blocked') return fail(403, 'account_blocked', 'This account has been suspended.', origin, quotaHeaders);
    if (q.reason === 'no_such_user') return fail(401, 'unauthenticated', 'Please sign in again.', origin);
    return fail(429, 'quota_exceeded',
      'You have used all ' + q.limit + ' of today\'s messages. Your allowance resets at midnight UTC.',
      origin, quotaHeaders);
  }

  // 6 — body policy.
  let bodyText = null;
  if (request.method === 'POST'){
    const maxBytes = num(env.MAX_BODY_BYTES, 262144);
    bodyText = await request.text();
    if (bodyText.length > maxBytes){
      return fail(413, 'request_too_large',
        'Request body exceeds the gateway limit of ' + maxBytes + ' bytes.', origin, quotaHeaders);
    }
    let body;
    try { body = JSON.parse(bodyText); }
    catch { return fail(400, 'invalid_request_error', 'Request body is not valid JSON.', origin, quotaHeaders); }
    const models = csv(env.ALLOWED_MODELS);
    if (models.length && body.model && !models.includes(body.model)){
      return fail(400, 'invalid_request_error',
        'Model ' + body.model + ' is not allowed by this gateway.', origin, quotaHeaders);
    }
    const cap = num(env.MAX_TOKENS_CAP, 0);
    if (cap > 0 && num(body.max_tokens, 0) > cap){ body.max_tokens = cap; bodyText = JSON.stringify(body); }
  }

  // 7 — proxy.
  const headers = new Headers();
  for (const name of FORWARD_HEADERS){
    const v = request.headers.get(name);
    if (v) headers.set(name, v);
  }
  if (!headers.has('anthropic-version')) headers.set('anthropic-version', DEFAULT_ANTHROPIC_VERSION);
  if (request.method === 'POST' && !headers.has('content-type')) headers.set('content-type', 'application/json');
  headers.set('x-api-key', env.ANTHROPIC_API_KEY);

  let upstream;
  try {
    upstream = await fetch(UPSTREAM + path + url.search,
      { method: request.method, headers, body: bodyText, signal: request.signal });
  } catch (e){
    return fail(502, 'upstream_error',
      'Could not reach the Anthropic API: ' + String((e && e.message) || e), origin, quotaHeaders);
  }

  const out = new Headers({ ...corsHeaders(origin), ...quotaHeaders });
  const ct = upstream.headers.get('content-type');
  if (ct) out.set('content-type', ct);
  const rid = upstream.headers.get('request-id');
  if (rid) out.set('request-id', rid);
  if (ct && ct.includes('text/event-stream')){
    out.set('cache-control', 'no-cache, no-transform');
    out.set('x-accel-buffering', 'no');
  }

  // Tee for accounting; the user's copy is returned immediately either way.
  let bodyOut = upstream.body;
  if (upstream.ok && upstream.body && ctx && typeof ctx.waitUntil === 'function'){
    const [a, b] = upstream.body.tee();
    bodyOut = a;
    ctx.waitUntil(countUsage(b, env.DB, session.sub, q.day || dayKey()));
  }
  return new Response(bodyOut, { status: upstream.status, headers: out });
}

export default { fetch: handleRequest };
