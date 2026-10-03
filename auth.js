/* auth.js — Sign in with Google / Apple, and the session tokens that follow.
   ---------------------------------------------------------------------------
   The whole flow, once:

     1. App sends the user to  GET /auth/login?provider=google&redirect_uri=…
     2. We 302 to the provider with a SIGNED state (no server-side session
        needed — the state carries redirect_uri + nonce + expiry, HMAC'd).
     3. Provider bounces back to /auth/callback/<provider> with a code.
        Google uses a GET; Apple POSTs a form when you ask for scopes.
     4. We exchange the code server-side (the client secret never leaves the
        Worker), read the id_token, and mint OUR OWN session token.
     5. The user lands back on the app carrying that session token.

   Why we do not verify the provider's id_token signature: we did not receive
   it from a browser, we fetched it ourselves from the provider's token
   endpoint over TLS, having authenticated with our client secret. OpenID
   Connect Core §3.1.3.7 explicitly allows skipping signature validation in
   exactly this case. We still check iss / aud / exp, because those catch
   configuration mistakes rather than forgery. This removes JWKS fetching,
   caching and key-rollover handling — a lot of moving parts that could only
   ever fail closed on a good day.

   Session tokens are HS256 JWTs signed with SESSION_SECRET and sent by the app
   as `Authorization: Bearer …`. Deliberately NOT cookies: the gateway is on a
   different origin from your app, so a cookie would be third-party, and
   browsers are busy killing those. A bearer token in localStorage is the
   arrangement that keeps working. */

const enc = new TextEncoder();
const dec = new TextDecoder();

/* ── base64url ──────────────────────────────────────────────────────────── */
export function b64uEncode(bytes){
  let s = '';
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function b64uDecode(str){
  const s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : '';
  const bin = atob(s + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const b64uJson = obj => b64uEncode(enc.encode(JSON.stringify(obj)));

/* ── HS256 ──────────────────────────────────────────────────────────────── */
async function hmacKey(secret){
  return crypto.subtle.importKey('raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
export async function signJWT(payload, secret, ttlSeconds){
  const now = Math.floor(Date.now() / 1000);
  const body = { iat: now, exp: now + (ttlSeconds || 2592000), ...payload };
  const head = b64uJson({ alg: 'HS256', typ: 'JWT' });
  const data = head + '.' + b64uJson(body);
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(data));
  return data + '.' + b64uEncode(sig);
}
/* Returns the payload, or null. Never throws on malformed input — a bad token
   is an ordinary event on a public endpoint, not an exception. */
export async function verifyJWT(token, secret){
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return null;
    const data = parts[0] + '.' + parts[1];
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(secret),
      b64uDecode(parts[2]), enc.encode(data));
    if (!ok) return null;
    const payload = JSON.parse(dec.decode(b64uDecode(parts[1])));
    if (payload.exp && Math.floor(Date.now() / 1000) >= payload.exp) return null;
    return payload;
  } catch { return null; }
}
/* Read a JWT we did NOT sign (a provider id_token). Claims only — see the
   header comment for why the signature is not checked here. */
export function decodeJWT(token){
  try {
    const p = String(token || '').split('.');
    if (p.length !== 3) return null;
    return JSON.parse(dec.decode(b64uDecode(p[1])));
  } catch { return null; }
}

/* ── Providers ──────────────────────────────────────────────────────────── */
export const PROVIDERS = {
  google: {
    authorize: 'https://accounts.google.com/o/oauth2/v2/auth',
    token: 'https://oauth2.googleapis.com/token',
    scope: 'openid email profile',
    issuers: ['https://accounts.google.com', 'accounts.google.com'],
    idField: 'GOOGLE_CLIENT_ID',
    secretField: 'GOOGLE_CLIENT_SECRET',
    // Google is happy with a plain GET redirect back.
    extraAuthParams: () => ({ prompt: 'select_account' }),
  },
  apple: {
    authorize: 'https://appleid.apple.com/auth/authorize',
    token: 'https://appleid.apple.com/auth/token',
    scope: 'email name',
    issuers: ['https://appleid.apple.com'],
    idField: 'APPLE_CLIENT_ID',            // the Services ID, e.g. fit.tangent.web
    secretField: null,                     // built per-request, signed ES256
    // Asking for scopes forces Apple to POST the callback as a form.
    extraAuthParams: () => ({ response_mode: 'form_post' }),
  },
};

/* Apple does not issue a static client secret: you sign a short-lived ES256
   JWT with the .p8 private key from the developer portal. Rebuilt per login
   (cheap) rather than cached, so a key rotation takes effect immediately. */
async function appleClientSecret(env){
  const pem = String(env.APPLE_PRIVATE_KEY || '').trim();
  if (!pem || !env.APPLE_TEAM_ID || !env.APPLE_KEY_ID || !env.APPLE_CLIENT_ID){
    throw new Error('Apple sign-in is not configured (needs APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_CLIENT_ID, APPLE_PRIVATE_KEY)');
  }
  const der = b64uDecode(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
    .replace(/\+/g, '-').replace(/\//g, '_'));
  const key = await crypto.subtle.importKey('pkcs8', der,
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const now = Math.floor(Date.now() / 1000);
  const head = b64uJson({ alg: 'ES256', kid: env.APPLE_KEY_ID, typ: 'JWT' });
  const body = b64uJson({ iss: env.APPLE_TEAM_ID, iat: now, exp: now + 300,
                          aud: 'https://appleid.apple.com', sub: env.APPLE_CLIENT_ID });
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key,
    enc.encode(head + '.' + body));
  return head + '.' + body + '.' + b64uEncode(sig);
}

export function providerConfigured(name, env){
  if (name === 'google') return !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);
  if (name === 'apple') return !!(env.APPLE_CLIENT_ID && env.APPLE_TEAM_ID
    && env.APPLE_KEY_ID && env.APPLE_PRIVATE_KEY);
  return false;
}

/* The OAuth `state` is a signed, expiring envelope rather than a random value
   we would otherwise have to remember somewhere. It is the CSRF defence AND
   how we know where to send the user back to. */
export async function makeState(env, data){
  return signJWT({ ...data, k: 'oauth_state' }, env.SESSION_SECRET, 600);
}
export async function readState(env, state){
  const p = await verifyJWT(state, env.SESSION_SECRET);
  return (p && p.k === 'oauth_state') ? p : null;
}

export function authorizeUrl(name, env, redirectUri, state){
  const p = PROVIDERS[name];
  const u = new URL(p.authorize);
  u.searchParams.set('client_id', env[p.idField]);
  u.searchParams.set('redirect_uri', redirectUri);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('scope', p.scope);
  u.searchParams.set('state', state);
  for (const [k, v] of Object.entries(p.extraAuthParams())) u.searchParams.set(k, v);
  return u.toString();
}

/* Exchange the one-time code for tokens, then distil the identity we care
   about. Returns { sub, email, name, picture, provider }. */
export async function exchangeCode(name, env, code, redirectUri){
  const p = PROVIDERS[name];
  const secret = name === 'apple' ? await appleClientSecret(env) : env[p.secretField];
  const body = new URLSearchParams({
    client_id: env[p.idField],
    client_secret: secret,
    code,
    grant_type: 'authorization_code',
    redirect_uri: redirectUri,
  });
  const res = await fetch(p.token, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const j = await res.json().catch(() => ({}));
  if (!res.ok){
    throw new Error('token exchange failed: ' + (j.error_description || j.error || res.status));
  }
  const claims = decodeJWT(j.id_token);
  if (!claims || !claims.sub) throw new Error('no usable id_token from ' + name);
  if (!p.issuers.includes(claims.iss)) throw new Error('unexpected issuer ' + claims.iss);
  if (claims.aud !== env[p.idField]) throw new Error('id_token was not issued for this client');
  return {
    provider: name,
    sub: name + ':' + claims.sub,           // namespaced: Google and Apple subs can collide
    email: claims.email || null,
    emailVerified: claims.email_verified !== false,
    name: claims.name || null,
    picture: claims.picture || null,
  };
}

/* The token the app will carry. Short-ish by default: a leaked bearer token
   should stop working on its own, and re-login is one silent redirect. */
export async function mintSession(env, user){
  const days = parseInt(env.SESSION_DAYS || '30', 10) || 30;
  return signJWT({ sub: user.sub, email: user.email, name: user.name,
                   picture: user.picture, k: 'session' },
                 env.SESSION_SECRET, days * 86400);
}
export async function readSession(env, request){
  const h = request.headers.get('authorization') || '';
  const m = /^Bearer\s+(.+)$/i.exec(h.trim());
  if (!m) return null;
  const p = await verifyJWT(m[1], env.SESSION_SECRET);
  return (p && p.k === 'session') ? p : null;
}

/* ── Dev sign-in stub ─────────────────────────────────────────────────────
   A fake provider that mints a REAL session for a fake person, so the rest of
   the system — sessions, D1 users, per-user daily quota, the proxy — can be
   built and tested before any Google credentials exist. Only the trip to the
   identity provider is skipped; nothing else is faked.

   `as` lets you be different people on demand, which is the whole point when
   the thing you are testing is a PER-USER quota:
       /auth/login?provider=dev&as=alice   → dev:alice
       /auth/login?provider=dev            → dev:dev@example.test

   Guarded by DEV_AUTH, off unless it is exactly "true". Sessions minted this
   way carry dev:true so they are identifiable in /auth/me and in any log. */
export const devAuthEnabled = env => String(env.DEV_AUTH || '') === 'true';

/* Who may hold an account at all. Empty = anyone who can sign in with a real
   provider. Entries are either a full address or '@domain.com' for everyone at
   that domain. This gates the REAL providers, where the identity is proven by
   Google or Apple.

   It deliberately does NOT make the dev stub safe. The stub proves nothing —
   it issues a session for whatever name you pass it — so allowlisting an
   address just advertises which one is worth impersonating. Use DEV_AUTH_TOKEN
   for that instead: a secret the caller must know. */
export function emailAllowed(email, list){
  if (!list.length) return true;                 // unrestricted
  const e = String(email || '').trim().toLowerCase();
  if (!e) return false;
  return list.some(rule => {
    const r = rule.trim().toLowerCase();
    if (!r) return false;
    if (r === '*') return true;
    if (r.startsWith('@')) return e.endsWith(r); // '@tangent.fit'
    return e === r;
  });
}

export function devUser(as){
  const who = String(as || 'dev@example.test').trim().slice(0, 64) || 'dev@example.test';
  const handle = who.includes('@') ? who : who + '@example.test';
  return {
    provider: 'dev',
    sub: 'dev:' + handle,
    email: handle,
    emailVerified: true,
    name: handle.split('@')[0],
    picture: null,
    dev: true,
  };
}
