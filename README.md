# login (login)

A Cloudflare Worker that lets a **consumer app** offer a Claude feature to the public without shipping an API key and without one person draining the account. Users sign in with Google or Apple; each signed-in person gets a daily message allowance; the Anthropic key never leaves the Worker.

```
browser ──login──▶ Google / Apple ──▶ /auth/callback ──▶ session token
browser ──Bearer session token──▶ /v1/messages ──▶ quota ──▶ Anthropic
```

Every `/v1/*` request must belong to a real signed-in person, and costs that person one of their daily messages. That per-user counter — not the origin allowlist — is what actually bounds your bill.

The Worker deploys as **`login`**, i.e. `https://login.tangent.workers.dev`. That name is deliberate: the older, unauthenticated `login` Worker is left alone, so anything already pointing at it keeps working while this one is built out.

## Start here: the dev stub

`DEV_AUTH = "true"` is on in `wrangler.toml`, which adds a `dev` provider that mints a **real session for a made-up person without contacting Google**. Everything downstream is genuine — real D1 user rows, real per-user daily quota, real proxying — so you can finish the app before touching an OAuth console.

```
/auth/login?provider=dev&redirect_uri=https://yourapp.com/          -> dev@example.test
/auth/login?provider=dev&as=alice&redirect_uri=https://yourapp.com/ -> alice@example.test
```

`as=` is the useful part: the thing you are testing is a *per-user* quota, so you need to be more than one person. Sign in as `alice`, spend her allowance, sign in as `bob`, confirm he still has his.

So the short path to a working system is: create the D1 database, set `ANTHROPIC_API_KEY` and `SESSION_SECRET`, put your app's origin in `ALLOWED_ORIGINS`, deploy. Google and Apple credentials can wait — steps 2 and 3 below are skippable for now.

Open `demo.html` from an allowlisted origin to walk the whole thing end to end: health, sign-in, quota, a normal call, a streamed call, and a "burn quota" button that shows you the 429 when the allowance runs out.

**Turn it off before real users.** While `DEV_AUTH` is on, anyone who can reach an allowlisted origin can sign in as anyone. `/health` reports `devAuth: true` and a warning the whole time it is enabled, so you cannot leave it on without being told.

## Setup

**1. Database.** Users and daily usage live in D1.

```bash
npx wrangler d1 create login          # paste the id into wrangler.toml
npx wrangler d1 execute login --remote --file=./schema.sql
```

**2. Google sign-in** (skippable while the dev stub is on). In the [Google Cloud console](https://console.cloud.google.com/apis/credentials), create an OAuth 2.0 Client ID of type *Web application*, and add this exact authorised redirect URI:

```
https://login.<your-subdomain>.workers.dev/auth/callback/google
```

**3. Apple sign-in** (optional). In the Apple Developer portal you need a **Services ID** (this is your `APPLE_CLIENT_ID`, e.g. `fit.tangent.web`), your **Team ID**, and a **Sign in with Apple key** — download the `.p8`, note its Key ID. Register the same callback URL, `…/auth/callback/apple`. Apple requires HTTPS and will not accept `localhost`, so test Apple against a deployed Worker.

**4. Secrets.**

```bash
npx wrangler secret put ANTHROPIC_API_KEY
npx wrangler secret put SESSION_SECRET        # long random string — this signs sessions
# Google — not needed while DEV_AUTH is on:
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
# Apple, if you want it:
npx wrangler secret put APPLE_CLIENT_ID
npx wrangler secret put APPLE_TEAM_ID
npx wrangler secret put APPLE_KEY_ID
npx wrangler secret put APPLE_PRIVATE_KEY     # paste the whole .p8 contents
```

**5. Origins.** Put your app's origins in `ALLOWED_ORIGINS` in `wrangler.toml`. This list does double duty: it is the CORS allowlist *and* the list of places a session token may be delivered, which is what stops the login flow becoming an open redirect.

**6.** `npx wrangler deploy`, then check `/health`:

```json
{ "ok": true, "keyConfigured": true, "sessionSecretConfigured": true,
  "databaseBound": true, "providers": ["google","apple"],
  "yourOriginAllowed": true, "defaultDailyLimit": 50 }
```

Anything `false` there is your next job. It never echoes a secret.

## Using it from the app

```html
<script type="module">
import { ClaudeClient } from './claude-client.js';

const claude = new ClaudeClient({
  baseUrl: 'https://login.tangent.workers.dev',
  model: 'claude-haiku-4-5',
  onAuthRequired: () => showSignInButton(),        // session expired or absent
  onQuotaExceeded: e => toast(e.message),          // used up today's messages
});

claude.captureRedirect();          // picks up a token after a redirect-mode login

if (!claude.isSignedIn) await claude.login('google');   // opens a popup
const { user, quota } = await claude.me();
show(`${quota.remaining} of ${quota.limit} messages left today`);

await claude.stream({ messages: [{ role: 'user', content: 'Hello' }] },
                    { onText: t => out.textContent += t });
</script>
```

`login()` opens a popup by default, which keeps the user's app state alive mid-task; pass `{ mode: 'redirect' }` for embeds or browsers that block popups, and call `captureRedirect()` on load to collect the token. The token is kept in `localStorage` and sent as an `Authorization: Bearer` header — deliberately not a cookie, because the gateway is a different origin from your app and third-party cookies are being phased out.

Every response carries `x-gateway-quota-used`, `-limit` and `-remaining`, so you can keep a counter in the UI without polling `/auth/me`.

## Running the business

Everything is a SQL statement away:

```sql
-- today's heaviest users
SELECT u.email, s.count, s.in_tokens, s.out_tokens FROM usage s
JOIN users u ON u.id = s.user_id WHERE s.day = date('now')
ORDER BY s.count DESC LIMIT 20;

UPDATE users SET daily_limit = 500 WHERE email = 'someone@example.com';  -- a paying user
UPDATE users SET blocked = 1 WHERE id = 'google:1234…';                  -- an abuser
DELETE FROM usage WHERE day < date('now', '-90 days');                   -- prune
```

Token counts are recorded per user per day off a tee'd copy of the response, so they never slow anyone's stream. The *limit* is message count, because that is what you can explain to a user ("50 messages a day"), but the token columns are what let you work out what a day of fifty messages actually costs before you price anything.

## Restricting who can sign up

`ALLOWED_EMAILS` decides who may hold an account. Empty means anyone with a Google or Apple account:

```toml
ALLOWED_EMAILS = "@tangent.fit,afriend@gmail.com"     # a whole domain, and one address
```

It is checked after the provider has proved who someone is, and before any row is written, so a refused sign-in leaves nothing in D1. `/health` reports `signupRestricted` so you can see at a glance which mode you are in.

**An allowlist cannot secure the dev stub.** The stub proves nothing about identity — it issues a session for whatever name you hand it — so allowlisting `tom@example.com` merely advertises which address is worth claiming. If you want the stub on a deployment that strangers can reach, gate it with a secret instead:

```bash
npx wrangler secret put DEV_AUTH_TOKEN
# then: /auth/login?provider=dev&token=<secret>&as=alice&redirect_uri=…
```

With that set, dev sign-in without the right `token` is refused. It still proves nothing about *who* you are — it just stops anyone who has not been told the secret from using it at all. For a public launch, `DEV_AUTH = "false"` remains the honest answer.

## Sharing one gateway across apps

Two apps use this Worker, and their costs are not comparable: a chess coach comment is a few hundred tokens, while one AI drawing is up to 16000 output tokens plus an uploaded image — two or three orders of magnitude more. The daily limit counts **requests**, not cost, so fifty of each is not fifty of the same thing. Price `DEFAULT_DAILY_LIMIT` against the expensive one.

Two settings exist because of the drawing app, and both bite quietly if wrong. `MAX_TOKENS_CAP` is `16000`; requests above it are *clamped, not rejected*, so a cap set too low silently truncates an SVG mid-document instead of erroring. `MAX_BODY_BYTES` is 4 MB because a 768px canvas render arrives as base64 and blows past 256 KB immediately.

If the two workloads diverge further, give the expensive one its own Worker with its own limit and its own D1 — it is all config, and a second deployment is a `name` change away.

## Security — the honest version

**The session is the boundary.** A request without a valid, unexpired, correctly-signed session token gets a 401 and never reaches Anthropic. Tokens are HS256 JWTs signed with `SESSION_SECRET`; tampering with the payload invalidates the signature. Rotating that secret signs everyone out — your emergency stop.

**The origin allowlist is hygiene, not security.** It stops other *websites* using your quota in a visitor's browser. It does not stop `curl`, which can send any Origin it likes. At consumer scale, assume anyone can replay a request; what stops them mattering is that they'd need a real Google or Apple account, and that account gets 50 messages a day like everyone else.

**What's still worth watching.** Someone determined can create many Google accounts. If you see that, the levers are lowering `DEFAULT_DAILY_LIMIT`, adding Turnstile to the login route, or requiring an account age or email domain. Also keep spend limits on the Anthropic key itself — defence in depth beats trusting any single layer here, including this one.

**Deliberate behaviour worth knowing:** a request that reaches Anthropic and then fails (a 502, a model error) still counts against the day's allowance. Otherwise a retry loop against a broken upstream would be a free bypass.

**What the Worker guarantees regardless:** the API key is injected server-side and never returned; client-supplied `x-api-key` and `authorization` credentials are dropped rather than forwarded; only allowlisted paths are reachable; and OAuth tokens come back in the URL *fragment*, which browsers never send to a server, so they stay out of access logs.

## Tests

```bash
npm test        # 30 tests, no network, no wrangler
```

The suite runs the Worker handler directly against a stubbed Anthropic and a **real SQLite** standing in for D1 (via `node:sqlite`), so the quota logic is exercised as actual SQL rather than against a fake that would accept anything. It covers session forgery and expiry, the open-redirect guard on `redirect_uri`, the full OAuth callback including wrong-audience and unverified-email rejection, popup `postMessage` targeting the app origin rather than `*`, per-user quota isolation, a **ten-way concurrent race** proving a spent allowance can't be beaten by parallel requests, per-user overrides and blocks, the burst limiter firing before any database work, and a timing assertion that SSE genuinely streams while usage is counted off a tee. The dev stub has its own set: that it contacts no provider, that `as=` really produces separate people with separate allowances, that it stays off unless `DEV_AUTH` is exactly `"true"`, that enabling it does not weaken the open-redirect guard, and that `/health` shouts while it is live.

## Notes

Apple posts its callback as a form (that is what asking for scopes does), and its client secret is a short-lived ES256 JWT signed with your `.p8` — both handled in `src/auth.js`. Provider `id_token` signatures are not verified, deliberately: we fetch them ourselves from the provider's token endpoint over TLS using our client secret, which is the case OpenID Connect Core §3.1.3.7 explicitly exempts. Issuer, audience and expiry are still checked, because those catch configuration mistakes rather than forgery.
