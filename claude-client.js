/* claude-client — the browser half of login, for a consumer app.
   ---------------------------------------------------------------------------
   Typical wiring:

     const claude = new ClaudeClient({ baseUrl: 'https://login.example.workers.dev' });

     // On every page load: pick up a token if we just came back from a login.
     claude.captureRedirect();

     if (!claude.isSignedIn) await claude.login('google');     // opens a popup
     const me = await claude.me();                             // { user, quota }
     await claude.stream({ messages }, { onText: t => out(t) });

   The session token lives in localStorage and travels as an Authorization
   header. Not a cookie: the gateway is a different origin from your app, so a
   cookie would be third-party, and browsers are phasing those out.

   Everything that can go wrong for a real user has a named hook rather than a
   thrown string: onAuthRequired (signed out or expired) and onQuotaExceeded
   (used up today's messages) are the two your UI must handle. */

const DEFAULT_VERSION = '2023-06-01';
const STORE_KEY = 'claude_gateway_session';

export class ClaudeGatewayError extends Error {
  constructor(message, status, type, extra){
    super(message);
    this.name = 'ClaudeGatewayError';
    this.status = status || 0;
    this.type = type || 'error';
    Object.assign(this, extra || {});
  }
  get isAuth(){ return this.status === 401; }
  get isQuota(){ return this.type === 'quota_exceeded'; }
}

export class ClaudeClient {
  constructor(opts = {}){
    const base = String(opts.baseUrl || '').replace(/\/+$/, '');
    if (!base) throw new Error('ClaudeClient: baseUrl is required');
    this.baseUrl = base;
    this.model = opts.model || null;
    this.maxTokens = opts.maxTokens || 1024;
    this.version = opts.version || DEFAULT_VERSION;
    this._fetch = opts.fetchImpl || ((...a) => fetch(...a));
    this.storeKey = opts.storeKey || STORE_KEY;
    this.onAuthRequired = opts.onAuthRequired || null;
    this.onQuotaExceeded = opts.onQuotaExceeded || null;
    this.noSignal = false;
    this.token = opts.token || this._load();
  }

  /* ── Session storage ────────────────────────────────────────────────── */
  _load(){
    try { return localStorage.getItem(this.storeKey) || null; } catch { return null; }
  }
  _store(t){
    this.token = t || null;
    try { t ? localStorage.setItem(this.storeKey, t) : localStorage.removeItem(this.storeKey); } catch {}
  }
  get isSignedIn(){ return !!this.token; }
  logout(){ this._store(null); }

  /* ── Login ──────────────────────────────────────────────────────────────
     'popup' keeps the user's app state alive, which matters if they are
     mid-task; 'redirect' is the fallback for browsers or embeds that block
     popups. Both end with a token in localStorage. */
  async login(provider = 'google', opts = {}){
    const mode = opts.mode || 'popup';
    const back = opts.redirectUri || location.href.split('#')[0];
    const url = this.baseUrl + '/auth/login?provider=' + encodeURIComponent(provider)
      + '&redirect_uri=' + encodeURIComponent(back) + '&mode=' + mode;
    if (mode !== 'popup'){ location.href = url; return new Promise(() => {}); }

    const w = window.open(url, 'login-login', 'width=520,height=680,menubar=no,toolbar=no');
    if (!w) throw new ClaudeGatewayError('The sign-in window was blocked. Allow popups, or use mode: "redirect".', 0, 'popup_blocked');
    return new Promise((resolve, reject) => {
      let done = false;
      const finish = (fn, arg) => {
        if (done) return;
        done = true;
        removeEventListener('message', onMsg);
        clearInterval(poll);
        fn(arg);
      };
      const onMsg = ev => {
        if (ev.origin !== new URL(this.baseUrl).origin) return;   // only our gateway may speak
        const d = ev.data;
        if (!d || d.type !== 'claude-gateway-auth') return;
        if (d.ok && d.token){ this._store(d.token); finish(resolve, d.token); }
        else finish(reject, new ClaudeGatewayError(d.error || 'Sign-in failed.', 0, 'auth_failed'));
      };
      addEventListener('message', onMsg);
      // A user who closes the window is not an error to log, but the promise
      // must settle or the caller's spinner spins forever.
      const poll = setInterval(() => {
        if (w.closed) finish(reject, new ClaudeGatewayError('Sign-in window was closed.', 0, 'auth_cancelled'));
      }, 500);
    });
  }

  /* Call once on page load. If we have just come back from a redirect-mode
     login, the token is in the fragment; take it and scrub the URL so it does
     not sit in the address bar or get shared. Returns true if it found one. */
  captureRedirect(){
    let h = '';
    try { h = location.hash || ''; } catch { return false; }
    if (!h) return false;
    const p = new URLSearchParams(h.replace(/^#/, ''));
    const t = p.get('claude_gateway_token');
    const e = p.get('claude_gateway_error');
    if (!t && !e) return false;
    if (t) this._store(t);
    p.delete('claude_gateway_token'); p.delete('claude_gateway_error');
    const rest = p.toString();
    try { history.replaceState(null, '', location.pathname + location.search + (rest ? '#' + rest : '')); } catch {}
    if (e) throw new ClaudeGatewayError(e, 0, 'auth_failed');
    return true;
  }

  /* ── Requests ───────────────────────────────────────────────────────── */
  _url(p){ return this.baseUrl + p; }
  _headers(){
    const h = { 'content-type': 'application/json', 'anthropic-version': this.version };
    if (this.token) h.authorization = 'Bearer ' + this.token;
    return h;
  }
  _body(body, opts){
    const b = { ...body };
    if (!b.model) b.model = this.model;
    if (!b.max_tokens) b.max_tokens = this.maxTokens;
    if (!b.model) throw new Error('ClaudeClient: no model given and no default set');
    if (opts && opts.cacheSystem && typeof b.system === 'string' && b.system){
      b.system = [{ type: 'text', text: b.system, cache_control: { type: 'ephemeral' } }];
    }
    return b;
  }
  /* Some hosts proxy fetch over postMessage, where an AbortSignal is not
     structured-cloneable. Retry once without it, then stop offering one. */
  async _fetchSafe(url, init, signal){
    const go = w => this._fetch(url, w && signal ? { ...init, signal } : init);
    if (this.noSignal || !signal) return go(false);
    try { return await go(true); }
    catch (e){
      if (!/clon/i.test(String((e && e.message) || e))) throw e;
      this.noSignal = true;
      return go(false);
    }
  }
  _quotaFrom(res){
    const n = h => { const v = res.headers && res.headers.get && res.headers.get(h); return v == null ? null : +v; };
    return { used: n('x-gateway-quota-used'), limit: n('x-gateway-quota-limit'),
             remaining: n('x-gateway-quota-remaining') };
  }
  async _throwForStatus(res){
    let msg = 'HTTP ' + res.status, type = 'api_error';
    try { const j = await res.json(); if (j && j.error){ msg = j.error.message || msg; type = j.error.type || type; } }
    catch {}
    const err = new ClaudeGatewayError(msg, res.status, type, { quota: this._quotaFrom(res) });
    if (res.status === 401){
      this._store(null);                       // an expired token is worse than none
      if (this.onAuthRequired) { try { this.onAuthRequired(err); } catch {} }
    }
    if (type === 'quota_exceeded' && this.onQuotaExceeded){ try { this.onQuotaExceeded(err); } catch {} }
    throw err;
  }

  async me(){
    const res = await this._fetch(this._url('/auth/me'), { headers: this._headers() });
    if (!res.ok) await this._throwForStatus(res);
    return await res.json();
  }
  async providers(){
    const res = await this._fetch(this._url('/auth/providers'));
    if (!res.ok) await this._throwForStatus(res);
    return (await res.json()).providers;
  }
  async health(){
    const res = await this._fetch(this._url('/health'));
    if (!res.ok) await this._throwForStatus(res);
    return await res.json();
  }

  async messages(body, opts = {}){
    const res = await this._fetchSafe(this._url('/v1/messages'), {
      method: 'POST', headers: this._headers(), body: JSON.stringify(this._body(body, opts)) }, opts.signal);
    if (!res.ok) await this._throwForStatus(res);
    const j = await res.json();
    Object.defineProperty(j, 'quota', { value: this._quotaFrom(res), enumerable: false });
    return j;
  }

  async stream(body, opts = {}){
    const onText = opts.onText || (() => {});
    const onEvent = opts.onEvent || (() => {});
    let full = '';
    const take = t => { if (t){ full += t; onText(t); } };
    const handleEvent = ev => {
      onEvent(ev);
      if (ev.type === 'content_block_delta' && ev.delta && ev.delta.type === 'text_delta') take(ev.delta.text);
      else if (ev.type === 'error') throw new ClaudeGatewayError(
        (ev.error && ev.error.message) || 'stream error', 0, (ev.error && ev.error.type) || 'error');
    };
    const handleLine = line => {
      if (!line.startsWith('data:')) return;
      const data = line.slice(5).trim();
      if (!data || data === '[DONE]') return;
      let ev; try { ev = JSON.parse(data); } catch { return; }
      handleEvent(ev);
    };

    const res = await this._fetchSafe(this._url('/v1/messages'), {
      method: 'POST', headers: this._headers(),
      body: JSON.stringify({ ...this._body(body, opts), stream: true }) }, opts.signal);
    if (!res.ok) await this._throwForStatus(res);
    this.lastQuota = this._quotaFrom(res);

    if (res.body && res.body.getReader){
      const rd = res.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      for (;;){
        const { done, value } = await rd.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let nl;
        while ((nl = buf.indexOf('\n')) >= 0){
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          handleLine(line);
        }
      }
      if (buf.trim()) handleLine(buf.trim());
      return full;
    }
    /* No readable stream here: either a buffered SSE transcript or, if the
       host unwrapped it, plain message JSON. */
    const text = (await res.text()).trim();
    if (text.startsWith('{')){
      let j = null;
      try { j = JSON.parse(text); } catch {}
      if (j && j.content){ take(j.content.map(b => b.text || '').join('')); return full; }
    }
    for (const raw of text.split('\n')) handleLine(raw.trim());
    return full;
  }
}

export default ClaudeClient;
if (typeof window !== 'undefined'){
  window.ClaudeClient = ClaudeClient;
  window.ClaudeGatewayError = ClaudeGatewayError;
}
