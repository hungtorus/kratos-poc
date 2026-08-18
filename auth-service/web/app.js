const state = { flowRef: null, totpFlowRef: null, stepupFlowRef: null };
const SESSION_KEY = 'poc_kratos_session';

function getSessionToken() {
  try { return sessionStorage.getItem(SESSION_KEY) || ''; } catch { return ''; }
}

function setSessionToken(token) {
  try {
    if (token) sessionStorage.setItem(SESSION_KEY, token);
    else sessionStorage.removeItem(SESSION_KEY);
  } catch {}
}

function apiHeaders(extra = {}) {
  const headers = { 'Content-Type': 'application/json', ...extra };
  const token = getSessionToken();
  if (token) headers['X-Session-Token'] = token;
  return headers;
}

function updateAuthBanner(session) {
  const el = document.getElementById('auth-banner');
  if (!el) return;
  if (session?.authenticated) {
    el.className = 'auth-banner auth-banner--ok';
    el.textContent = `Signed in as ${session.email || session.user_id} (AAL ${session.aal})`;
  } else {
    el.className = 'auth-banner auth-banner--fail';
    el.textContent = 'Not signed in — use the ngrok HTTPS URL (not localhost) for Google/Telegram';
  }
}

function log(msg, extra) {
  const el = document.getElementById('req-log');
  const detail = extra ? `\n${typeof extra === 'string' ? extra : JSON.stringify(extra, null, 2)}` : '';
  el.textContent = `[${new Date().toISOString()}] ${msg}${detail}\n` + el.textContent;
}

function clearLog() {
  document.getElementById('req-log').textContent = '';
}

async function api(path, opts = {}) {
  const started = performance.now();
  const res = await fetch(path, {
    credentials: 'include',
    headers: apiHeaders(opts.headers || {}),
    ...opts,
  });
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = text; }
  const ms = Math.round(performance.now() - started);
  log(`${opts.method || 'GET'} ${path} -> ${res.status} (${ms}ms)`, body);
  if (!res.ok) throw Object.assign(new Error('request failed'), { status: res.status, body });
  return body;
}

function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4;
  if (pad) s += '='.repeat(4 - pad);
  return decodeURIComponent(atob(s).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
}

function showJWT(jwt) {
  if (!jwt) { document.getElementById('jwt-view').textContent = ''; return; }
  const [h, p] = jwt.split('.');
  document.getElementById('jwt-view').textContent = JSON.stringify({
    header: JSON.parse(b64urlDecode(h)),
    payload: JSON.parse(b64urlDecode(p)),
  }, null, 2);
}

async function refreshSession() {
  const s = await api('/api/v1/session');
  if (s.session_token) setSessionToken(s.session_token);
  else if (!s.authenticated) setSessionToken('');
  updateAuthBanner(s);
  document.getElementById('session-view').textContent = JSON.stringify(s, null, 2);
  showJWT(s.jwt);
  try {
    const who = await api('/api/v1/debug/session');
    document.getElementById('whoami-view').textContent = JSON.stringify(who, null, 2);
  } catch {}
  try {
    const id = await api('/api/v1/debug/identity');
    document.getElementById('identity-view').textContent = JSON.stringify(id, null, 2);
  } catch {}
  return s;
}

async function refreshOTP() {
  const email = document.getElementById('email').value;
  if (!email) return;
  try {
    const o = await api(`/api/v1/debug/last-otp?email=${encodeURIComponent(email)}`);
    document.getElementById('last-otp').textContent = o.login_code || o.registration_code || JSON.stringify(o);
  } catch {}
}

async function refreshMethods() {
  const methods = await api('/api/v1/auth/methods');
  const ul = document.getElementById('methods-list');
  ul.innerHTML = '';
  for (const m of methods) {
    const li = document.createElement('li');
    li.textContent = `${m.type} / ${m.label}`;
    if (m.can_remove && m.type === 'oidc') {
      const btn = document.createElement('button');
      btn.textContent = 'Remove';
      btn.onclick = () => api(`/api/v1/auth/methods/oidc/${m.provider}`, { method: 'DELETE' }).then(refreshSession).then(refreshMethods);
      li.appendChild(btn);
    }
    if (m.can_remove && m.type === 'passkey' && m.credential_id) {
      const btn = document.createElement('button');
      btn.textContent = 'Remove';
      btn.onclick = () => api(`/api/v1/auth/methods/passkey/${encodeURIComponent(m.credential_id)}`, { method: 'DELETE' }).then(refreshSession).then(refreshMethods);
      li.appendChild(btn);
    }
    ul.appendChild(li);
  }
}

function redirectOIDC(url, debug) {
  log(`OIDC redirect -> ${url}`, debug);
  window.location.assign(url);
}

async function startOIDC(provider, intent) {
  const { redirect_url, debug } = await api(`/api/v1/auth/oidc/${provider}/start`, {
    method: 'POST',
    body: JSON.stringify({ intent }),
  });
  if (!redirect_url) {
    log('OIDC start missing redirect_url', debug);
    return;
  }
  redirectOIDC(redirect_url, debug);
}

function parseCreationOptions(raw) {
  if (!raw) return raw;
  if (raw.credentialOptions) return raw.credentialOptions;
  return raw;
}

function bufferToBase64URL(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64URLToBuffer(b64) {
  const pad = '='.repeat((4 - (b64.length % 4)) % 4);
  const bin = atob((b64 + pad).replace(/-/g, '+').replace(/_/g, '/'));
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

function prepOptions(opts, forCreate) {
  const o = structuredClone(opts);
  if (o.challenge) o.challenge = base64URLToBuffer(o.challenge);
  if (o.user && o.user.id) o.user.id = base64URLToBuffer(o.user.id);
  if (!forCreate && o.allowCredentials) {
    o.allowCredentials = o.allowCredentials.map(c => ({ ...c, id: base64URLToBuffer(c.id) }));
  }
  return o;
}

function credToJSON(cred) {
  const r = {
    id: cred.id,
    rawId: bufferToBase64URL(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToBase64URL(cred.response.clientDataJSON),
    },
    clientExtensionResults: cred.getClientExtensionResults?.() || {},
  };
  if (cred.response.attestationObject) {
    r.response.attestationObject = bufferToBase64URL(cred.response.attestationObject);
  }
  if (cred.response.authenticatorData) {
    r.response.authenticatorData = bufferToBase64URL(cred.response.authenticatorData);
  }
  if (cred.response.signature) {
    r.response.signature = bufferToBase64URL(cred.response.signature);
  }
  if (cred.response.userHandle) {
    r.response.userHandle = bufferToBase64URL(cred.response.userHandle);
  }
  return r;
}

async function startEmailOTP(intent) {
  const email = document.getElementById('email').value;
  const r = await api('/api/v1/auth/email-otp/start', { method: 'POST', body: JSON.stringify({ email, intent }) });
  state.flowRef = r.flow_ref;
  setTimeout(refreshOTP, 800);
}

document.getElementById('btn-email-register').onclick = () => startEmailOTP('register');
document.getElementById('btn-email-start').onclick = () => startEmailOTP('login');

document.getElementById('btn-email-verify').onclick = async () => {
  await api('/api/v1/auth/email-otp/verify', {
    method: 'POST',
    body: JSON.stringify({ flow_ref: state.flowRef, code: document.getElementById('otp').value }),
  });
  await refreshSession();
};

document.getElementById('btn-passkey-register').onclick = async () => {
  const email = document.getElementById('email').value;
  const { flow_ref, creation_options } = await api('/api/v1/auth/passkey/register/start', {
    method: 'POST', body: JSON.stringify({ email }),
  });
  const opts = prepOptions(parseCreationOptions(creation_options), true);
  const cred = await navigator.credentials.create({ publicKey: opts });
  await api('/api/v1/auth/passkey/register/finish', {
    method: 'POST',
    body: JSON.stringify({ flow_ref, email, credential: JSON.stringify(credToJSON(cred)) }),
  });
  await refreshSession();
};

document.getElementById('btn-passkey-login').onclick = async () => {
  const { flow_ref, request_options } = await api('/api/v1/auth/passkey/login/start', { method: 'POST', body: '{}' });
  const opts = prepOptions(parseCreationOptions(request_options), false);
  const cred = await navigator.credentials.get({ publicKey: opts });
  await api('/api/v1/auth/passkey/login/finish', {
    method: 'POST',
    body: JSON.stringify({ flow_ref, credential: JSON.stringify(credToJSON(cred)) }),
  });
  await refreshSession();
};

document.getElementById('btn-google-login').onclick = () => startOIDC('google', 'login');
document.getElementById('btn-google-register').onclick = () => startOIDC('google', 'register');
document.getElementById('btn-telegram-login').onclick = () => startOIDC('telegram', 'login');
document.getElementById('btn-telegram-register').onclick = () => startOIDC('telegram', 'register');
document.getElementById('btn-link-google').onclick = () => startOIDC('google', 'link');
document.getElementById('btn-link-telegram').onclick = () => startOIDC('telegram', 'link');

document.getElementById('btn-add-passkey').onclick = async () => {
  const { flow_ref, creation_options } = await api('/api/v1/auth/methods/passkey/start', { method: 'POST', body: '{}' });
  const opts = prepOptions(parseCreationOptions(creation_options), true);
  const cred = await navigator.credentials.create({ publicKey: opts });
  await api('/api/v1/auth/methods/passkey/finish', {
    method: 'POST',
    body: JSON.stringify({ flow_ref, credential: JSON.stringify(credToJSON(cred)) }),
  });
  await refreshSession();
  await refreshMethods();
};

document.getElementById('btn-totp-start').onclick = async () => {
  const r = await api('/api/v1/auth/2fa/totp/start', { method: 'POST', body: '{}' });
  state.totpFlowRef = r.flow_ref;
  document.getElementById('totp-secret').textContent = 'Secret: ' + r.secret;
  document.getElementById('totp-qr').src = r.qr_data_uri || '';
};

document.getElementById('btn-totp-confirm').onclick = async () => {
  await api('/api/v1/auth/2fa/totp/confirm', {
    method: 'POST',
    body: JSON.stringify({ flow_ref: state.totpFlowRef, code: document.getElementById('totp-code').value }),
  });
  await refreshSession();
};

document.getElementById('btn-totp-delete').onclick = async () => {
  await api('/api/v1/auth/2fa/totp', { method: 'DELETE' });
  await refreshSession();
};

document.getElementById('btn-stepup-aal2').onclick = async () => {
  const r = await api('/api/v1/auth/stepup/aal2/start', { method: 'POST', body: '{}' });
  state.stepupFlowRef = r.flow_ref;
};

document.getElementById('btn-stepup-refresh').onclick = async () => {
  await api('/api/v1/auth/stepup/refresh/start', { method: 'POST', body: '{}' });
};

document.getElementById('totp-code').addEventListener('keydown', async (e) => {
  if (e.key === 'Enter' && state.stepupFlowRef) {
    await api('/api/v1/auth/stepup/aal2/totp', {
      method: 'POST',
      body: JSON.stringify({ flow_ref: state.stepupFlowRef, code: document.getElementById('totp-code').value }),
    });
    await refreshSession();
  }
});

document.getElementById('btn-session').onclick = refreshSession;
document.getElementById('btn-refresh-methods').onclick = refreshMethods;
document.getElementById('btn-clear-log').onclick = clearLog;
document.getElementById('btn-logout').onclick = async () => {
  await api('/api/v1/auth/logout', { method: 'POST', body: '{}' });
  setSessionToken('');
  await refreshSession();
};
document.getElementById('btn-delete').onclick = async () => {
  if (!confirm('Delete account?')) return;
  await api('/api/v1/auth/account', { method: 'DELETE' });
  await refreshSession();
};

refreshSession().catch(() => {});
refreshMethods().catch(() => {});
const qs = new URLSearchParams(location.search);
if (qs.get('oidc') === 'ok') {
  log('OIDC return succeeded — session token saved, refreshing…');
  api('/api/v1/debug/auth-state')
    .then((state) => log('post-oidc auth-state', state))
    .catch(() => {});
  refreshSession()
    .then((s) => {
      if (s.authenticated) log('Google/Telegram sign-in complete', { user_id: s.user_id, email: s.email });
      else log('OIDC finished but session still unauthenticated — check token in Application → Session Storage');
      history.replaceState({}, '', '/');
    });
}
if (qs.get('oidc_error')) {
  log(`OIDC error: ${qs.get('oidc_error')}`, Object.fromEntries(qs.entries()));
  api('/api/v1/debug/auth-state').then((state) => log('auth-state after oidc error', state)).catch(() => {});
  history.replaceState({}, '', '/');
}
if (qs.get('oidc') === 'linked') {
  log('OIDC provider linked');
  refreshSession().then(refreshMethods).then(() => history.replaceState({}, '', '/'));
}
