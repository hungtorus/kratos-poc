const state = { flowRef: null, linkEmailFlowRef: null, totpFlowRef: null, stepupFlowRef: null, stepupEmailFlowRef: null, session: null };
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
    const who = session.email || session.username || session.user_id;
    el.textContent = `Signed in as ${who} (AAL ${session.aal})`;
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
  state.session = s.authenticated ? s : null;
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

function otpCodeFromPayload(o) {
  if (!o || !Object.keys(o).length) return '';
  return o.code || o.login_code || o.verification_code || o.registration_code || o.recovery_code || '';
}

async function fetchLastOTP({ email, latest = false } = {}) {
  const params = new URLSearchParams();
  if (email) params.set('email', email);
  if (latest) params.set('latest', '1');
  const res = await fetch(`/api/v1/debug/last-otp?${params}`, { credentials: 'include' });
  return res.json();
}

function showOTPIn(elId, o, inputId) {
  const el = document.getElementById(elId);
  if (!el) return;
  const code = otpCodeFromPayload(o);
  const type = o?.code_type ? ` (${o.code_type})` : '';
  const who = o?.recipient ? ` → ${o.recipient}` : '';
  el.textContent = code ? `${code}${type}${who}` : '-';
  if (code && inputId) {
    const input = document.getElementById(inputId);
    if (input && !input.value) input.placeholder = code;
  }
}

async function refreshOTP() {
  const email = document.getElementById('email')?.value?.trim();
  try {
    const o = email
      ? await fetchLastOTP({ email })
      : await fetchLastOTP({ latest: true });
    showOTPIn('last-otp', o);
  } catch {}
}

async function refreshLinkOTP(emailOverride) {
  const email = emailOverride || document.getElementById('link-email')?.value?.trim();
  try {
    const o = email
      ? await fetchLastOTP({ email })
      : await fetchLastOTP({ latest: true });
    showOTPIn('link-last-otp', o, 'link-otp');
  } catch {}
}

async function refreshStepUpOTP(emailOverride) {
  const email = emailOverride || stepUpEmail();
  try {
    const o = email
      ? await fetchLastOTP({ email })
      : await fetchLastOTP({ latest: true });
    showOTPIn('stepup-last-otp', o, 'stepup-otp');
    const code = otpCodeFromPayload(o);
    if (code) showOTPIn('last-otp', o);
  } catch {}
}

function pollLinkOTP(email, times = 10) {
  let n = 0;
  const tick = () => {
    refreshLinkOTP(email);
    if (++n < times) setTimeout(tick, 1200);
  };
  setTimeout(tick, 400);
}

function pollStepUpOTP(email, times = 10) {
  let n = 0;
  const tick = () => {
    refreshStepUpOTP(email);
    if (++n < times) setTimeout(tick, 1200);
  };
  setTimeout(tick, 400);
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
  // Kratos registration wraps options; login returns publicKey at top level.
  if (raw.credentialOptions?.publicKey) return raw.credentialOptions.publicKey;
  if (raw.publicKey) return raw.publicKey;
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

function prepOptions(opts, forCreate, displayName) {
  const o = structuredClone(opts);
  if (o.challenge) o.challenge = base64URLToBuffer(o.challenge);
  if (o.user?.id) o.user.id = base64URLToBuffer(o.user.id);
  if (forCreate && displayName && o.user) {
    o.user.name = displayName;
    o.user.displayName = displayName;
  }
  if (!forCreate && o.allowCredentials) {
    o.allowCredentials = o.allowCredentials.map(c => ({ ...c, id: base64URLToBuffer(c.id) }));
  }
  return o;
}

function encodeBufferField(value) {
  if (value == null) return '';
  return bufferToBase64URL(value);
}

function credCreateToJSON(cred) {
  return {
    id: cred.id,
    rawId: encodeBufferField(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: encodeBufferField(cred.response.attestationObject),
      clientDataJSON: encodeBufferField(cred.response.clientDataJSON),
    },
    clientExtensionResults: cred.getClientExtensionResults?.() || {},
  };
}

function credGetToJSON(cred) {
  // Match Kratos webauthn.js: login lookup uses response.userHandle.
  return {
    id: cred.id,
    rawId: encodeBufferField(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: encodeBufferField(cred.response.authenticatorData),
      clientDataJSON: encodeBufferField(cred.response.clientDataJSON),
      signature: encodeBufferField(cred.response.signature),
      userHandle: encodeBufferField(cred.response.userHandle),
    },
    clientExtensionResults: cred.getClientExtensionResults?.() || {},
  };
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

async function runPasskeyCreate(startPath, finishPath, finishBody) {
  const start = await api(startPath, { method: 'POST', body: finishBody?.startBody ?? '{}' });
  const rawOpts = start.creation_options || start.request_options;
  const opts = prepOptions(parseCreationOptions(rawOpts), true, finishBody?.displayName);
  const cred = await navigator.credentials.create({ publicKey: opts });
  await api(finishPath, {
    method: 'POST',
    body: JSON.stringify({ flow_ref: start.flow_ref, ...finishBody?.extra, credential: credCreateToJSON(cred) }),
  });
  await refreshSession();
}

async function runPasskeyGet(startPath, finishPath) {
  const start = await api(startPath, { method: 'POST', body: '{}' });
  const opts = prepOptions(parseCreationOptions(start.request_options), false);
  const cred = await navigator.credentials.get({ publicKey: opts });
  const payload = credGetToJSON(cred);
  if (!payload.response.userHandle) {
    log('Passkey login warning', 'WebAuthn response missing userHandle — pick the passkey you just registered for this site.');
  }
  await api(finishPath, {
    method: 'POST',
    body: JSON.stringify({ flow_ref: start.flow_ref, credential: payload }),
  });
  await refreshSession();
}

document.getElementById('btn-passkey-register').onclick = async () => {
  try {
    if (state.session?.authenticated) {
      log('Register passkey skipped', 'Already signed in — use Linked methods → Add passkey to attach Touch ID to this account (same user_id as Google).');
      return;
    }
    const username = document.getElementById('username').value.trim();
    const displayName = username || 'Passkey user';
    await runPasskeyCreate(
      '/api/v1/auth/passkey/register/start',
      '/api/v1/auth/passkey/register/finish',
      {
        startBody: JSON.stringify({ username }),
        extra: { username },
        displayName,
      },
    );
    await refreshMethods();
  } catch (err) {
    log('Passkey register failed', err.body || err.message || String(err));
  }
};

document.getElementById('btn-passkey-login').onclick = async () => {
  try {
    await runPasskeyGet('/api/v1/auth/passkey/login/start', '/api/v1/auth/passkey/login/finish');
  } catch (err) {
    const body = err.body || {};
    const msg = body.messages?.[0] || body.flow?.ui?.messages?.[0]?.text || body.error || err.message || String(err);
    log('Passkey login failed', msg.includes('security key') || msg.includes('does not exist')
      ? `${msg} — pick the passkey you registered on this ngrok URL, not an older one.`
      : body);
  }
};

document.getElementById('btn-google-login').onclick = () => startOIDC('google', 'login');
document.getElementById('btn-google-register').onclick = () => startOIDC('google', 'register');
document.getElementById('btn-telegram-login').onclick = () => startOIDC('telegram', 'login');
document.getElementById('btn-telegram-register').onclick = () => startOIDC('telegram', 'register');
document.getElementById('btn-link-google').onclick = () => startOIDC('google', 'link');
document.getElementById('btn-link-telegram').onclick = () => startOIDC('telegram', 'link');

document.getElementById('btn-add-passkey').onclick = async () => {
  try {
    const s = state.session || await refreshSession();
    if (!s?.authenticated) {
      log('Add passkey failed', 'Sign in first (e.g. Google), then Add passkey links Touch ID to that same account.');
      return;
    }
    const displayName = s.username || s.email || s.google_email || 'Account';
    await runPasskeyCreate('/api/v1/auth/methods/passkey/start', '/api/v1/auth/methods/passkey/finish', { displayName });
    await refreshSession();
    await refreshMethods();
    log('Passkey added', `Linked to user ${s.user_id} — same identity as ${(s.linked_methods || []).join(', ')}.`);
  } catch (err) {
    log('Add passkey failed', err.body || err.message || String(err));
  }
};

document.getElementById('btn-link-email-otp').onclick = async () => {
  try {
    const s = state.session || await refreshSession();
    if (!s?.authenticated) {
      log('Link email OTP failed', 'Sign in first, then link email OTP.');
      return;
    }
    const email = document.getElementById('link-email').value.trim();
    if (!email) {
      log('Link email OTP failed', 'Enter your email in the “Email to link” field in Linked methods.');
      return;
    }
    const r = await api('/api/v1/auth/methods/email-otp/start', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
    state.linkEmailFlowRef = r.flow_ref;
    log('Email OTP link started — enter the code below (verification_code)', r);
    pollLinkOTP(r.email || email);
  } catch (err) {
    log('Link email OTP failed', err.body || err.message || String(err));
  }
};

document.getElementById('btn-link-email-verify').onclick = async () => {
  try {
    const code = document.getElementById('link-otp').value.trim();
    if (!state.linkEmailFlowRef) {
      log('Verify link OTP failed', 'Click Link email OTP first.');
      return;
    }
    if (!code) {
      log('Verify link OTP failed', 'Enter the OTP code in the field above Verify link OTP.');
      return;
    }
    await api('/api/v1/auth/methods/email-otp/verify', {
      method: 'POST',
      body: JSON.stringify({ flow_ref: state.linkEmailFlowRef, code }),
    });
    state.linkEmailFlowRef = null;
    document.getElementById('link-otp').value = '';
    await refreshSession();
    await refreshMethods();
    log('Email OTP linked');
  } catch (err) {
    log('Verify link OTP failed', err.body || err.message || String(err));
  }
};

document.getElementById('btn-totp-start').onclick = async () => {
  try {
    const r = await api('/api/v1/auth/2fa/totp/start', { method: 'POST', body: '{}' });
    state.totpFlowRef = r.flow_ref;
    document.getElementById('totp-secret').textContent = 'Secret: ' + r.secret;
    document.getElementById('totp-qr').src = r.qr_data_uri || '';
    document.getElementById('totp-qr').alt = 'TOTP QR code';
    log('TOTP enrollment started — scan QR or enter secret in your authenticator app, then Confirm.');
  } catch (err) {
    log('TOTP enroll failed', err.body || err.message || String(err));
  }
};

document.getElementById('btn-totp-confirm').onclick = async () => {
  try {
    await api('/api/v1/auth/2fa/totp/confirm', {
      method: 'POST',
      body: JSON.stringify({ flow_ref: state.totpFlowRef, code: document.getElementById('totp-code').value }),
    });
    await refreshSession();
    await refreshMethods();
    log('TOTP enrolled — session is now AAL2 when you use the authenticator code.');
  } catch (err) {
    log('TOTP confirm failed', err.body || err.message || String(err));
  }
};

document.getElementById('btn-totp-delete').onclick = async () => {
  try {
    await api('/api/v1/auth/2fa/totp', { method: 'DELETE' });
    await refreshSession();
    await refreshMethods();
    document.getElementById('totp-secret').textContent = '';
    document.getElementById('totp-qr').src = '';
    log('TOTP removed');
  } catch (err) {
    log('TOTP remove failed', err.body || err.message || String(err));
  }
};

document.getElementById('btn-stepup-passkey').onclick = async () => {
  try {
    const start = await api('/api/v1/auth/stepup/passkey/start', { method: 'POST', body: '{}' });
    const opts = prepOptions(parseCreationOptions(start.request_options), false);
    const cred = await navigator.credentials.get({ publicKey: opts });
    await api('/api/v1/auth/stepup/passkey/finish', {
      method: 'POST',
      body: JSON.stringify({ flow_ref: start.flow_ref, credential: credGetToJSON(cred) }),
    });
    const s = await refreshSession();
    log('Passkey step-up complete', { methods_used: s.methods_used, aal: s.aal, hint: start.hint });
  } catch (err) {
    log('Passkey step-up failed', err.body || err.message || String(err));
  }
};

document.getElementById('btn-stepup-google').onclick = async () => {
  try {
    const s = state.session || await refreshSession();
    if (!s?.authenticated) {
      log('Google step-up failed', 'Sign in first.');
      return;
    }
    const { redirect_url, debug, hint } = await api('/api/v1/auth/stepup/google/start', { method: 'POST', body: '{}' });
    if (!redirect_url) {
      log('Google step-up failed', debug || 'no redirect_url');
      return;
    }
    log('Google step-up redirect', { hint, debug });
    redirectOIDC(redirect_url, debug);
  } catch (err) {
    log('Google step-up failed', err.body || err.message || String(err));
  }
};

function stepUpEmail() {
  return document.getElementById('link-email')?.value?.trim()
    || document.getElementById('email')?.value?.trim()
    || state.session?.email
    || '';
}

document.getElementById('btn-stepup-email-otp').onclick = async () => {
  try {
    const s = state.session || await refreshSession();
    if (!s?.authenticated) {
      log('Email OTP step-up failed', 'Sign in first.');
      return;
    }
    const email = stepUpEmail();
    const body = email ? JSON.stringify({ email }) : '{}';
    const start = await api('/api/v1/auth/stepup/email-otp/start', { method: 'POST', body });
    state.stepupEmailFlowRef = start.flow_ref;
    if (start.email) {
      document.getElementById('link-email').value = start.email;
      document.getElementById('email').value = start.email;
    }
    log('Email OTP step-up started — OTP is login_code (not verification_code)', start);
    pollStepUpOTP(start.email);
  } catch (err) {
    log('Email OTP step-up failed', err.body || err.message || String(err));
  }
};

document.getElementById('btn-stepup-email-verify').onclick = async () => {
  try {
    const code = document.getElementById('stepup-otp').value.trim()
      || document.getElementById('link-otp').value.trim()
      || document.getElementById('otp').value.trim();
    if (!state.stepupEmailFlowRef) {
      log('Email OTP step-up verify failed', 'Click Step up email OTP first.');
      return;
    }
    if (!code) {
      log('Email OTP step-up verify failed', 'Enter the OTP code.');
      return;
    }
    await api('/api/v1/auth/stepup/email-otp/verify', {
      method: 'POST',
      body: JSON.stringify({ flow_ref: state.stepupEmailFlowRef, code }),
    });
    state.stepupEmailFlowRef = null;
    document.getElementById('stepup-otp').value = '';
    const s = await refreshSession();
    log('Email OTP step-up complete', { methods_used: s.methods_used, aal: s.aal });
  } catch (err) {
    log('Email OTP step-up verify failed', err.body || err.message || String(err));
  }
};

async function submitStepUpTOTP() {
  if (!state.stepupFlowRef) {
    log('TOTP step-up', 'Click “Step up to AAL2 (TOTP)” first.');
    return;
  }
  await api('/api/v1/auth/stepup/aal2/totp', {
    method: 'POST',
    body: JSON.stringify({ flow_ref: state.stepupFlowRef, code: document.getElementById('totp-code').value }),
  });
  state.stepupFlowRef = null;
  const s = await refreshSession();
  log('AAL2 step-up complete', { aal: s.aal, methods_used: s.methods_used });
}

document.getElementById('btn-stepup-aal2').onclick = async () => {
  try {
    const r = await api('/api/v1/auth/stepup/aal2/start', { method: 'POST', body: '{}' });
    state.stepupFlowRef = r.flow_ref;
    log('AAL2 step-up started', 'Enter the 6-digit code from your authenticator app, then Submit TOTP step-up.');
  } catch (err) {
    log('AAL2 step-up start failed', err.body || err.message || String(err));
  }
};

document.getElementById('btn-stepup-aal2-submit').onclick = async () => {
  try {
    await submitStepUpTOTP();
  } catch (err) {
    log('AAL2 step-up failed', err.body || err.message || String(err));
  }
};

document.getElementById('btn-stepup-refresh').onclick = async () => {
  await api('/api/v1/auth/stepup/refresh/start', { method: 'POST', body: '{}' });
};

document.getElementById('btn-policy-demo').onclick = async () => {
  try {
    const r = await api('/api/v1/policy/demo-sensitive', { method: 'POST', body: '{}' });
    log('Demo policy OK', r);
  } catch (err) {
    log('Demo policy denied', err.body || err.message || String(err));
  }
};

document.getElementById('totp-code').addEventListener('keydown', async (e) => {
  if (e.key === 'Enter' && state.stepupFlowRef) {
    try {
      await submitStepUpTOTP();
    } catch (err) {
      log('AAL2 step-up failed', err.body || err.message || String(err));
    }
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
if (qs.get('oidc') === 'stepup') {
  log('Google step-up return succeeded — refreshing session…');
  refreshSession()
    .then((s) => {
      if (s.authenticated) {
        log('Google step-up complete', { methods_used: s.methods_used, aal: s.aal, user_id: s.user_id });
      } else {
        log('Google step-up finished but session unauthenticated');
      }
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
