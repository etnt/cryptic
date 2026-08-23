// Cryptic Admin - front-end shell (Phase 2)
// Handles the auth flow (session check, login, logout) and section nav.
// All state-changing requests carry the CSRF token issued at login.
'use strict';

(function () {
  const state = { username: null, csrf: null };

  const el = (id) => document.getElementById(id);
  const loginView = () => el('login-view');
  const appView = () => el('app-view');

  // --- API helpers ---------------------------------------------------------

  async function api(path, { method = 'GET', body } = {}) {
    const headers = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    // Attach CSRF for state-changing methods once authenticated.
    if (method !== 'GET' && method !== 'HEAD' && state.csrf) {
      headers['X-CSRF-Token'] = state.csrf;
    }
    const res = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch (_e) { /* no body */ }
    return { ok: res.ok, status: res.status, data };
  }

  // --- Views ---------------------------------------------------------------

  function showLogin(message) {
    state.username = null;
    state.csrf = null;
    appView().hidden = true;
    loginView().hidden = false;
    const errEl = el('login-error');
    if (message) {
      errEl.textContent = message;
      errEl.hidden = false;
    } else {
      errEl.hidden = true;
    }
    el('password').value = '';
  }

  function showApp() {
    loginView().hidden = true;
    appView().hidden = false;
    el('current-user').textContent = state.username || '';
    selectSection('users');
  }

  function selectSection(name) {
    for (const btn of document.querySelectorAll('.nav-btn')) {
      btn.classList.toggle('active', btn.dataset.section === name);
    }
    for (const sec of document.querySelectorAll('.section')) {
      sec.hidden = sec.id !== `section-${name}`;
    }
  }

  // --- Auth flow -----------------------------------------------------------

  async function checkSession() {
    const { ok, data } = await api('/admin/api/session');
    if (ok && data && data.authenticated) {
      state.username = data.username;
      state.csrf = data.csrf_token;
      showApp();
    } else {
      showLogin();
    }
  }

  async function handleLogin(event) {
    event.preventDefault();
    const btn = el('login-btn');
    btn.disabled = true;
    const username = el('username').value.trim();
    const password = el('password').value;
    const { ok, status, data } = await api('/admin/api/login', {
      method: 'POST',
      body: { username, password },
    });
    btn.disabled = false;
    if (ok && data && data.status === 'ok') {
      state.username = data.username;
      state.csrf = data.csrf_token;
      showApp();
      return;
    }
    let msg = 'Sign in failed.';
    if (status === 401) msg = 'Invalid username or password.';
    else if (status === 403) msg = 'Account suspended.';
    else if (status === 429) msg = 'Too many attempts. Try again later.';
    showLogin(msg);
  }

  async function handleLogout() {
    await api('/admin/api/logout', { method: 'POST' });
    showLogin();
  }

  // --- Wire up -------------------------------------------------------------

  function init() {
    el('login-form').addEventListener('submit', handleLogin);
    el('logout-btn').addEventListener('click', handleLogout);
    for (const btn of document.querySelectorAll('.nav-btn')) {
      btn.addEventListener('click', () => selectSection(btn.dataset.section));
    }
    checkSession();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
