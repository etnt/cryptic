// Cryptic Admin - front-end
// Handles the auth flow (session check, login, logout), section nav, and the
// user / enrollment / audit administration views, including mobile enrollment
// package creation with client-side QR rendering. All state-changing requests
// carry the CSRF token issued at login.
'use strict';

(function () {
  const state = { username: null, csrf: null, currentUserFp: null };

  const el = (id) => document.getElementById(id);
  const loginView = () => el('login-view');
  const appView = () => el('app-view');

  // --- Utilities -----------------------------------------------------------

  function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function fmtTime(epochSeconds) {
    if (!epochSeconds) return '—';
    const d = new Date(epochSeconds * 1000);
    if (Number.isNaN(d.getTime())) return String(epochSeconds);
    return d.toLocaleString();
  }

  function shortFp(fp) {
    if (!fp) return '—';
    return fp.length > 16 ? `${fp.slice(0, 8)}…${fp.slice(-8)}` : fp;
  }

  function statusBadge(status) {
    const s = escapeHtml(status || 'unknown');
    return `<span class="badge badge-${s}">${s}</span>`;
  }

  function onlineDot(online) {
    return online
      ? '<span class="dot dot-on" title="Online">●</span>'
      : '<span class="dot dot-off" title="Offline">●</span>';
  }

  function setMsg(id, text, kind) {
    const node = el(id);
    if (!text) {
      node.hidden = true;
      node.textContent = '';
      return;
    }
    node.textContent = text;
    node.className = `msg${kind ? ` msg-${kind}` : ''}`;
    node.hidden = false;
  }

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
    if (res.status === 401 && state.csrf) {
      // Session expired mid-session: bounce to login.
      showLogin('Session expired. Please sign in again.');
    }
    return { ok: res.ok, status: res.status, data };
  }

  // --- Views ---------------------------------------------------------------

  function showLogin(message) {
    state.username = null;
    state.csrf = null;
    closeDrawer();
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
    if (name === 'users') loadUsers();
    else if (name === 'enrollments') loadEnrollments();
    else if (name === 'audit') loadAudit();
  }

  // --- Users ---------------------------------------------------------------

  async function loadUsers() {
    setMsg('users-msg', 'Loading…');
    const filter = el('users-filter').value;
    const qs = filter ? `?status=${encodeURIComponent(filter)}` : '';
    const { ok, data } = await api(`/admin/api/users${qs}`);
    if (!ok || !data || data.status !== 'ok') {
      setMsg('users-msg', (data && data.message) || 'Failed to load users.', 'error');
      return;
    }
    setMsg('users-msg', null);
    renderUsers(data.users || []);
  }

  function renderUsers(users) {
    const tbody = el('users-tbody');
    if (users.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty">No users.</td></tr>';
      return;
    }
    tbody.innerHTML = users.map((u) => `
      <tr class="row" data-fp="${escapeHtml(u.gpg_fp)}">
        <td>${escapeHtml(u.username || 'unknown')}</td>
        <td>${statusBadge(u.status)}</td>
        <td>${onlineDot(u.online)}</td>
        <td>${escapeHtml(fmtTime(u.registered_at))}</td>
        <td class="mono">${escapeHtml(shortFp(u.gpg_fp))}</td>
      </tr>`).join('');
    for (const row of tbody.querySelectorAll('.row')) {
      row.addEventListener('click', () => openUserDrawer(row.dataset.fp));
    }
  }

  async function openUserDrawer(fp) {
    state.currentUserFp = fp;
    el('drawer-title').textContent = 'User';
    el('drawer-body').innerHTML = '<p class="msg">Loading…</p>';
    el('drawer-actions').innerHTML = '';
    openDrawer();

    const [userRes, certRes] = await Promise.all([
      api(`/admin/api/users/${encodeURIComponent(fp)}`),
      api(`/admin/api/users/${encodeURIComponent(fp)}/certs`),
    ]);

    if (!userRes.ok || !userRes.data || userRes.data.status !== 'ok') {
      el('drawer-body').innerHTML =
        `<p class="msg msg-error">${escapeHtml(
          (userRes.data && userRes.data.message) || 'Failed to load user.')}</p>`;
      return;
    }

    const u = userRes.data.user || {};
    const certs = (certRes.ok && certRes.data && certRes.data.certificates) || [];
    el('drawer-title').textContent = u.username || 'User';

    const rows = [
      ['Fingerprint', `<span class="mono">${escapeHtml(u.gpg_fp)}</span>`],
      ['Status', statusBadge(u.status)],
      ['Registered by', escapeHtml(u.registered_by || '—')],
      ['Registered at', escapeHtml(fmtTime(u.registered_at))],
      ['Last seen', escapeHtml(u.last_seen ? fmtTime(u.last_seen) : '—')],
    ];
    const certRows = certs.length === 0
      ? '<p class="msg">No certificates.</p>'
      : `<table class="grid mini"><thead><tr>
           <th>Serial</th><th>Status</th><th>Issued</th><th>Expires</th>
         </tr></thead><tbody>${certs.map((c) => `
           <tr>
             <td class="mono">${escapeHtml(shortFp(c.serial))}</td>
             <td>${statusBadge(c.status)}</td>
             <td>${escapeHtml(fmtTime(c.issued_at))}</td>
             <td>${escapeHtml(fmtTime(c.expires_at))}</td>
           </tr>`).join('')}</tbody></table>`;

    el('drawer-body').innerHTML = `
      <dl class="detail">${rows.map(([k, v]) =>
        `<dt>${escapeHtml(k)}</dt><dd>${v}</dd>`).join('')}</dl>
      <h4>Certificates</h4>${certRows}`;

    renderUserActions(u.status);
  }

  function renderUserActions(status) {
    const actions = el('drawer-actions');
    const buttons = [];
    if (status === 'active') {
      buttons.push('<button class="danger" data-action="suspend">Suspend</button>');
      buttons.push('<button class="danger" data-action="revoke">Revoke</button>');
    } else if (status === 'suspended') {
      buttons.push('<button data-action="reactivate">Reactivate</button>');
      buttons.push('<button class="danger" data-action="revoke">Revoke</button>');
    }
    // Revoked users are terminal: no actions.
    actions.innerHTML = buttons.join('');
    for (const btn of actions.querySelectorAll('button')) {
      btn.addEventListener('click', () => performUserAction(btn.dataset.action));
    }
  }

  async function performUserAction(action) {
    const fp = state.currentUserFp;
    if (!fp) return;
    const labels = { suspend: 'suspend', revoke: 'revoke', reactivate: 'reactivate' };
    const verb = labels[action] || action;

    let body;
    if (action === 'suspend' || action === 'revoke') {
      const reason = window.prompt(
        `Reason to ${verb} this user (optional):`, '');
      if (reason === null) return; // cancelled
      body = { reason: reason || 'No reason provided' };
    } else {
      if (!window.confirm('Reactivate this user?')) return;
    }

    const { ok, data } = await api(
      `/admin/api/users/${encodeURIComponent(fp)}/${action}`,
      { method: 'POST', body });

    if (ok && data && data.status === 'ok') {
      await openUserDrawer(fp); // refresh drawer
      loadUsers();              // refresh table underneath
    } else {
      const msg = (data && data.message) || `Failed to ${verb} user.`;
      window.alert(msg);
    }
  }

  // --- Enrollments ---------------------------------------------------------

  async function loadEnrollments() {
    setMsg('enroll-msg', 'Loading…');
    const filter = el('enroll-filter').value;
    const qs = filter ? `?status=${encodeURIComponent(filter)}` : '';
    const { ok, data } = await api(`/admin/api/enrollments${qs}`);
    if (!ok || !data || data.status !== 'ok') {
      setMsg('enroll-msg',
        (data && data.message) || 'Failed to load enrollments.', 'error');
      return;
    }
    setMsg('enroll-msg', null);
    renderEnrollments(data.enrollments || []);
  }

  function renderEnrollments(items) {
    const tbody = el('enroll-tbody');
    if (items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty">No enrollments.</td></tr>';
      return;
    }
    tbody.innerHTML = items.map((e) => `
      <tr>
        <td>${escapeHtml(e.username || '—')}</td>
        <td>${statusBadge(e.status)}</td>
        <td>${escapeHtml(fmtTime(e.registered_at))}</td>
        <td>${escapeHtml(e.consumed_at ? fmtTime(e.consumed_at) : '—')}</td>
        <td class="mono">${escapeHtml(shortFp(e.enrollment_fp))}</td>
      </tr>`).join('');
  }

  // --- Enrollment creation modal -------------------------------------------

  const enrollModalState = { lastPackage: null };

  function openEnrollModal() {
    const form = el('enroll-form');
    form.reset();
    el('enroll-expiry').value = '365';
    form.hidden = false;
    el('enroll-result').hidden = true;
    el('enroll-form-error').hidden = true;
    el('enroll-qr').innerHTML = '';
    enrollModalState.lastPackage = null;
    el('enroll-modal').hidden = false;
    el('enroll-username').focus();
  }

  function closeEnrollModal() {
    el('enroll-modal').hidden = true;
    el('enroll-qr').innerHTML = '';
    enrollModalState.lastPackage = null;
  }

  function setEnrollError(text) {
    const node = el('enroll-form-error');
    if (!text) { node.hidden = true; node.textContent = ''; return; }
    node.textContent = text;
    node.hidden = false;
  }

  function renderQr(container, text) {
    container.innerHTML = '';
    // typeNumber 0 = auto-size; 'L' error correction maximises data capacity.
    const qr = qrcode(0, 'L');
    qr.addData(text);
    qr.make();
    // 4 px per module, 8 px quiet-zone margin; crisp <img> data URL.
    container.innerHTML = qr.createImgTag(4, 8, 'Enrollment QR code');
  }

  async function handleEnrollSubmit(event) {
    event.preventDefault();
    setEnrollError(null);
    const submitBtn = el('enroll-submit');
    submitBtn.disabled = true;

    const body = {
      username: el('enroll-username').value.trim(),
      passphrase: el('enroll-passphrase').value,
    };
    const fullName = el('enroll-fullname').value.trim();
    const email = el('enroll-email').value.trim();
    if (fullName) body.full_name = fullName;
    if (email) body.email = email;
    const days = parseInt(el('enroll-expiry').value, 10);
    if (Number.isFinite(days) && days > 0) {
      body.expiry_seconds = days * 86400;
    }

    let res;
    try {
      res = await api('/admin/api/enrollments', { method: 'POST', body });
    } finally {
      submitBtn.disabled = false;
    }

    const { ok, data } = res;
    if (!ok || !data || data.status !== 'ok') {
      setEnrollError(enrollErrorText(data));
      return;
    }

    enrollModalState.lastPackage = data.package;
    el('enroll-result-user').textContent = data.username || body.username;
    el('enroll-result-fp').textContent = data.enrollment_fp || '—';
    el('enroll-result-expiry').textContent = fmtTime(data.expires_at);
    try {
      renderQr(el('enroll-qr'), data.package);
    } catch (_e) {
      el('enroll-qr').innerHTML =
        '<p class="msg msg-error">Package too large to render as QR. ' +
        'Use “Copy package” instead.</p>';
    }
    el('enroll-form').hidden = true;
    el('enroll-result').hidden = false;
    loadEnrollments(); // refresh the table underneath
  }

  function enrollErrorText(data) {
    const msg = data && data.message;
    switch (msg) {
      case 'username_required': return 'A username is required.';
      case 'passphrase_too_short':
        return 'Passphrase must be at least 8 characters.';
      case 'enrollment_failed':
        return 'Server failed to create the enrollment. Check server logs.';
      default: return (msg && String(msg)) || 'Failed to create enrollment.';
    }
  }

  async function copyEnrollPackage() {
    const pkg = enrollModalState.lastPackage;
    if (!pkg) return;
    const btn = el('enroll-copy');
    try {
      await navigator.clipboard.writeText(pkg);
      const original = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = original; }, 1500);
    } catch (_e) {
      window.prompt('Copy the enrollment package:', pkg);
    }
  }

  // --- Audit ---------------------------------------------------------------

  async function loadAudit() {
    setMsg('audit-msg', 'Loading…');
    const { ok, data } = await api('/admin/api/audit?limit=100');
    if (!ok || !data || data.status !== 'ok') {
      setMsg('audit-msg',
        (data && data.message) || 'Failed to load audit log.', 'error');
      return;
    }
    setMsg('audit-msg', null);
    renderAudit(data.entries || []);
  }

  function renderAudit(entries) {
    const tbody = el('audit-tbody');
    if (entries.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty">No audit entries.</td></tr>';
      return;
    }
    tbody.innerHTML = entries.map((e) => {
      let details = e.details;
      if (details && typeof details === 'object') {
        details = JSON.stringify(details);
      }
      return `
        <tr>
          <td>${escapeHtml(fmtTime(e.timestamp))}</td>
          <td>${escapeHtml(e.event_type)}</td>
          <td class="mono">${escapeHtml(shortFp(e.gpg_fp))}</td>
          <td class="mono">${escapeHtml(e.ip_address || '—')}</td>
          <td class="details">${escapeHtml(details || '—')}</td>
        </tr>`;
    }).join('');
  }

  // --- Drawer --------------------------------------------------------------

  function openDrawer() { el('drawer').hidden = false; }
  function closeDrawer() {
    const d = el('drawer');
    if (d) d.hidden = true;
    state.currentUserFp = null;
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
    el('users-refresh').addEventListener('click', loadUsers);
    el('users-filter').addEventListener('change', loadUsers);
    el('enroll-refresh').addEventListener('click', loadEnrollments);
    el('enroll-filter').addEventListener('change', loadEnrollments);
    el('enroll-create').addEventListener('click', openEnrollModal);
    el('enroll-form').addEventListener('submit', handleEnrollSubmit);
    el('enroll-copy').addEventListener('click', copyEnrollPackage);
    el('enroll-done').addEventListener('click', closeEnrollModal);
    for (const node of document.querySelectorAll('[data-enroll-close]')) {
      node.addEventListener('click', closeEnrollModal);
    }
    el('audit-refresh').addEventListener('click', loadAudit);
    for (const node of document.querySelectorAll('[data-close]')) {
      node.addEventListener('click', closeDrawer);
    }
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeDrawer();
        if (!el('enroll-modal').hidden) closeEnrollModal();
      }
    });
    checkSession();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
