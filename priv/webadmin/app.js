// Cryptic Admin - front-end
// Handles the auth flow (session check, login, logout), section nav, and the
// user / enrollment / audit administration views, including mobile enrollment
// package creation with client-side QR rendering and a live server-log stream
// over WebSocket. All state-changing requests carry the CSRF token issued at
// login.
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
    if (name !== 'logs') disconnectLogs();
    if (name === 'users') loadUsers();
    else if (name === 'enrollments') loadEnrollments();
    else if (name === 'audit') loadAudit();
    else if (name === 'logs') connectLogs();
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
      <tr class="row" data-fp="${escapeHtml(u.enrollment_fp)}">
        <td>${escapeHtml(u.username || 'unknown')}</td>
        <td>${statusBadge(u.status)}</td>
        <td>${onlineDot(u.online)}</td>
        <td>${escapeHtml(fmtTime(u.registered_at))}</td>
        <td class="mono">${escapeHtml(shortFp(u.enrollment_fp))}</td>
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
      ['Fingerprint', `<span class="mono">${escapeHtml(u.enrollment_fp)}</span>`],
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
    // 'active' = pending enrollment invite, 'consumed' = enrolled user; both
    // can be suspended or revoked.
    if (status === 'active' || status === 'consumed') {
      buttons.push('<button class="danger" data-action="suspend">Suspend</button>');
      buttons.push('<button class="danger" data-action="revoke">Revoke</button>');
    } else if (status === 'suspended') {
      buttons.push('<button data-action="reactivate">Reactivate</button>');
      buttons.push('<button class="danger" data-action="revoke">Revoke</button>');
    }
    // Delete permanently removes the enrollment row (any status). Useful for
    // cleaning up stale/pending invites or freeing a username for re-enrollment.
    buttons.push('<button class="danger" data-action="delete">Delete</button>');
    actions.innerHTML = buttons.join('');
    for (const btn of actions.querySelectorAll('button')) {
      btn.addEventListener('click', () => performUserAction(btn.dataset.action));
    }
  }

  async function performUserAction(action) {
    const fp = state.currentUserFp;
    if (!fp) return;
    const labels = {
      suspend: 'suspend', revoke: 'revoke',
      reactivate: 'reactivate', delete: 'delete',
    };
    const verb = labels[action] || action;

    // Delete uses an HTTP DELETE on the user resource, not an action suffix.
    if (action === 'delete') {
      if (!window.confirm(
        'Permanently delete this enrollment? This cannot be undone.')) return;
      const { ok, data } = await api(
        `/admin/api/users/${encodeURIComponent(fp)}`, { method: 'DELETE' });
      if (ok && data && data.status === 'ok') {
        closeDrawer();
        loadUsers();
      } else {
        window.alert((data && data.message) || 'Failed to delete user.');
      }
      return;
    }

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

  async function populateServerHosts() {
    const select = el('enroll-server-host');
    select.innerHTML = '';
    let hosts = [];
    let def = '';
    try {
      const { ok, data } = await api('/admin/api/server-hosts');
      if (ok && data && data.status === 'ok') {
        hosts = Array.isArray(data.hosts) ? data.hosts : [];
        def = data.default || '';
      }
    } catch (_e) { /* fall through to server default */ }

    if (hosts.length === 0) {
      // No cert SANs readable: let the server fall back to its own default.
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = def
        ? `Server default (${def})`
        : 'Server default';
      select.appendChild(opt);
      select.disabled = true;
      return;
    }

    select.disabled = false;
    hosts.forEach((h) => {
      const opt = document.createElement('option');
      opt.value = h;
      opt.textContent = h;
      if (h === def) opt.selected = true;
      select.appendChild(opt);
    });
  }

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
    populateServerHosts();
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
    const serverHost = el('enroll-server-host').value.trim();
    if (serverHost) body.server_host = serverHost;
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

  // --- Logs ----------------------------------------------------------------

  const logs = {
    ws: null,
    lines: [],
    paused: false,
    pinned: true,
    heartbeat: null,
    reconnect: null,
    active: false,
  };

  const LOG_MAX_LINES = 5000;

  function logLevelClass(text) {
    if (/<ERROR>/i.test(text)) return 'log-error';
    if (/<WARNING>/i.test(text)) return 'log-warning';
    if (/<DEBUG>/i.test(text)) return 'log-debug';
    if (/<INFO>/i.test(text)) return 'log-info';
    return 'log-plain';
  }

  function logMatches(text) {
    const level = el('logs-level').value;
    if (level && !new RegExp(`<${level}>`, 'i').test(text)) return false;
    const q = el('logs-search').value.trim().toLowerCase();
    if (q && !text.toLowerCase().includes(q)) return false;
    return true;
  }

  function renderLogLine(line) {
    const div = document.createElement('div');
    div.className = `log-line ${logLevelClass(line.text)}`;
    div.textContent = line.text;
    return div;
  }

  function renderLogPane() {
    const pane = el('logs-pane');
    const frag = document.createDocumentFragment();
    for (const line of logs.lines) {
      if (logMatches(line.text)) frag.appendChild(renderLogLine(line));
    }
    pane.replaceChildren(frag);
    if (logs.pinned) pane.scrollTop = pane.scrollHeight;
  }

  function pushLogLines(newLines) {
    if (!newLines || newLines.length === 0) return;
    logs.lines.push(...newLines);
    if (logs.lines.length > LOG_MAX_LINES) {
      logs.lines.splice(0, logs.lines.length - LOG_MAX_LINES);
      renderLogPane();
      return;
    }
    const pane = el('logs-pane');
    const frag = document.createDocumentFragment();
    for (const line of newLines) {
      if (logMatches(line.text)) frag.appendChild(renderLogLine(line));
    }
    pane.appendChild(frag);
    if (logs.pinned) pane.scrollTop = pane.scrollHeight;
  }

  function updateLogStatus(text, kind) {
    const node = el('logs-status');
    node.textContent = text;
    node.className = `conn-status conn-${kind}`;
  }

  function handleLogFrame(msg) {
    if (!msg || !msg.type) return;
    if (msg.type === 'backfill') {
      logs.lines = [];
      el('logs-pane').replaceChildren();
      pushLogLines(msg.lines || []);
    } else if (msg.type === 'append') {
      if (logs.paused) {
        logs.lines.push(...(msg.lines || []));
        if (logs.lines.length > LOG_MAX_LINES) {
          logs.lines.splice(0, logs.lines.length - LOG_MAX_LINES);
        }
      } else {
        pushLogLines(msg.lines || []);
      }
    } else if (msg.type === 'error') {
      setMsg('logs-msg', msg.message || 'Log stream error.', 'error');
    }
  }

  function clearLogHeartbeat() {
    if (logs.heartbeat) {
      clearInterval(logs.heartbeat);
      logs.heartbeat = null;
    }
  }

  function scheduleLogReconnect() {
    if (logs.reconnect) return;
    logs.reconnect = setTimeout(() => {
      logs.reconnect = null;
      if (logs.active) connectLogs();
    }, 3000);
  }

  function connectLogs() {
    logs.active = true;
    if (logs.ws) return;
    setMsg('logs-msg', null);
    updateLogStatus('connecting…', 'pending');
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${location.host}/admin/ws/logs?tail=200`;
    let ws;
    try {
      ws = new WebSocket(url);
    } catch (_e) {
      updateLogStatus('disconnected', 'off');
      scheduleLogReconnect();
      return;
    }
    logs.ws = ws;
    ws.addEventListener('open', () => {
      updateLogStatus('live', 'on');
      logs.heartbeat = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'ping' }));
        }
      }, 30000);
    });
    ws.addEventListener('message', (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch (_e) { return; }
      handleLogFrame(msg);
    });
    ws.addEventListener('close', () => {
      clearLogHeartbeat();
      logs.ws = null;
      if (logs.active) {
        updateLogStatus('reconnecting…', 'pending');
        scheduleLogReconnect();
      } else {
        updateLogStatus('disconnected', 'off');
      }
    });
    ws.addEventListener('error', () => {
      try { ws.close(); } catch (_e) { /* ignore */ }
    });
  }

  function disconnectLogs() {
    logs.active = false;
    if (logs.reconnect) {
      clearTimeout(logs.reconnect);
      logs.reconnect = null;
    }
    clearLogHeartbeat();
    if (logs.ws) {
      const ws = logs.ws;
      logs.ws = null;
      try { ws.close(); } catch (_e) { /* ignore */ }
    }
    updateLogStatus('disconnected', 'off');
  }

  function toggleLogPause() {
    logs.paused = !logs.paused;
    const btn = el('logs-pause');
    btn.textContent = logs.paused ? 'Resume' : 'Pause';
    btn.classList.toggle('active', logs.paused);
    if (!logs.paused) renderLogPane();
  }

  function clearLogPane() {
    logs.lines = [];
    el('logs-pane').replaceChildren();
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
    el('logs-pause').addEventListener('click', toggleLogPause);
    el('logs-clear').addEventListener('click', clearLogPane);
    el('logs-level').addEventListener('change', renderLogPane);
    el('logs-search').addEventListener('input', renderLogPane);
    const logsPane = el('logs-pane');
    logsPane.addEventListener('scroll', () => {
      const gap = logsPane.scrollHeight - logsPane.scrollTop - logsPane.clientHeight;
      logs.pinned = gap < 40;
    });
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
