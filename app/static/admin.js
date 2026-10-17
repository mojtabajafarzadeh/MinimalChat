/* Admin panel logic.

   External rather than inline so the CSP needs no 'unsafe-inline'.

   /admin/api is replaced by the server with the panel's own API prefix
   (it follows ADMIN_PATH). A relative './api' would resolve against a
   slash-less document URL and escape to /api -- the *user* endpoints. */
(function () {
  'use strict';

  var API = '__ADMIN_API__';
  var loginView = document.getElementById('login-view');
  var panelView = document.getElementById('panel-view');
  var loginErr = document.getElementById('login-error');
  var panelErr = document.getElementById('panel-error');
  var usersBox = document.getElementById('users');

  // Same escaping as app.js: quotes included, so a display name can never
  // break out of an attribute context.
  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
  function showError(el, msg) {
    el.textContent = msg;
    el.classList.remove('hidden');
    setTimeout(function () { el.classList.add('hidden'); }, 5000);
  }
  function show(view) {
    loginView.classList.toggle('hidden', view !== 'login');
    panelView.classList.toggle('hidden', view !== 'panel');
  }

  async function loadUsers() {
    const r = await fetch(API + '/users');
    if (r.status === 401) { show('login'); return; }
    if (!r.ok) { showError(panelErr, 'Could not load users.'); return; }
    const users = await r.json();
    document.getElementById('user-count').textContent = users.length + ' user(s)';
    usersBox.innerHTML = '';
    users.forEach((u) => {
      const row = document.createElement('div');
      row.className = 'user-row';
      row.innerHTML =
        '<div class="user-info"><strong>' + esc(u.name) + '</strong> @' + esc(u.username) +
        ' <span class="muted">#' + u.id + '</span></div>' +
        '<input class="input" type="password" placeholder="New password" maxlength="128" data-pw>' +
        '<button class="btn btn-secondary btn-sm" data-set>Set password</button>' +
        '<button class="btn btn-destructive btn-sm" data-del>Delete</button>';
      const pwInput = row.querySelector('[data-pw]');
      row.querySelector('[data-set]').addEventListener('click', async () => {
        const pw = pwInput.value;
        if (!pw) return;
        if (!confirm('Set a new password for @' + u.username + '? They will be logged out everywhere.')) return;
        const fd = new FormData();
        fd.append('password', pw);
        fd.append('confirm', pw);
        const rr = await fetch(API + '/users/' + u.id + '/password', { method: 'POST', body: fd });
        const data = await rr.json().catch(() => ({}));
        if (!rr.ok) { showError(panelErr, data.error || 'Failed.'); return; }
        pwInput.value = '';
        await loadUsers();
      });
      row.querySelector('[data-del]').addEventListener('click', async () => {
        if (!confirm('Delete @' + u.username + ' and ALL their messages? This cannot be undone.')) return;
        const rr = await fetch(API + '/users/' + u.id, { method: 'DELETE' });
        const data = await rr.json().catch(() => ({}));
        if (!rr.ok) { showError(panelErr, data.error || 'Failed.'); return; }
        await loadUsers();
      });
      usersBox.appendChild(row);
    });
    show('panel');
  }

  loginView.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginErr.classList.add('hidden');
    const fd = new FormData();
    fd.append('password', document.getElementById('password').value);
    document.getElementById('password').value = '';
    const r = await fetch(API + '/login', { method: 'POST', body: fd });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) { showError(loginErr, data.error || 'Login failed.'); return; }
    await loadUsers();
  });

  document.getElementById('add-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData();
    fd.append('name', document.getElementById('add-name').value.trim());
    fd.append('username', document.getElementById('add-username').value.trim());
    fd.append('password', document.getElementById('add-password').value);
    fd.append('confirm', document.getElementById('add-confirm').value);
    const r = await fetch(API + '/users', { method: 'POST', body: fd });
    const data = await r.json().catch(() => ({}));
    if (r.status === 401) { show('login'); return; }
    if (!r.ok) { showError(panelErr, data.error || 'Failed.'); return; }
    e.target.reset();
    await loadUsers();
  });

  document.getElementById('logout').addEventListener('click', async () => {
    try { await fetch(API + '/logout', { method: 'POST' }); } catch (e) {}
    show('login');
  });

  loadUsers();
})();
