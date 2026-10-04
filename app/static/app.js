/* Vanilla JS chat client: public room + private DMs over one WebSocket. */
(function () {
  'use strict';
  const list = document.getElementById('messages');
  const form = document.getElementById('form');
  const input = document.getElementById('input');
  const meEl = document.getElementById('me');
  const statusEl = document.getElementById('status');
  const titleEl = document.getElementById('view-title');
  const convBox = document.getElementById('conversations');
  const btnPublic = document.getElementById('btn-public');
  const sidebarToggle = document.getElementById('sidebar-toggle');
  const sidebarBackdrop = document.getElementById('sidebar-backdrop');
  const dmForm = document.getElementById('dm-form');
  const dmInput = document.getElementById('dm-input');
  const dmError = document.getElementById('dm-error');
  let me = null;
  let ws = null;
  let retryMs = 1000;
  let view = { kind: 'public' }; // or { kind: 'dm', username: '...' }
  let conversations = [];
  let seen = {}; // message id -> {name, username, content} of the current view
  let pendingReply = null; // {id, name, username, content} or null

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function previewText(s) {
    s = String(s);
    return s.length > 80 ? s.slice(0, 80) + '…' : s;
  }

  function scrollBottom() {
    list.scrollTop = list.scrollHeight;
  }

  function addMessage(m) {
    seen[m.id] = { name: m.name, username: m.username, content: m.content };
    const div = document.createElement('div');
    div.className = 'msg' + (me && m.username === me.username ? ' mine' : '');
    div.setAttribute('data-mid', m.id);
    const when = m.created_at ? ' · ' + esc(m.created_at) : '';
    let html = '';
    if (m.reply_to) {
      // A real <button>, so the quote is keyboard focusable and announced.
      html += '<button type="button" class="quote" data-jump="' + m.reply_to.id + '">' +
        '<span class="q-who">' + esc(m.reply_to.name || m.reply_to.username) + '</span> ' +
        esc(previewText(m.reply_to.content)) + '</button>';
    }
    html += '<div class="meta"><strong>' + esc(m.name || m.username) + '</strong> @' +
      esc(m.username) + when + '</div><div>' + esc(m.content) + '</div>' +
      '<button class="reply-btn" data-reply="' + m.id + '" type="button">↩ Reply</button>';
    div.innerHTML = html;
    list.appendChild(div);
    scrollBottom();
  }

  function startReply(id) {
    const t = seen[id];
    if (!t) return;
    pendingReply = { id: id, name: t.name, username: t.username, content: t.content };
    document.getElementById('reply-to').textContent =
      '@' + t.username + ': ' + previewText(t.content);
    document.getElementById('reply-bar').classList.remove('hidden');
    input.focus();
  }

  function cancelReply() {
    pendingReply = null;
    document.getElementById('reply-bar').classList.add('hidden');
  }

  function jumpToMessage(id) {
    const el = list.querySelector('[data-mid="' + id + '"]');
    if (!el) {
      statusEl.textContent = 'Original message is not in loaded history.';
      setTimeout(() => {
        if (statusEl.textContent.indexOf('Original message') === 0) {
          statusEl.textContent = 'Connected';
        }
      }, 3000);
      return;
    }
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.classList.remove('flash');
    void el.offsetWidth; // restart the highlight animation
    el.classList.add('flash');
    setTimeout(() => el.classList.remove('flash'), 2200);
  }

  list.addEventListener('click', (e) => {
    if (!e.target || !e.target.closest) return;
    const rb = e.target.closest('[data-reply]');
    if (rb && list.contains(rb)) {
      startReply(parseInt(rb.getAttribute('data-reply'), 10));
      return;
    }
    const q = e.target.closest('[data-jump]');
    if (q && list.contains(q)) {
      jumpToMessage(parseInt(q.getAttribute('data-jump'), 10));
    }
  });

  function otherParty(m) {
    return m.username === me.username ? m.to : m.username;
  }

  function setSidebar(open) {
    document.body.classList.toggle('sidebar-open', open);
    sidebarToggle.setAttribute('aria-expanded', String(open));
    if (sidebarBackdrop) sidebarBackdrop.hidden = !open;
  }

  // Picking a conversation on a phone should reveal the conversation.
  function closeSidebarOnNarrow() {
    if (window.matchMedia('(max-width: 600px)').matches) setSidebar(false);
  }

  function renderConversations() {
    convBox.innerHTML = '';
    conversations.forEach((c) => {
      const b = document.createElement('button');
      b.className = 'conv' + (view.kind === 'dm' && view.username === c.username ? ' active' : '');
      b.textContent = '@' + c.username;
      b.title = c.name;
      b.addEventListener('click', () => { openDm(c.username); closeSidebarOnNarrow(); });
      convBox.appendChild(b);
    });
    btnPublic.classList.toggle('active', view.kind === 'public');
  }

  async function loadConversations() {
    try { conversations = await Api.conversations(); } catch (e) { /* best-effort */ }
    renderConversations();
  }

  function ensureInList(username) {
    if (!conversations.some((c) => c.username === username)) {
      conversations.unshift({ username: username, name: username });
      renderConversations();
    }
  }

  async function openPublic() {
    view = { kind: 'public' };
    titleEl.textContent = 'Public Chat';
    input.placeholder = 'Type a message…';
    list.innerHTML = '';
    seen = {};
    cancelReply();
    renderConversations();
    try {
      (await Api.messages(50)).forEach(addMessage);
    } catch (e) { /* best-effort */ }
  }

  async function openDm(username) {
    view = { kind: 'dm', username: username };
    titleEl.textContent = 'Private chat with @' + username;
    input.placeholder = 'Message @' + username + '…';
    list.innerHTML = '';
    seen = {};
    cancelReply();
    ensureInList(username);
    renderConversations();
    try {
      (await Api.dmHistory(username, 50)).forEach(addMessage);
    } catch (e) {
      if (e && e.status === 404) {
        showDmError('User not found.');
        await openPublic();
      }
    }
    input.focus();
  }

  function showDmError(msg) {
    dmError.textContent = msg;
    dmError.style.display = 'block';
    setTimeout(() => { dmError.style.display = 'none'; }, 4000);
  }

  async function init() {
    try {
      await Api.boot();
      me = await Api.me();
      meEl.textContent = me.name + ' (@' + me.username + ')';
      showSecurityState();
    } catch (e) {
      location.href = '/login';
      return;
    }
    await openPublic();
    await loadConversations();
    connect();
  }

  function connect() {
    ws = Api.openSocket(handleFrame, (status, detail) => {
      if (status === 'open') {
        statusEl.textContent = Api.state.mode === 'enc'
          ? 'Connected (encrypted)' : 'Connected';
        retryMs = 1000;
        if (Api.state.mode === 'enc') Enc.saveState(Api.state.channel);
      } else if (status === 'close') {
        statusEl.textContent = 'Disconnected — reconnecting…';
        setTimeout(connect, Math.min(retryMs, 10000));
        retryMs *= 2;
      } else if (status === 'error' && detail) {
        statusEl.textContent = 'Channel error: ' + detail;
      } else if (status === 'heal') {
        // A dropped frame desynchronised the socket; the reconnect heals it.
        statusEl.textContent = 'Reconnecting…';
      }
    });
  }

  function handleFrame(m) {
    if (!m) return;
    if (m.kind === 'error') {
      statusEl.textContent = 'Error: ' + (m.error || 'something went wrong');
      return;
    }
    if (m.kind === 'dm') {
      const other = otherParty(m);
      ensureInList(other);
      if (view.kind === 'dm' && view.username === other) addMessage(m);
      return;
    }
    if (view.kind === 'public') addMessage(m);
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text || !ws || !ws.isOpen()) return;
    const payload = { content: text.slice(0, 1000) };
    if (view.kind === 'dm') {
      payload.type = 'dm';
      payload.to = view.username;
    } else {
      payload.type = 'public';
    }
    if (pendingReply) payload.reply_to = pendingReply.id;
    ws.send(payload).catch(() => {});
    input.value = '';
    cancelReply();
    input.focus();
  });

  document.getElementById('reply-cancel').addEventListener('click', cancelReply);

  btnPublic.addEventListener('click', () => { openPublic(); closeSidebarOnNarrow(); });

  sidebarToggle.addEventListener('click', () => {
    setSidebar(!document.body.classList.contains('sidebar-open'));
  });
  if (sidebarBackdrop) sidebarBackdrop.addEventListener('click', () => setSidebar(false));
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && document.body.classList.contains('sidebar-open')) {
      setSidebar(false);
      sidebarToggle.focus();
    }
  });
  // Leaving the narrow breakpoint must not strand the drawer open.
  window.matchMedia('(max-width: 600px)').addEventListener('change', (e) => {
    if (!e.matches) setSidebar(false);
  });

  dmForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    let u = dmInput.value.trim().replace(/^@/, '');
    dmInput.value = '';
    if (!u) return;
    // Verify the user exists before opening the conversation.
    try {
      const users = await Api.users(u, 5);
      const exact = users.find((x) => x.username.toLowerCase() === u.toLowerCase());
      if (!exact) { showDmError('User @' + u + ' not found.'); return; }
      await openDm(exact.username);
    } catch (err) {
      showDmError('Could not find user. Try again.');
    }
  });

  document.getElementById('logout').addEventListener('click', async () => {
    try { await Api.logout(); } catch (e) {}
    location.href = '/login';
  });

  function showSplitWarning() {
    const box = document.getElementById('split-warning');
    if (!box) return;
    const cfg = Api.state.config || {};
    if (!cfg.split_rooms) { box.classList.add('hidden'); return; }
    box.classList.remove('hidden');
    box.textContent =
      'Split-rooms mode is active: users on different workers do not see ' +
      "each other's messages. Public chat is split into one room per worker " +
      'process (currently ' + (cfg.workers || '?') + ' workers).';
  }

  function showSecurityState() {
    showSplitWarning();
    const box = document.getElementById('security');
    if (!box) return;
    if (Api.state.mode !== 'enc') { box.classList.add('hidden'); return; }
    const fp = Api.fingerprint() || '';
    const pin = Api.pinState();
    // Assigning className drops the initial `hidden`, which is what shows it.
    box.className = 'security' + (pin === 'changed' ? ' warn' : '');
    box.innerHTML =
      // "encrypted transport", not end-to-end: the server can still read
      // stored messages, so do not claim E2EE here.
      '<span class="lock" title="Encrypted transport from this page">🔒</span>' +
      '<span class="fp" title="Server identity fingerprint (pin your server key to detect MITM)">' +
      esc(fp) + '</span>' +
      '<button class="sec-copy" type="button" title="Copy fingerprint">copy</button>' +
      (pin === 'new' ? '<span class="sec-new">pinned</span>' :
       pin === 'changed' ? '<span class="sec-changed">IDENTITY CHANGED!</span>' : '');
    const copyBtn = box.querySelector('.sec-copy');
    if (copyBtn) copyBtn.addEventListener('click', () => {
      if (navigator.clipboard) navigator.clipboard.writeText(fp);
    });
  }

  init();
})();
