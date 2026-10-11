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
  // Unread counts, for this page load only. Nothing is persisted and nothing
  // is sent to the server: a reload starts from zero. That is the whole
  // feature -- it answers "did something arrive while I was looking
  // elsewhere", which is a question about this page load.
  let unread = Object.create(null);
  // conversation key -> {button, badge, label}, so a badge update never
  // rebuilds the list and never steals focus from someone tabbing through it.
  let convRows = Object.create(null);
  // Our own messages that have been sent but not yet echoed, oldest first.
  const pending = [];

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

  // Auto-scroll only when the reader is already at the bottom. Jumping down
  // while someone is reading older messages yanks the view out from under them.
  function isAtBottom() {
    return list.scrollHeight - list.scrollTop - list.clientHeight < 60;
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
    if (isAtBottom()) scrollBottom();
  }

  /* ---- optimistic send -----------------------------------------------
     A sent message appears immediately as "sending", then the server's own
     echo replaces it. The echo is what makes this safe: it carries the real
     id and created_at, so the confirmed row is rendered from server data
     exactly like everyone else's. A pending row never enters `seen`, so it
     can never become a reply target -- a reply cannot point at a message
     that does not exist on the server yet. */
  function addPending(text) {
    const div = document.createElement('div');
    div.className = 'msg mine pending';
    div.innerHTML =
      '<div class="meta"><strong>' + esc(me.name) + '</strong> @' +
      esc(me.username) + ' · sending…</div><div>' + esc(text) + '</div>';
    list.appendChild(div);
    pending.push(div);
    scrollBottom();
  }

  // The next echo of our own message settles the oldest pending row: each
  // connection sends its frames in order, and the server awaits them in order
  // (_ws_loop), so echoes come back in the order they were sent.
  function settleOldestPending() {
    const node = pending.shift();
    if (node) node.remove();
  }

  function dropAllPending() {
    if (!pending.length) return;
    pending.splice(0, pending.length).forEach((n) => n.remove());
    statusEl.textContent = 'Message not sent — connection lost.';
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

  /* Usernames are user-chosen, so the key is lowercased and both maps are
     prototype-less: a conversation with @constructor must not resolve to
     something off Object.prototype. */
  function convKey(kind, username) {
    return kind === 'public' ? 'public' : 'dm:' + String(username).toLowerCase();
  }

  function paintRow(row) {
    const n = unread[row.key] || 0;
    if (row.badge) {
      row.badge.textContent = n > 99 ? '99+' : String(n);
      row.badge.classList.toggle('hidden', n === 0);
    }
    // Left to itself the digits join the button's name and it announces
    // "@alice 3", so spell the count out and hide the badge from assistive
    // technology to avoid saying it twice.
    row.button.setAttribute('aria-label',
      n ? row.label + ', ' + n + ' unread message' + (n === 1 ? '' : 's')
        : row.label);
  }

  function paintBadges() {
    Object.keys(convRows).forEach((k) => paintRow(convRows[k]));
  }

  function markUnread(kind, username) {
    const key = convKey(kind, username);
    unread[key] = (unread[key] || 0) + 1;
    paintBadges();
  }

  function markRead(kind, username) {
    delete unread[convKey(kind, username)];
    paintBadges();
  }

  function renderConversations() {
    convBox.innerHTML = '';
    convRows = Object.create(null);
    conversations.forEach((c) => {
      const key = convKey('dm', c.username);
      const b = document.createElement('button');
      b.className = 'conv' + (view.kind === 'dm' && view.username === c.username ? ' active' : '');
      const name = document.createElement('span');
      name.className = 'conv-name';
      name.textContent = '@' + c.username;
      const badge = document.createElement('span');
      badge.className = 'conv-badge hidden';
      badge.setAttribute('aria-hidden', 'true');
      // Presence dot: purely decorative, so hidden from assistive tech. The
      // conversation's name never claims someone is online.
      const dot = document.createElement('span');
      dot.className = 'conv-online' + (c.online ? '' : ' hidden');
      dot.setAttribute('aria-hidden', 'true');
      b.appendChild(name);
      b.appendChild(dot);
      b.appendChild(badge);
      b.title = c.name + (c.online ? ' (online)' : '');
      b.addEventListener('click', () => { openDm(c.username); closeSidebarOnNarrow(); });
      convBox.appendChild(b);
      convRows[key] = { key: key, button: b, badge: badge,
                        label: 'Private chat with @' + c.username };
    });
    // # Public Chat is static markup, but it is a conversation like any other.
    // Query pubBadge here (after any potential DOM changes) so it's never null.
    const pubBadge = btnPublic.querySelector('.conv-badge');
    convRows.public = { key: 'public', button: btnPublic, badge: pubBadge,
                        label: 'Public Chat' };
    btnPublic.classList.toggle('active', view.kind === 'public');
    paintBadges();
  }

  async function loadConversations() {
    try { conversations = await Api.conversations(); } catch (e) { /* best-effort */ }
    renderConversations();
  }

  function ensureInList(username) {
    const lower = String(username).toLowerCase();
    if (!conversations.some((c) => c.username.toLowerCase() === lower)) {
      conversations.unshift({ username: username, name: username });
      renderConversations();
    }
  }

  async function openPublic() {
    view = { kind: 'public' };
    markRead('public');
    titleEl.textContent = 'Public Chat';
    input.placeholder = 'Type a message…';
    list.innerHTML = '';
    pending.splice(0, pending.length);
    seen = {};
    cancelReply();
    renderConversations();
    try {
      (await Api.messages(50)).forEach(addMessage);
    } catch (e) { /* best-effort */ }
  }

  async function openDm(username) {
    view = { kind: 'dm', username: username };
    markRead('dm', username);
    titleEl.textContent = 'Private chat with @' + username;
    input.placeholder = 'Message @' + username + '…';
    list.innerHTML = '';
    pending.splice(0, pending.length);
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
        statusEl.textContent = Api.mode === 'enc'
          ? 'Connected (encrypted)' : 'Connected';
        retryMs = 1000;
        if (Api.mode === 'enc') Enc.saveState(Api.channel);
      } else if (status === 'close') {
        statusEl.textContent = 'Disconnected — reconnecting…';
        dropAllPending();
        setTimeout(connect, Math.min(retryMs, 10000));
        retryMs *= 2;
      } else if (status === 'error' && detail) {
        statusEl.textContent = 'Channel error: ' + detail;
      } else if (status === 'rejected') {
        // The server refused this socket on purpose; retrying cannot help.
        statusEl.textContent = detail || 'Connection refused by the server.';
        dropAllPending();
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
      // Our own echo settles the pending row before it is rendered again.
      if (me && m.username === me.username) settleOldestPending();
      // may create the row, which paints the badge
      ensureInList(other);
      if (view.kind === 'dm' && view.username === other) {
        addMessage(m);
      } else {
        // A message you cannot see right now. This includes the echo of your
        // own send, which can only ever arrive for the conversation you are
        // already looking at -- so it lands in the branch above, not here.
        markUnread('dm', other);
      }
      return;
    }
    if (me && m.username === me.username) settleOldestPending();
    if (view.kind === 'public') addMessage(m);
    else markUnread('public');
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
    addPending(payload.content);
    ws.send(payload).catch(dropAllPending);
    input.value = '';
    cancelReply();
    input.focus();
  });

  // Enter still submits the form; Ctrl/Cmd+Enter is an extra shortcut. The
  // composer is a single-line <input>, so Shift+Enter inserts no newline --
  // it just submits, same as a bare Enter.
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      form.requestSubmit();
    }
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
    const cfg = Api.config || {};
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
    if (Api.mode !== 'enc') { box.classList.add('hidden'); return; }
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
