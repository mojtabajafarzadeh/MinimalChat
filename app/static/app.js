/* Vanilla JS chat client: history via REST, live messages via WebSocket. */
(function () {
  'use strict';
  const list = document.getElementById('messages');
  const form = document.getElementById('form');
  const input = document.getElementById('input');
  const meEl = document.getElementById('me');
  const statusEl = document.getElementById('status');
  let me = null;
  let ws = null;
  let retryMs = 1000;

  function esc(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function scrollBottom() {
    list.scrollTop = list.scrollHeight;
  }

  function addMessage(m) {
    const div = document.createElement('div');
    div.className = 'msg' + (me && m.username === me.username ? ' mine' : '');
    const when = m.created_at ? ' · ' + esc(m.created_at) : '';
    div.innerHTML =
      '<div class="meta"><strong>' + esc(m.name || m.username) + '</strong> @' +
      esc(m.username) + when + '</div><div>' + esc(m.content) + '</div>';
    list.appendChild(div);
    scrollBottom();
  }

  async function init() {
    // Who am I? Redirect to login if session invalid.
    try {
      const r = await fetch('/api/me');
      if (!r.ok) { location.href = '/login'; return; }
      me = await r.json();
      meEl.textContent = me.name + ' (@' + me.username + ')';
    } catch (e) {
      location.href = '/login';
      return;
    }
    // Load history.
    try {
      const r = await fetch('/api/messages?limit=50');
      if (r.ok) {
        const msgs = await r.json();
        list.innerHTML = '';
        msgs.forEach(addMessage);
      }
    } catch (e) { /* history is best-effort; WS still works */ }
    connect();
  }

  function connect() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(proto + '://' + location.host + '/ws');
    ws.onopen = () => {
      statusEl.textContent = 'Connected';
      retryMs = 1000;
    };
    ws.onmessage = (ev) => {
      try { addMessage(JSON.parse(ev.data)); } catch (e) { /* ignore bad frame */ }
    };
    ws.onclose = () => {
      statusEl.textContent = 'Disconnected — reconnecting…';
      setTimeout(connect, Math.min(retryMs, 10000));
      retryMs *= 2;
    };
    ws.onerror = () => { try { ws.close(); } catch (e) {} };
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify({ content: text.slice(0, 1000) }));
    input.value = '';
    input.focus();
  });

  document.getElementById('logout').addEventListener('click', async () => {
    try { await fetch('/api/logout', { method: 'POST' }); } catch (e) {}
    location.href = '/login';
  });

  init();
})();
