/* api.js -- one API surface for both transports.
 *
 * Encrypted mode (ENC_ENABLED): everything goes through the Enc channel, no
 * cookies are used, and a stolen session token is worthless without the
 * channel keys. Plain mode keeps the original cookie-based fetch.
 */
'use strict';

var Api = (function () {
  var state = { mode: 'plain', channel: null, config: null,
              identityChanged: false };

  function json(url, opts) {
    return fetch(url, opts).then(function (r) {
      return r.text().then(function (t) {
        var data = {};
        try { data = JSON.parse(t); } catch (e) {}
        if (!r.ok) {
          var err = new Error(data.error || 'Request failed');
          err.status = r.status;
          throw err;
        }
        return data;
      });
    });
  }

  function plainPost(url, fields) {
    var fd = new FormData();
    Object.keys(fields).forEach(function (k) { fd.append(k, fields[k]); });
    return json(url, { method: 'POST', body: fd });
  }

  function handshakeJson(path, method, obj) {
    if (method === 'GET') return json(path);
    return json(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(obj),
    });
  }

  function handshake() {
    var ch = new Enc.Channel();
    return ch.handshake(handshakeJson).then(function () {
      state.channel = ch;
      state.mode = 'enc';
      Enc.saveState(ch);
      return state;
    });
  }

  /* ---------- identity-change recovery ---------- */

  function identityBanner(message, onTrust) {
    var bar = document.createElement('div');
    bar.id = 'identity-warning';
    bar.style.cssText =
      'position:fixed;top:0;left:0;right:0;z-index:9999;padding:12px 16px;' +
      'background:#c92a2a;color:#fff;font:14px system-ui;display:flex;' +
      'gap:12px;align-items:center;flex-wrap:wrap';
    var txt = document.createElement('span');
    txt.style.flex = '1';
    txt.textContent = message;
    bar.appendChild(txt);
    if (onTrust) {
      var btn = document.createElement('button');
      btn.textContent = 'Trust the new identity';
      btn.style.cssText =
        'padding:6px 12px;border:none;border-radius:6px;font-weight:600;cursor:pointer';
      btn.addEventListener('click', onTrust);
      bar.appendChild(btn);
    }
    var close = document.createElement('button');
    close.textContent = '×';
    close.style.cssText =
      'background:none;border:none;color:#fff;font-size:20px;cursor:pointer';
    close.addEventListener('click', function () { bar.remove(); });
    bar.appendChild(close);
    document.body.appendChild(bar);
  }

  function trustNewIdentity() {
    Enc.clearPin();
    Enc.clearState();
    if (location.reload) location.reload();
  }

  /* ---------- boot ---------- */

  function boot() {
    return json('/api/config').then(function (cfg) {
      state.config = cfg;
      if (!cfg.enc_enabled) { state.mode = 'plain'; return state; }
      return startChannel().catch(function (err) {
        if (isIdentityChange(err)) {
          reportIdentityChange(err);
          return state;
        }
        throw err;
      });
    });
  }

  function isIdentityChange(err) {
    return !!err && /IDENTITY CHANGED|signature invalid|MITM/i.test(err.message || '');
  }

  function reportIdentityChange(err) {
    state.identityChanged = true;
    identityBanner('The server identity changed since you last connected. This ' +
      'is expected after a server move or key rotation — but it can also mean ' +
      'someone is impersonating the server. Stop and verify before continuing.' +
      (err && err.message ? ' (' + err.message.slice(0, 120) + ')' : ''),
      trustNewIdentity);
  }

  function startChannel() {
    var saved = Enc.loadState();
    if (!saved) return handshake();
    var restored = new Enc.Channel();
    try {
      restored.restoreState(saved);
    } catch (e) {
      Enc.clearState();
      return handshake();
    }
    // A session left over from a server restart is stale: channels live in
    // server memory, so verify and silently re-handshake when it is gone.
    return restored.call('/api/me', {}).then(function () {
      state.channel = restored;
      state.mode = 'enc';
      return state;
    }, function (err) {
      if (err && typeof err.status === 'number') {
        // Channel is healthy, the user simply is not logged in yet.
        state.channel = restored;
        state.mode = 'enc';
        return state;
      }
      Enc.clearState();
      return handshake();
    });
  }

  function enc() {
    if (state.mode !== 'enc' || !state.channel) {
      return Promise.reject(new Error('Encrypted channel not ready.'));
    }
    return Promise.resolve(state.channel);
  }

  /* ---------- auth ---------- */

  function me() {
    if (state.mode === 'enc') {
      return enc().then(function (c) { return c.call('/api/me', {}); });
    }
    return json('/api/me');
  }

  function login(username, password) {
    if (state.mode === 'enc') {
      return enc().then(function (c) {
        return c.login(username, password).then(function (data) {
          Enc.saveState(c);
          return data.user;
        });
      });
    }
    return plainPost('/api/login', { username: username, password: password })
      .then(function () { return json('/api/me'); });
  }

  function register(name, username, password, confirm) {
    if (state.mode === 'enc') {
      return enc().then(function (c) {
        return c.call('/api/register', { name: name, username: username,
          password: password, confirm: confirm });
      });
    }
    return plainPost('/api/register', { name: name, username: username,
      password: password, confirm: confirm });
  }

  function logout() {
    var done = (state.mode === 'enc')
      ? enc().then(function (c) { return c.call('/api/logout', {}); })
          .catch(function () {})
      : plainPost('/api/logout', {}).catch(function () {});
    return done.then(function () {
      Enc.clearState();
      Enc.clearPin();
    });
  }

  /* ---------- data ---------- */

  function messages(limit) {
    if (state.mode === 'enc') {
      return enc().then(function (c) {
        return c.call('/api/messages', { q: { limit: limit || 50 } });
      });
    }
    return json('/api/messages?limit=' + (limit || 50));
  }

  function conversations() {
    if (state.mode === 'enc') {
      return enc().then(function (c) { return c.call('/api/conversations', {}); });
    }
    return json('/api/conversations');
  }

  function users(q, limit) {
    if (state.mode === 'enc') {
      return enc().then(function (c) {
        return c.call('/api/users', { q: { q: q || '', limit: limit || 20 } });
      });
    }
    return json('/api/users?q=' + encodeURIComponent(q || '') +
      '&limit=' + (limit || 20));
  }

  function dmHistory(username, limit) {
    var path = '/api/dm/' + encodeURIComponent(username);
    if (state.mode === 'enc') {
      return enc().then(function (c) {
        return c.call(path, { q: { limit: limit || 50 } });
      });
    }
    return json(path + '?limit=' + (limit || 50));
  }

  /* ---------- websocket ---------- */

  /* onFrame(decodedAppObject) */
  function openSocket(onFrame, onStatus) {
    var url;
    if (state.mode === 'enc') {
      var proto = location.protocol === 'https:' ? 'wss' : 'ws';
      url = proto + '://' + location.host + '/enc/ws?sid=' +
        encodeURIComponent(state.channel.sid);
    } else {
      var p = location.protocol === 'https:' ? 'wss' : 'ws';
      url = p + '://' + location.host + '/ws';
    }
    var ws = new WebSocket(url);
    var ready = false;
    var queued = [];
    ws.onopen = function () { if (onStatus) onStatus('open'); };
    ws.onclose = function () { if (onStatus) onStatus('close'); };
    ws.onerror = function () { if (onStatus) onStatus('error'); };
    ws.onmessage = function (ev) {
      var raw;
      try { raw = JSON.parse(ev.data); } catch (e) { return; }
      if (state.mode === 'enc') {
        if (raw && raw.hello) {
          // Server sends the per-socket salt first; derive socket keys.
          state.channel.socketMaterial(raw.hello.salt).then(function () {
            ready = true;
            queued.splice(0).forEach(function (f) { f(); });
          }).catch(function (e) {
            if (onStatus) onStatus('error', e.message);
          });
          return;
        }
        if (typeof raw.e !== 'string') return;
        var deliver = function () {
          state.channel.openWs(raw.e).then(function (obj) {
            onFrame(obj, ev);
          }).catch(function (e) {
            heal('channel desynchronised: ' + (e.message || 'bad frame'));
          });
        };
        if (!ready) queued.push(deliver); else deliver();
        return;
      }
      onFrame(raw, ev);
    };
    function heal(reason) {
      // A lost frame desynchronises the socket counter, so every later frame
      // would fail too. Recycle the socket: reconnecting renegotiates fresh
      // per-socket keys and resets the counters (see Channel.socketMaterial).
      if (onStatus) onStatus('heal', reason);
      try { ws.close(); } catch (e) { /* already closing */ }
    }
    return {
      send: function (obj) {
        var ch = state.channel;
        var wire = function () {
          return (state.mode === 'enc')
            ? ch.sealWs(obj).then(function (f) { return JSON.stringify({ e: f }); })
            : Promise.resolve(JSON.stringify(obj));
        };
        if (state.mode === 'enc' && !ready) {
          return new Promise(function (resolve, reject) {
            queued.push(function () {
              wire().then(function (t) { ws.send(t); resolve(); }, reject);
            });
          });
        }
        return wire().then(function (t) { ws.send(t); });
      },
      close: function () { ws.close(); },
      isOpen: function () { return ws.readyState === 1; },
      _heal: heal,
    };
  }

  function fingerprint() {
    return state.channel ? state.channel.fingerprint : null;
  }

  function pinState() {
    var fp = fingerprint();
    return fp ? Enc.pinState(fp) : 'none';
  }

  return {
    boot: boot,
    me: me,
    login: login,
    register: register,
    logout: logout,
    messages: messages,
    conversations: conversations,
    users: users,
    dmHistory: dmHistory,
    openSocket: openSocket,
    state: state,
    fingerprint: fingerprint,
    pinState: pinState,
  };
})();