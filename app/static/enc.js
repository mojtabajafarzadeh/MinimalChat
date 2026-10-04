/* enc.js -- client half of the application-layer encrypted channel.
 *
 * Mirrors app/enc.py byte for byte:
 *   ECDH P-256 + ECDSA P-256 + HKDF-SHA256 + AES-256-GCM (WebCrypto only).
 * No custom primitive is implemented here; this is the same composition the
 * server performs.
 *
 * Anti-MITM: the server signs the handshake transcript with its long-term key.
 * We pin that key's fingerprint in localStorage (TOFU) and refuse to continue
 * if it changes silently.
 */
'use strict';

var Enc = (function () {
  var P = 'chat-enc-v1';
  var enc = new TextEncoder();
  var dec = new TextDecoder();
  var PIN_KEY = 'chat-server-fp';

  function b64e(buf) {
    var bytes = new Uint8Array(buf);
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function b64d(str) {
    // WebCrypto JWK components are base64url; normalize to standard base64.
    var s = String(str).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function hex(buf) {
    return Array.prototype.map
      .call(new Uint8Array(buf), function (b) {
        return ('0' + b.toString(16)).slice(-2);
      })
      .join('');
  }

  function sha256(bytes) {
    return crypto.subtle.digest('SHA-256', bytes);
  }

  function hkdf(ikm, salt, info, len) {
    return crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
      .then(function (key) {
        return crypto.subtle.deriveBits(
          { name: 'HKDF', hash: 'SHA-256', salt: salt, info: enc.encode(info) },
          key, (len || 32) * 8);
      });
  }

  // ---- P-256 helpers (uncompressed points, 65 bytes) ----

  function pubRawFromJwk(jwk) {
    var raw = new Uint8Array(65);
    raw[0] = 4;
    raw.set(b64d(jwk.x), 1);
    raw.set(b64d(jwk.y), 33);
    return raw;
  }

  function importEcdhPublic(raw) {
    return crypto.subtle.importKey('raw', raw, { name: 'ECDH', namedCurve: 'P-256' },
      false, []);
  }

  function generateEcdh() {
    return crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' },
      true, ['deriveBits']);
  }

  function exportPublicRaw(pair) {
    return crypto.subtle.exportKey('jwk', pair.publicKey)
      .then(function (jwk) { return pubRawFromJwk(jwk); });
  }

  function verifySignature(signingPubB64, transcript, sigB64) {
    return importVerifyKey(b64d(signingPubB64))
      .then(function (key) {
        return crypto.subtle.verify(
          { name: 'ECDSA', hash: 'SHA-256' }, key, b64d(sigB64), transcript);
      });
  }

  function importVerifyKey(raw) {
    return crypto.subtle.importKey('raw', raw,
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  }

  // ---- fingerprints (TOFU pinning) ----

  function fingerprintOf(signingPubB64) {
    return sha256(b64d(signingPubB64)).then(function (h) {
      var s = hex(h).toUpperCase();
      return (s.match(/.{1,4}/g) || []).join(' ');
    });
  }

  function pinStatus(serverFp) {
    var known = null;
    try { known = localStorage.getItem(PIN_KEY); } catch (e) { known = null; }
    if (!known) {
      try { localStorage.setItem(PIN_KEY, serverFp); } catch (e) {}
      return 'new';
    }
    return known === serverFp ? 'ok' : 'changed';
  }

  function clearPin() {
    try { localStorage.removeItem(PIN_KEY); } catch (e) {}
  }

  // ---- channel ----

  function Channel() {
    this.sid = null;
    this.keys = {};
    this.ctrC2S = 0;
    this.ctrS2C = 0;
    this.fingerprint = null;
    this.pinState = 'new';
  }

  Channel.prototype.transcript = function (label, cPub, sEph, signing) {
    return enc.encode(P + '|' + label + '|' + b64e(cPub) + '|' +
      b64e(sEph) + '|' + b64e(signing));
  };

  Channel.prototype.derive = function (shared, transcriptBytes, sid) {
    var self = this;
    return sha256(transcriptBytes).then(function (salt) {
      return hkdf(shared, salt, P + ':root:' + sid);
    }).then(function (root) {
      var labels = {
        chain_ws_c2s: 'ws:c2s', chain_ws_s2c: 'ws:s2c',
        chain_http_c2s: 'http:c2s', chain_http_s2c: 'http:s2c',
        mac_c2s: 'mac:c2s', mac_s2c: 'mac:s2c'
      };
      return Promise.all(Object.keys(labels).map(function (name) {
        return hkdf(root, enc.encode(P), P + ':' + labels[name])
          .then(function (k) { self.keys[name] = k; });
      }));
    });
  };

  Channel.prototype.handshake = function (fetchJson) {
    var self = this;
    return fetchJson('/enc/hello', 'GET').then(function (info) {
      if (!info || info.error || !info.eph || !info.signing || !info.sid) {
        throw new Error('Handshake refused by the server' +
          (info && info.error ? ': ' + info.error : ' (malformed reply)') + '.');
      }
      var signingPub = b64d(info.signing);
      return fingerprintOf(info.signing).then(function (fp) {
        self.pinState = pinStatus(fp);
        self.fingerprint = fp;
        if (self.pinState === 'changed') {
          var prev = null;
          try { prev = localStorage.getItem(PIN_KEY); } catch (e) {}
          throw new Error('Server identity CHANGED — this connection may be ' +
            'intercepted. Was ' + prev + ', now ' + fp);
        }
        return generateEcdh().then(function (pair) {
          return exportPublicRaw(pair).then(function (cPub) {
            return fetchJson('/enc/hello/finish', 'POST',
              { sid: info.sid, eph: b64e(cPub) })
              .then(function (done) {
                var transcript = self.transcript(info.sid, cPub, b64d(info.eph),
                  signingPub);
                // Anti-MITM: the server must prove it holds the pinned key.
                return verifySignature(info.signing, transcript, done.sig)
                  .then(function (ok) {
                    if (!ok) {
                      throw new Error('Server signature invalid — possible ' +
                        'MITM attack.');
                    }
                    return importEcdhPublic(b64d(info.eph));
                  })
                  .then(function (serverEphKey) {
                    return crypto.subtle.deriveBits({ name: 'ECDH',
                      public: serverEphKey }, pair.privateKey, 256);
                  })
                  .then(function (shared) {
                    self.sid = info.sid;
                    return self.derive(shared, transcript, info.sid);
                  });
              });
          });
        });
      });
    });
  };

  function aesKey(bytes, usages) {
    return crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM' }, false, usages);
  }

  Channel.prototype.step = function (chain, nonce, label) {
    return hkdf(chain, nonce, P + ':msg:' + label).then(function (msgKey) {
      return hkdf(chain, nonce, P + ':chain:' + label).then(function (next) {
        return { key: msgKey, next: next };
      });
    });
  };

  // Per-socket keys: the server sends a random salt on connect and derives a
  // separate chain/counter per socket, so a page reload (new socket) can never
  // desynchronise an older one.
  Channel.prototype.socketMaterial = function (saltB64) {
    var self = this;
    var salt = b64d(saltB64);
    return Promise.all([
      hkdf(this.keys.chain_ws_c2s, salt, P + ':ws:c2s'),
      hkdf(this.keys.chain_ws_s2c, salt, P + ':ws:s2c'),
    ]).then(function (r) {
      self.wsC2S = r[0];
      self.wsS2C = r[1];
      self.ctrC2S = 0;
      self.ctrS2C = 0;
      return self;
    });
  };

  Channel.prototype.sealWs = function (obj) {
    var self = this;
    if (!this.wsC2S) return Promise.reject(new Error('Socket not ready.'));
    var nonce = crypto.getRandomValues(new Uint8Array(12));
    var ctr = this.ctrC2S++;
    return this.step(this.wsC2S, nonce, 'ws:c2s').then(function (s) {
      self.wsC2S = s.next;
      var body = enc.encode(JSON.stringify({ c: ctr, p: obj }));
      var aad = enc.encode(P + '|ws|c2s|' + ctr);
      return aesKey(s.key, ['encrypt']).then(function (k) {
        return crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce,
          additionalData: aad, tagLength: 128 }, k, body);
      });
    }).then(function (ct) {
      var out = new Uint8Array(12 + ct.byteLength);
      out.set(nonce, 0);
      out.set(new Uint8Array(ct), 12);
      return b64e(out);
    });
  };

  Channel.prototype.openWs = function (blob) {
    var self = this;
    if (!this.wsS2C) return Promise.reject(new Error('Socket not ready.'));
    var raw = b64d(blob);
    var nonce = raw.slice(0, 12);
    var ct = raw.slice(12);
    var ctr = this.ctrS2C++;
    return this.step(this.wsS2C, nonce, 'ws:s2c').then(function (s) {
      self.wsS2C = s.next;
      var aad = enc.encode(P + '|ws|s2c|' + ctr);
      return aesKey(s.key, ['decrypt']).then(function (k) {
        return crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce,
          additionalData: aad, tagLength: 128 }, k, ct);
      });
    }).then(function (plain) {
      return JSON.parse(dec.decode(plain)).p;
    });
  };

  // HTTP bodies use the session key with a random nonce (no ratchet): a
  // rejected request must not desynchronize the channel. These keys live only
  // as long as the channel session (one handshake per page load).
  Channel.prototype.encBody = function (obj, label, keyName) {
    var nonce = crypto.getRandomValues(new Uint8Array(12));
    var aad = enc.encode(P + '|http|' + label);
    return aesKey(this.keys[keyName], ['encrypt'])
      .then(function (k) {
        return crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce,
          additionalData: aad, tagLength: 128 }, k, enc.encode(JSON.stringify(obj)));
      }).then(function (ct) {
      var out = new Uint8Array(12 + ct.byteLength);
      out.set(nonce, 0);
      out.set(new Uint8Array(ct), 12);
      return b64e(out);
    });
  };

  Channel.prototype.decBody = function (blob, label, keyName) {
    var raw = b64d(blob);
    var nonce = raw.slice(0, 12);
    var aad = enc.encode(P + '|http|' + label);
    return aesKey(this.keys[keyName], ['decrypt'])
      .then(function (k) {
        return crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce,
          additionalData: aad, tagLength: 128 }, k, raw.slice(12));
      }).then(function (plain) { return JSON.parse(dec.decode(plain)); });
  };

  // request proof: base64(nonce || gcm tag) over the request metadata
  Channel.prototype.proof = function (method, path, bodyStr) {
    var self = this;
    var nonce = crypto.getRandomValues(new Uint8Array(12));
    var ts = Math.floor(Date.now() / 1000);
    return sha256Hex(enc.encode(bodyStr || '')).then(function (bodyHash) {
      var macInput = P + '|' + method.toUpperCase() + '|' + path + '|' + ts +
        '|' + b64e(nonce) + '|' + bodyHash;
      return hkdf(self.keys.mac_c2s, nonce, P + ':mac')
        .then(function (raw) { return aesKey(raw, ['encrypt']); })
        .then(function (key) {
          return crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce,
            additionalData: enc.encode(macInput), tagLength: 128 }, key,
            new Uint8Array(0));
        }).then(function (tag) {
          var out = new Uint8Array(12 + tag.byteLength);
          out.set(nonce, 0);
          out.set(new Uint8Array(tag), 12);
          return { ts: String(ts), mac: b64e(out) };
        });
    });
  };

  function sha256Hex(bytes) {
    return sha256(bytes).then(hex);
  }

  // Encrypted fetch wrapper: proves possession of the channel, encrypts the
  // body and decrypts the reply. No cookies are involved.
  function sealedFetch(path, sealed, proof, sid) {
    return fetch(path, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Enc-Sid': sid,
        'X-Enc-Ts': proof.ts,
        'X-Enc-Mac': proof.mac
      },
      body: sealed,
      credentials: 'same-origin'
    }).then(function (r) {
      return r.text().then(function (t) {
        var env;
        try { env = JSON.parse(t); } catch (e) {
          throw new Error('Encrypted channel failed (' + r.status + ').');
        }
        if (!env.e) throw new Error(env.error || 'Encrypted channel failed.');
        return env.e;
      });
    });
  }

  Channel.prototype.call = function (logicalPath, payload) {
    var self = this;
    var sealed, proof;
    return this.encBody(payload || {}, 'http:c2s', 'chain_http_c2s')
      .then(function (s) { sealed = s; return self.proof('POST', logicalPath, s); })
      .then(function (p) {
        proof = p;
        return sealedFetch('/enc' + logicalPath, sealed, proof, self.sid);
      })
      .then(function (blob) {
        return self.decBody(blob, 'http:s2c', 'chain_http_s2c');
      })
      .then(function (envelope) {
        if (envelope.status >= 400) {
          var err = new Error((envelope.data && envelope.data.error) ||
            'Request failed');
          err.status = envelope.status;
          throw err;
        }
        return envelope.data;
      });
  };

  Channel.prototype.login = function (username, password) {
    var self = this;
    var sealed, proof;
    return this.encBody({ username: username, password: password },
      'http:c2s', 'chain_http_c2s')
      .then(function (s) { sealed = s; return self.proof('POST', '/enc/login', s); })
      .then(function (p) {
        proof = p;
        return sealedFetch('/enc/login', sealed, proof, self.sid);
      })
      .then(function (blob) {
        return self.decBody(blob, 'http:s2c', 'chain_http_s2c');
      })
      .then(function (envelope) {
        if (envelope.status >= 400 || (envelope.data && envelope.data.error)) {
          throw new Error((envelope.data && envelope.data.error) || 'Login failed');
        }
        return envelope.data;
      });
  };

  // Session persistence: the channel keys live in sessionStorage (per tab,
  // cleared when the tab closes) so a page reload does not lose the session.
  // A network sniffer cannot read sessionStorage; the residual risk is a
  // script-injection attacker, which already compromises everything.
  var SESSION_KEY = 'chat-enc-session';

  Channel.prototype.exportState = function () {
    // Socket chain/counters are deliberately NOT persisted: each connection
    // negotiates fresh ones via socketMaterial().
    var out = { sid: this.sid, k: {} };
    var keys = ['chain_ws_c2s', 'chain_ws_s2c', 'chain_http_c2s',
      'chain_http_s2c', 'mac_c2s', 'mac_s2c'];
    for (var i = 0; i < keys.length; i++) {
      if (this.keys[keys[i]]) out.k[keys[i]] = b64e(this.keys[keys[i]]);
    }
    return out;
  };

  Channel.prototype.restoreState = function (state) {
    if (!state || !state.sid || !state.k) throw new Error('No channel state.');
    var keys = ['chain_ws_c2s', 'chain_ws_s2c', 'chain_http_c2s',
      'chain_http_s2c', 'mac_c2s', 'mac_s2c'];
    var missing = keys.filter(function (n) { return !state.k[n]; });
    if (missing.length) throw new Error('Incomplete channel state.');
    this.sid = state.sid;
    for (var i = 0; i < keys.length; i++) this.keys[keys[i]] = b64d(state.k[keys[i]]);
    this.wsC2S = this.wsS2C = null;
    this.ctrC2S = this.ctrS2C = 0;
    this.fingerprint = state.fp || null;
    return this;
  };

  function saveState(ch) {
    try {
      var st = ch.exportState();
      st.fp = ch.fingerprint;
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(st));
    } catch (e) { /* ignore */ }
  }

  function loadState() {
    try {
      var raw = sessionStorage.getItem(SESSION_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) { return null; }
  }

  function clearState() {
    try { sessionStorage.removeItem(SESSION_KEY); } catch (e) {}
  }

  return {
    P: P,
    Channel: Channel,
    b64e: b64e,
    b64d: b64d,
    sha256Hex: sha256Hex,
    clearPin: clearPin,
    saveState: saveState,
    loadState: loadState,
    clearState: clearState,
    pinState: function (fp) {
      var known = null;
      try { known = localStorage.getItem(PIN_KEY); } catch (e) {}
      return known ? (known === fp ? 'ok' : 'changed') : 'new';
    }
  };
})();