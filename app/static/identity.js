/* Server-identity verification panel.
 *
 * The fingerprint the page shows comes from the same connection it is meant to
 * verify, so on its own it proves nothing: anyone intercepting the connection
 * can serve their own key and their own fingerprint. What makes it useful is
 * comparing it against a copy the operator obtained out of band -- the server
 * console, its logs, over SSH -- which is why run.py prints it at startup.
 *
 * This module is deliberately read-mostly: it shows what the connection
 * presents, what this browser has pinned, and lets a human compare the two. It
 * never pins on its own initiative.
 */
(function () {
  'use strict';

  var Api = window.Api;
  var Enc = window.Enc;

  var refreshers = [];
  var userToggled = false;

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function fingerprintCells(labelText, value, extra) {
    var row = el('div', 'identity-row');
    row.appendChild(el('span', 'identity-key', labelText));
    var code = el('code', 'identity-value', value || '—');
    row.appendChild(code);
    if (extra) row.appendChild(extra);
    return { row: row, code: code };
  }

  function copyButton(getValue) {
    var btn = el('button', 'btn btn-secondary btn-sm', 'copy');
    btn.type = 'button';
    btn.title = 'Copy to clipboard';
    btn.addEventListener('click', function () {
      var value = getValue();
      if (!value) return;
      if (navigator.clipboard) navigator.clipboard.writeText(value);
      btn.textContent = 'copied';
      setTimeout(function () { btn.textContent = 'copy'; }, 1500);
    });
    return btn;
  }

  function mount(container) {
    if (!container || !Api) return;

    var section = el('section', 'identity');
    section.setAttribute('aria-label', 'Server identity');

    var toggle = el('button', 'identity-toggle');
    toggle.type = 'button';
    toggle.setAttribute('aria-expanded', 'false');
    var toggleLabel = el('span', null, 'Server identity');
    var toggleHint = el('span', 'identity-toggle-hint');
    toggle.appendChild(toggleLabel);
    toggle.appendChild(toggleHint);

    var body = el('div', 'identity-body hidden');
    var live = fingerprintCells('This connection', '', copyButton(function () {
      return live.code.textContent === '—' ? null : live.code.textContent;
    }));
    var pinned = fingerprintCells('Pinned in this browser', '', null);
    var forget = el('button', 'btn btn-ghost btn-sm', 'forget pin');
    forget.type = 'button';
    pinned.row.appendChild(forget);

    var form = el('form', 'identity-form');
    var label = el('label', 'label', 'Fingerprint from a trusted source');
    label.htmlFor = 'identity-expected';
    var input = el('input', 'input identity-input');
    input.id = 'identity-expected';
    input.type = 'text';
    input.autocomplete = 'off';
    input.spellcheck = false;
    input.placeholder = 'paste the value printed by the server';
    var submit = el('button', 'btn', 'Verify and pin');
    submit.type = 'submit';
    form.appendChild(label);
    form.appendChild(input);
    form.appendChild(submit);

    var result = el('p', 'identity-result');
    result.setAttribute('role', 'status');
    result.setAttribute('aria-live', 'polite');

    var hint = el('p', 'identity-hint');
    hint.id = 'identity-hint';
    input.setAttribute('aria-describedby', 'identity-hint');
    hint.textContent =
      'Read it from the server itself — its console prints it at startup — ' +
      'not from this page. A fingerprint served by this page could have been ' +
      'written by whatever is intercepting the connection.';

    body.appendChild(live.row);
    body.appendChild(pinned.row);
    body.appendChild(form);
    body.appendChild(result);
    body.appendChild(hint);
    section.appendChild(toggle);
    section.appendChild(body);
    container.appendChild(section);

    function liveFingerprint() {
      return Api.fingerprint() || null;
    }

    function refresh() {
      var value = liveFingerprint();
      live.code.textContent = value || '—';
      var pin = Api.pinnedFingerprint();
      pinned.code.textContent = pin || 'not pinned';
      pinned.code.classList.toggle('is-bad', !!pin && !!value && pin !== value);
      forget.disabled = !pin;

      if (!value) {
        // Plain mode has no server identity to verify.
        section.classList.add('hidden');
        return false;
      }
      section.classList.remove('hidden');

      var state = Api.pinState();
      toggleHint.textContent =
        state === 'changed' ? 'changed — verify'
        : state === 'new' ? 'pinned automatically'
        : 'pinned';
      toggleHint.className = 'identity-toggle-hint' +
        (state === 'changed' ? ' is-bad' : '');
      return true;
    }

    function setOpen(open) {
      body.classList.toggle('hidden', !open);
      toggle.setAttribute('aria-expanded', String(open));
      if (open) {
        refresh();
        input.focus();
      }
    }

    toggle.addEventListener('click', function () {
      userToggled = true;
      setOpen(body.classList.contains('hidden'));
    });

    forget.addEventListener('click', function () {
      Api.clearPin();
      input.value = '';
      result.textContent = '';
      result.className = 'identity-result';
      refresh();
      toggleHint.textContent = 'pin cleared — reconnect to pin again';
    });

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var outcome = Api.verifyFingerprint(input.value);
      result.textContent = outcome.message;
      result.className = 'identity-result ' + (outcome.ok ? 'is-ok' : 'is-bad');
      if (outcome.ok) {
        input.value = outcome.live;
      } else if (outcome.reason === 'mismatch' && outcome.expected) {
        // Keep what they pasted visible next to the live value so the two can
        // be compared by eye, which is the entire point of the panel.
        input.value = outcome.expected;
      }
      refresh();
    });

    // A changed identity is the one case where hiding this behind a toggle
    // would be wrong -- and it is also learned after this script runs, because
    // the handshake rejects. So react on every announcement until the operator
    // touches the toggle themselves.
    //
    // Registered before the first refresh, with no early return when there is
    // no fingerprint yet: on the auth pages this runs before the handshake
    // resolves, so bailing out here would leave the panel hidden forever.
    refreshers.push(react);
    react();

    function react() {
      refresh();
      if (!userToggled && Api.state && Api.state.identityChanged) setOpen(true);
    }
  }

  function init() {
    var target = document.getElementById('identity-panel');
    if (target) mount(target);
    document.addEventListener('chat:identity', function () {
      refreshers.forEach(function (fn) { fn(); });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  window.Identity = { mount: mount, normalize: Enc ? Enc.normalizeFingerprint : null };
})();