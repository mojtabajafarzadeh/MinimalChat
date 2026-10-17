/* Login page logic.
   External rather than inline so the CSP needs no 'unsafe-inline': see
   app/security.py. */
(function () {
  'use strict';

  const form = document.getElementById('form');
  const err = document.getElementById('error');

  function show(msg) {
    err.textContent = msg;
    err.classList.remove('hidden');   // toggle the class, not style.display
  }

  Api.boot().then((st) => {
    if (!st.config.registration_enabled) {
      document.getElementById('register-link').classList.add('hidden');
    }
    return Api.me().then((u) => { location.href = '/chat'; }).catch(() => {});
  }).catch((e) => { show('Encrypted channel unavailable: ' + e.message); });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.classList.add('hidden');
    const btn = form.querySelector('button');
    btn.disabled = true;
    try {
      await Api.login(document.getElementById('username').value.trim(),
                      document.getElementById('password').value);
      location.href = '/chat';
    } catch (ex) {
      show(ex.message || 'Login failed.');
    } finally { btn.disabled = false; }
  });
})();
