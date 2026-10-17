/* Register page logic.
   External rather than inline so the CSP needs no 'unsafe-inline'. */
(function () {
  'use strict';

  const form = document.getElementById('form');
  const err = document.getElementById('error');

  function show(msg) {
    err.textContent = msg;
    err.classList.remove('hidden');
  }

  Api.boot().then((st) => {
    if (!st.config.registration_enabled) {
      show('Registration is disabled on this server.');
      form.querySelector('button').disabled = true;
    }
  }).catch((e) => { show('Encrypted channel unavailable: ' + e.message); });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.classList.add('hidden');
    const btn = form.querySelector('button');
    btn.disabled = true;
    try {
      await Api.register(document.getElementById('name').value.trim(),
                         document.getElementById('username').value.trim(),
                         document.getElementById('password').value,
                         document.getElementById('confirm').value);
      location.href = '/chat';
    } catch (ex) {
      show(ex.message || 'Registration failed.');
    } finally { btn.disabled = false; }
  });
})();
