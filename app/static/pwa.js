/* Progressive-web-app plumbing: register the service worker.
 *
 * The worker itself caches nothing (see sw.js for why). This file's whole job
 * is to make the app installable, which needs a registered worker -- Chrome
 * offers "Install" only once one exists, and iOS needs one before it will
 * give a home-screen shortcut its own icon and no browser chrome.
 *
 * Kept in its own file, like every other concern here, and loaded on every
 * page: the registration has to have happened by the time the user looks for
 * the install prompt, and the prompt only appears on a visit.
 */
(function () {
  'use strict';

  if (!('serviceWorker' in navigator)) return;

  // A service worker needs a secure context. On plain HTTP over a network
  // address there is none, and the registration fails with a SecurityError
  // -- so there is nothing to register and no point trying.
  if (!window.isSecureContext) return;

  window.addEventListener('load', function () {
    // The worker is served from the root on purpose: a service worker's
    // scope can never be wider than the directory it came from, so a worker
    // at /static/sw.js could only ever control /static/ -- and a scope that
    // does not include the page registering it is refused outright.
    navigator.serviceWorker.register('/sw.js', { scope: '/' })
      .catch(function (err) {
        // A failed registration costs the install prompt and nothing else:
        // the app works exactly as it did before. Not worth a console
        // warning on every page load, so this stays quiet.
        if (window.console && console.debug) {
          console.debug('Service worker not registered:', err && err.message);
        }
      });
  });
})();
