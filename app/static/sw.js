/* MChat service worker -- deliberately almost empty.
 *
 * Its only job is to make the app installable: a registered service worker with
 * a fetch handler is what Chrome requires before it will offer "Install", and
 * what iOS needs before it will allow a home-screen shortcut with its own
 * icon and no browser chrome.
 *
 * It deliberately does NOT cache anything.
 *
 *   - The channel keys live in the page's sessionStorage, which a service
 *     worker cannot read. So even if the responses were cached, they could
 *     never be decrypted: the cache would hold ciphertext with no key beside
 *     it.
 *   - The responses are the user's messages. Caching them would put message
 *     bodies on disk in the browser's cache storage, where they outlive the
 *     session and are not covered by the app's own storage policy.
 *   - A cache-first strategy would serve stale messages to a client that has
 *     no way to tell they are stale.
 *
 * So: no fetch handler at all, no caches, no push. Anything the app wants
 * cached later has to be decided on its own merits, and the notification
 * feature's ceiling (a service worker cannot read the channel keys) has to be
 * re-checked before that.
 *
 * One thing it does do is claim clients, so a future version can replace it
 * without leaving half the population running an old worker.
 */
self.addEventListener('install', function (event) {
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  event.waitUntil(self.clients.claim());
});
