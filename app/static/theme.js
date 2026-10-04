/* Shared theme toggle: light/dark via [data-theme], persisted in localStorage.
   Include this script in <head> so the theme applies before first paint. */
(function () {
  'use strict';

  function stored() {
    try { return localStorage.getItem('chat-theme'); } catch (e) { return null; }
  }

  function paint(btn, theme) {
    btn.textContent = theme === 'dark' ? '☀️' : '🌙';
    btn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
    btn.setAttribute('title', theme === 'dark' ? 'Light mode' : 'Dark mode');
  }

  function apply(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    Array.prototype.forEach.call(
      document.querySelectorAll('[data-theme-toggle]'),
      function (btn) { paint(btn, theme); }
    );
    try { localStorage.setItem('chat-theme', theme); } catch (e) { /* private mode */ }
  }

  var initial = stored();
  if (initial !== 'light' && initial !== 'dark') {
    initial = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)
      ? 'dark' : 'light';
  }
  // Paint ASAP; if <head> hasn't got buttons yet, DOMContentLoaded repaints.
  apply(initial);
  document.addEventListener('DOMContentLoaded', function () { apply(currentTheme()); });

  function currentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  }

  document.addEventListener('click', function (e) {
    var t = e.target && e.target.closest ? e.target.closest('[data-theme-toggle]') : null;
    if (!t) return;
    e.preventDefault();
    apply(currentTheme() === 'dark' ? 'light' : 'dark');
  });
})();
