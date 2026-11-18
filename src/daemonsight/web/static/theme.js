// Runs in <head>, before the page paints. With the theme set to "Auto" (the
// theme cookie says "auto", which the server writes as data-theme-pref), follow
// the system's colour scheme and keep following it:
// https://developer.mozilla.org/en-US/docs/Web/CSS/@media/prefers-color-scheme
// Light and Dark need no script: the server writes data-bs-theme itself.
(function () {
  "use strict";
  var root = document.documentElement;
  if (root.getAttribute("data-theme-pref") !== "auto" || !window.matchMedia) return;
  var query = window.matchMedia("(prefers-color-scheme: dark)");
  function apply() { root.setAttribute("data-bs-theme", query.matches ? "dark" : "light"); }
  apply();
  query.addEventListener("change", apply);
}());
