/* Apply the saved theme before first paint to avoid a flash. Classic script, loaded synchronously
   from <head> (an inline script would need a CSP exception). Keep in sync with js/theme.js */
(function () {
  var pref = 'auto';
  try { pref = localStorage.getItem('pathwatch.theme') || 'auto'; } catch (e) {}
  var known = ['auto','light','dark','midnight','nord','solarized-light','solarized-dark','high-contrast','classic'];
  if (known.indexOf(pref) < 0) pref = 'auto';
  var t = pref;
  if (pref === 'auto') {
    t = (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
  }
  var d = document.documentElement;
  d.setAttribute('data-theme', t);
  d.setAttribute('data-theme-pref', pref);
})();
