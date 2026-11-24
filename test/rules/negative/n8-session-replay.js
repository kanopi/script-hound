// Legitimate-looking session replay: records inputs (masked) and ships batches to the vendor.
var buf = [];
document.addEventListener('input', function (e) { if (e.target.matches('input, select, textarea')) buf.push({ t: Date.now(), id: e.target.id, v: e.target.type === 'password' ? '***' : e.target.value.replace(/./g, '*') }); }, true);
setInterval(function () { if (buf.length) { navigator.sendBeacon('https://collect.replay-vendor.example/rec', JSON.stringify(buf.splice(0))); } }, 5000);
