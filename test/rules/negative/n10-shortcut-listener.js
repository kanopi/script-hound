// Legitimate: keyboard-shortcut handler (modeled on a font-service debug toggle). Checks keys, collects nothing.
document.addEventListener('keydown', function (c) { handler.apply(null, [c]); });
function handler(a) { if ((a.ctrlKey || a.metaKey) && a.altKey && a.keyCode === 70) { toggleFontDebug(); } var stack = []; stack.push(a.type); }
