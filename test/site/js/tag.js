// Stand-in for a tag manager: injects an inline "Custom HTML" tag at runtime.
// The debugger statement checks that origin tracing never stalls the page.
debugger;
setTimeout(function () {
  var s = document.createElement('script');
  s.text = 'window.__tagFired = "custom-html-tag";';
  document.body.appendChild(s);
}, 20);

// Interaction-gated loads, like skimmers that wait for a human: one on first scroll, one on card typing.
function load(src) {
  var s = document.createElement('script');
  s.src = src;
  document.head.appendChild(s);
}
window.addEventListener('scroll', function onScroll() {
  window.removeEventListener('scroll', onScroll);
  load('/js/on-scroll.js');
});
document.addEventListener('input', function onInput(e) {
  if (e.target && e.target.name === 'cc_number') {
    document.removeEventListener('input', onInput);
    load('/js/on-input.js');
  }
});
// Loads only when the "show card form" button is clicked (exercised by custom interaction steps).
document.addEventListener('click', function (e) {
  if (e.target && e.target.id === 'show-pay') load('/js/on-click.js');
});
