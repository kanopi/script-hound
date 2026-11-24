// Legitimate: saves contact-form progress (no card fields) to localStorage.
document.querySelectorAll('#contact-form input, #contact-form textarea').forEach(function (el) {
  el.value = localStorage.getItem('draft_' + el.name) || el.value;
  el.addEventListener('input', function () { localStorage.setItem('draft_' + el.name, el.value); });
});
