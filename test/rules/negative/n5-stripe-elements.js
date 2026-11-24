// Legitimate: Stripe Elements with a publishable key; card data never touches page code.
var stripe = Stripe('pk_live_EXAMPLEEXAMPLE');
var card = stripe.elements().create('card');
card.mount('#card-element');
document.getElementById('payment-form').addEventListener('submit', async function (e) {
  e.preventDefault();
  var r = await stripe.createPaymentMethod({ type: 'card', card: card });
  await fetch('/checkout/confirm', { method: 'POST', body: JSON.stringify({ pm: r.paymentMethod.id }) });
});
