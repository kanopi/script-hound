// Legitimate: support chat widget; messages are parsed as JSON, never executed.
var ws = new WebSocket('wss://chat.vendor.example/socket');
ws.addEventListener('message', function (event) {
  var msg = JSON.parse(event.data);
  var li = document.createElement('li'); li.textContent = msg.text; document.getElementById('chat').appendChild(li);
});
document.getElementById('chat-form').addEventListener('submit', function (e) { e.preventDefault(); ws.send(JSON.stringify({ text: document.getElementById('chat-input').value })); });
