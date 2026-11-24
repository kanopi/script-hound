// Legitimate: NFT gallery reads a token URI from a contract and shows the image (no script loading).
fetch('https://rpc.vendor.example/', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: '0x0000000000000000000000000000000000000001', data: '0xc87b56dd' }, 'latest'] }) })
  .then(function (r) { return r.json(); })
  .then(function (j) { var img = document.createElement('img'); img.src = 'https://ipfs.vendor.example/' + j.result.slice(2, 50); document.getElementById('gallery').appendChild(img); });
