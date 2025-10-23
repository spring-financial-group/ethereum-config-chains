// CommonJS, Node 18+ (works on Node v22)
// Reads alloc from ../genesis.json and queries balances via HTTP JSON-RPC.

const fs = require('fs');
const path = require('path');

const PROVIDER_URL = process.env.RPC_URL || 'https://rpc-geth-node.mqube-playground.com'
const GENESIS = path.resolve(__dirname, '../helm-configs/genesis.json');

// minimal wei->ether formatter using BigInt
function formatEther(weiHexOrDec) {
  let wei;
  if (typeof weiHexOrDec === 'string' && weiHexOrDec.startsWith('0x')) {
    wei = BigInt(weiHexOrDec);
  } else {
    wei = BigInt(weiHexOrDec);
  }
  const base = 10n ** 18n;
  const whole = wei / base;
  const frac = wei % base;
  const fracStr = frac.toString().padStart(18, '0').replace(/0+$/,'') || '0';
  return `${whole.toString()}.${fracStr}`;
}

async function rpc(method, params) {
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
  const res = await fetch(PROVIDER_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body
  });
  if (!res.ok) {
    throw new Error(`RPC HTTP ${res.status}: ${await res.text()}`);
  }
  const json = await res.json();
  if (json.error) throw new Error(JSON.stringify(json.error));
  return json.result;
}

(async () => {
  const genesis = JSON.parse(fs.readFileSync(GENESIS, 'utf8'));
  const addrs = Object.keys(genesis.alloc || {});
  if (addrs.length === 0) {
    console.log('No alloc entries found in genesis.json');
    process.exit(0);
  }

  // Batch requests in chunks to be polite
  const chunkSize = 50;
  for (let i = 0; i < addrs.length; i += chunkSize) {
    const chunk = addrs.slice(i, i + chunkSize);

    // JSON-RPC batch
    const batch = chunk.map((addr, idx) => ({
      jsonrpc: '2.0',
      id: idx + 1,
      method: 'eth_getBalance',
      params: [addr, 'latest']
    }));

    const res = await fetch(PROVIDER_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(batch)
    });

    if (!res.ok) {
      throw new Error(`RPC HTTP ${res.status}: ${await res.text()}`);
    }
    const replies = await res.json();

    // replies is an array in the same order as batch (most nodes keep order)
    for (let j = 0; j < chunk.length; j++) {
      const addr = chunk[j];
      const reply = replies[j];
      if (reply.error) {
        console.log(`${addr} ERROR ${JSON.stringify(reply.error)}`);
      } else {
        const weiHex = reply.result; // e.g., "0x16345785d8a0000"
        console.log(`${addr} ${formatEther(weiHex)} ETH`);
      }
    }
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});

