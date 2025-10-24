import { ethers } from 'ethers';

const mnemonic = "giant issue aisle success illegal bike spike question tent bar rely arctic volcano long crawl hungry vocal artwork sniff fantasy very lucky have athlete";
const derivationPath = "m/44'/60'/0'/0/";

console.log('{\n  "mnemonic": "' + mnemonic + '",');
console.log('  "derivation_path": "' + derivationPath + '{index}",');
console.log('  "accounts": [');

for (let i = 0; i < 20; i++) {
  const wallet = ethers.HDNodeWallet.fromPhrase(mnemonic, undefined, derivationPath + i);
  const comma = i < 19 ? ',' : '';
  console.log(`    {"index": ${i}, "address": "${wallet.address}", "privateKey": "${wallet.privateKey}"}${comma}`);
}

console.log('  ]\n}');
