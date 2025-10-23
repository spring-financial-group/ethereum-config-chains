// Add these details from the keystore file for the respective accounts
const keythereum = require('keythereum');

const keystore = {
  "address": "1d6197196c227e2be52c917b62343f7815638b2d",
  "crypto": {
    "cipher": "aes-128-ctr",
    "ciphertext": "8e3a95ae312a56c8a723720db12508b2ccdcaeba4c8af7e278f63d49308a39da",
    "cipherparams": {
      "iv": "6d52036553aa1cdac95fb026bc702709"
    },
    "kdf": "scrypt",
    "kdfparams": {
      "dklen": 32,
      "n": 262144,
      "p": 1,
      "r": 8,
      "salt": "b0b011bc849a3413380d2d5c51b0172403d982d958cd23077993758faaae92cb"
    },
    "mac": "81756ae7be4cb7b4097da9dd97e5a5e98112edaacbf8bc3635117c6836b55c0e"
  },
  "id": "0470d288-7f7c-4b19-94be-55115cbb9b1d",
  "version": 3
};

const password = "1"; // replace with the password for the keystore

const privateKey = keythereum.recover(password, keystore);
console.log("Private Key:", privateKey.toString("hex"));