const { contextBridge } = require('electron');

let nativeBindings = null;
try {
  // Try to require the Node bindings package (napi). If not available, fall back to a JS shim.
  nativeBindings = require(pathJoin(__dirname, '..', 'bindings'));
} catch (e) {
  // ignore
}

function pathJoin(...parts) {
  return parts.join('/');
}

const shim = {
  generate_mnemonic: (strength = 128) => {
    // simple in-process fallback
    const crypto = require('crypto');
    // use 128-bit entropy => 12 words via bip39 library if available
    try {
      const bip39 = require('bip39');
      return bip39.generateMnemonic(strength);
    } catch (e) {
      return crypto.randomBytes(16).toString('hex');
    }
  },
  first_receive_address: (mnemonic) => {
    try {
      const bip39 = require('bip39');
      const bitcoin = require('bitcoinjs-lib');
      const seed = bip39.mnemonicToSeedSync(mnemonic);
      const root = bitcoin.bip32.fromSeed(seed, bitcoin.networks.testnet);
      const child = root.derivePath("m/84'/1'/0'/0/0");
      const { address } = bitcoin.payments.p2wpkh({ pubkey: child.publicKey, network: bitcoin.networks.testnet });
      return address || '';
    } catch (e) {
      return '';
    }
  },
  create_psbt: (_mnemonic, toAddress, satoshis) => {
    return Buffer.from(JSON.stringify({ type: 'psbt-mock', to: toAddress, sats: satoshis })).toString('base64');
  },
  sign_psbt: (_mnemonic, psbtB64) => {
    const decoded = Buffer.from(psbtB64, 'base64').toString('utf8');
    return Buffer.from(JSON.stringify({ signed: true, original: decoded })).toString('base64');
  }
};

const api = nativeBindings ? nativeBindings : shim;

contextBridge.exposeInMainWorld('cryptec', {
  generateMnemonic: (strength) => api.generate_mnemonic ? api.generate_mnemonic(strength) : api.generate_mnemonic(strength),
  firstReceiveAddress: (mnemonic) => api.first_receive_address ? api.first_receive_address(mnemonic) : api.first_receive_address(mnemonic),
  createPsbt: (mnemonic, to, sats) => api.create_psbt ? api.create_psbt(mnemonic, to, sats) : api.create_psbt(mnemonic, to, sats),
  signPsbt: (mnemonic, psbtB64) => api.sign_psbt ? api.sign_psbt(mnemonic, psbtB64) : api.sign_psbt(mnemonic, psbtB64)
});