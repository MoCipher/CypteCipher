import { NativeModules } from 'react-native';
import * as bip39 from 'bip39';
import * as bitcoin from 'bitcoinjs-lib';

const NETWORK = bitcoin.networks.testnet;

// If a native mobile binding (UniFFI) is installed, use it. Otherwise fall back to JS mock.
const NativeCryptec: any = (NativeModules && (NativeModules.Cryptec || NativeModules.CryptecModule)) || null;

async function generateMnemonicNative(strength = 128): Promise<string> {
  if (NativeCryptec && NativeCryptec.generate_mnemonic) {
    return await NativeCryptec.generate_mnemonic(strength);
  }
  return bip39.generateMnemonic(strength);
}

function firstReceiveAddressFromMnemonicNative(mnemonic: string): string {
  if (NativeCryptec && NativeCryptec.first_receive_address) {
    try {
      return NativeCryptec.first_receive_address(mnemonic);
    } catch (e) {
      // fallback to JS
    }
  }
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const root = bitcoin.bip32.fromSeed(seed, NETWORK);
  const child = root.derivePath("m/84'/1'/0'/0/0");
  const { publicKey } = child;
  const { address } = bitcoin.payments.p2wpkh({ pubkey: publicKey, network: NETWORK });
  return address || '';
}

async function createPsbtNative(mnemonic: string, toAddress: string, satoshis: number): Promise<string> {
  if (NativeCryptec && NativeCryptec.create_psbt) {
    return await NativeCryptec.create_psbt(mnemonic, toAddress, satoshis);
  }
  const payload = { type: 'psbt-mock', to: toAddress, sats: satoshis };
  return Buffer.from(JSON.stringify(payload)).toString('base64');
}

async function signPsbtNative(mnemonic: string, psbtB64: string): Promise<string> {
  if (NativeCryptec && NativeCryptec.sign_psbt) {
    return await NativeCryptec.sign_psbt(mnemonic, psbtB64);
  }
  const decoded = Buffer.from(psbtB64, 'base64').toString('utf8');
  const payload = { signed: true, original: decoded };
  return Buffer.from(JSON.stringify(payload)).toString('base64');
}

export default {
  generateMnemonic: generateMnemonicNative,
  firstReceiveAddressFromMnemonic: firstReceiveAddressFromMnemonicNative,
  createPsbtMock: createPsbtNative,
  signPsbtMock: signPsbtNative
};
