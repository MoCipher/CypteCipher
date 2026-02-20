use crate::bip39::Mnemonic as LocalMnemonic;
use crate::wallet_bdk::{BdkWallet, PersistentBdkWallet};
use bitcoin::Network;

/// UniFFI-compatible thin bridge functions consumed by mobile/native bindings.
/// These mirror the `cryptec.udl` UDL surface and delegate to existing core logic.

/// Generate a BIP39 mnemonic (wordlist phrase)
pub fn generate_mnemonic(strength: u32) -> String {
    // Accept strengths like 128, 160, 192, 224, 256
    let s = match strength {
        128 | 160 | 192 | 224 | 256 => strength as usize,
        _ => 128,
    };
    let m = LocalMnemonic::generate(s);
    m.phrase
}

/// Return the first (external 0) receive address for the given mnemonic (Testnet)
pub fn first_receive_address(mnemonic: &str) -> String {
    // Reuse the BDK wallet helper which already derives descriptors/addresses
    let w = match BdkWallet::new_from_mnemonic(mnemonic, "", Network::Testnet) {
        Ok(x) => x,
        Err(_) => return String::new(),
    };
    match w.get_new_address() {
        Ok(a) => a,
        Err(_) => String::new(),
    }
}

/// Create a PSBT (base64) using the mnemonic (Testnet)
pub fn create_psbt(mnemonic: &str, to_address: &str, satoshis: u64) -> String {
    let w = BdkWallet::new_from_mnemonic(mnemonic, "", Network::Testnet)
        .expect("create wallet");
    w.create_psbt(to_address, satoshis).expect("create psbt")
}

/// Sign a PSBT (base64) with the wallet's internal keys (Testnet)
pub fn sign_psbt(mnemonic: &str, psbt_b64: &str) -> String {
    let w = BdkWallet::new_from_mnemonic(mnemonic, "", Network::Testnet)
        .expect("create wallet");
    w.sign_psbt_base64(psbt_b64).expect("sign psbt")
}
