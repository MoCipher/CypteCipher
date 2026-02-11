//! CrypteCipher core (skeleton)
//!
//! This crate contains the core primitives (seed generation, key derivation, network interfaces).
//! It's a minimal skeleton; do NOT consider this production-ready. Use as a starting point.

use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::SecretKey;

mod btc;
mod bip39;
mod wallet_bdk;
mod lightning;
mod keystore;
mod hardware;
mod lnd;
mod monero;
mod wallet_manager;

pub use btc::BtcWallet;
pub use bip39::Mnemonic;
pub use wallet_bdk::{BdkWallet, PersistentBdkWallet, DecryptedDb, InMemoryDb};
pub use lightning::LightningClient;
pub use keystore::{encrypt_seed_file, decrypt_seed_file, decrypt_file_to_memory, store_password_in_keyring, retrieve_password_from_keyring};
pub use hardware::{HardwareWallet, LedgerHw};
pub use lnd::LndClient;
pub use monero::MoneroClient;
pub use monero_swap::{AtomicSwap, SwapRole};
pub use swap_manager::SwapOffer;
pub use swap_sim::SwapSimulation;
pub use wallet_manager::{register_decrypted_db, close_decrypted_db, register_inmemory_db, close_inmemory_db, close_all, list_handles};

/// WalletCore: minimal demonstrative API
pub struct WalletCore {
    // In a real implementation, secrets should be stored in a secure enclave or encrypted storage
    pub(crate) seed: [u8; 32],
}

impl WalletCore {
    /// Generate a new random seed using system CSPRNG
    pub fn generate_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        seed
    }

    /// Create a new core instance with a fresh seed
    pub fn new() -> Self {
        let s = Self::generate_seed();
        Self { seed: s }
    }

    /// Example: derive an example secp256k1 private key from the seed (NOT a full HD derivation)
    pub fn example_btc_privkey_hex(&self) -> String {
        // This is ONLY an example; implement BIP32/BIP39 derivation in production
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.seed);
        // Use SecretKey::from_slice to show how to validate
        let sk = SecretKey::from_slice(&buf).expect("seed must be valid sk");
        hex::encode(sk.secret_bytes())
    }

    /// Return a public-facing fingerprint (for demo/testing)
    pub fn fingerprint(&self) -> String {
        // Return first 8 hex chars of seed as fingerprint
        hex::encode(&self.seed[0..8])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_seed_len() {
        let s = WalletCore::generate_seed();
        assert_eq!(s.len(), 32);
    }

    #[test]
    fn example_privkey() {
        let w = WalletCore::new();
        let hex = w.example_btc_privkey_hex();
        assert_eq!(hex.len(), 64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_seed_len() {
        let s = WalletCore::generate_seed();
        assert_eq!(s.len(), 32);
    }

    #[test]
    fn example_privkey() {
        let w = WalletCore::new();
        let hex = w.example_btc_privkey_hex();
        assert_eq!(hex.len(), 64);
    }
}
