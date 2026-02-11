use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::key::PrivateKey;
use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::{Digest, Sha256};

/// Simple Bitcoin on-chain wallet helper (minimal, safe-by-default)
///
/// This implements a deterministic derivation of a single private key from the core seed
/// purely for demonstration and testing. In production use **BIP32/BIP39** HD derivation
/// and robust UTXO management (e.g., `bdk`).
pub struct BtcWallet {
    secret_key: SecretKey,
    network: Network,
}

impl BtcWallet {
    /// Derive a secret key deterministically from a seed and domain tag
    pub fn derive_from_seed(seed: &[u8; 32], network: Network, tag: &[u8]) -> Self {
        // Use SHA256(seed || tag) as a simple DRBG to get 32 bytes -> SecretKey
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(tag);
        let hash = hasher.finalize();
        let sk = SecretKey::from_slice(&hash).expect("hash must be a valid secret key");
        Self { secret_key: sk, network }
    }

    /// Return the P2WPKH bech32 address for this key
    pub fn get_address(&self) -> Address {
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &self.secret_key);
        let compressed = PublicKey::new(pk.key);
        let pk_hash = bitcoin::hashes::hash160::Hash::hash(&compressed.serialize());
        Address::p2wpkh(&pk, self.network).expect("address creation")
    }

    /// Return the private key in WIF format (useful for tests/examples only)
    pub fn wif(&self) -> String {
        let pk = PrivateKey { key: self.secret_key, network: self.network, compressed: true };
        pk.to_wif()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WalletCore;

    #[test]
    fn derive_and_address() {
        let core = WalletCore::new();
        let seed = core.seed; // NOTE: demo access to seed (in real code seed would be private)
        let wallet = BtcWallet::derive_from_seed(&seed, Network::Testnet, b"cryptec-btc");
        let addr = wallet.get_address();
        assert!(addr.to_string().starts_with("tb1") || addr.to_string().starts_with("2") );
        let wif = wallet.wif();
        assert!(!wif.is_empty());
    }
}
