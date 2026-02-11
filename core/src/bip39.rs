use bip39::{Language, Mnemonic as Bip39Mnemonic, Seed as Bip39Seed};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::network::constants::Network;

/// High-level mnemonic wrapper
pub struct Mnemonic {
    pub phrase: String,
}

impl Mnemonic {
    /// Generate a new BIP39 mnemonic with the given strength (entropy bits)
    pub fn generate(strength: usize) -> Self {
        let m = Bip39Mnemonic::new(bip39::MnemonicType::for_word_count((strength/32)*3).unwrap(), Language::English);
        Self { phrase: m.phrase().to_string() }
    }

    /// Create a mnemonic from an existing phrase (validation)
    pub fn from_phrase(phrase: &str) -> Result<Self, bip39::Error> {
        let _ = Bip39Mnemonic::from_phrase(phrase, Language::English)?;
        Ok(Self { phrase: phrase.to_string() })
    }

    /// Convert mnemonic (+optional passphrase) to BIP39 seed bytes
    pub fn to_seed_bytes(&self, passphrase: &str) -> [u8; 64] {
        let m = Bip39Mnemonic::from_phrase(&self.phrase, Language::English).expect("valid mnemonic");
        let seed = Bip39Seed::new(&m, passphrase);
        let bytes = seed.as_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes[0..64]);
        out
    }

    /// Derive master ExtendedPrivKey (BIP32) for the given network
    pub fn to_master_xprv(&self, passphrase: &str, network: Network) -> ExtendedPrivKey {
        let seed = self.to_seed_bytes(passphrase);
        ExtendedPrivKey::new_master(network, &seed).expect("master xprv")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::network::constants::Network;

    #[test]
    fn mnemonic_and_master() {
        let m = Mnemonic::generate(128);
        let seed = m.to_seed_bytes("");
        assert_eq!(seed.len(), 64);
        let xprv = m.to_master_xprv("", Network::Testnet);
        assert!(xprv.to_string().starts_with("tprv") || xprv.to_string().starts_with("xprv"));
    }
}
