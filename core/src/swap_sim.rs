use anyhow::Result;
use serde_json::json;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha256, Digest};

/// Simple in-process BTC<->XMR swap simulation (for testing and demonstration only)
/// This does not interact with real networks — it simulates the protocol flow using generated preimages.

pub struct SwapSimulation {
    pub preimage: Vec<u8>,
    pub hash: Vec<u8>,
    pub btc_sats: u64,
    pub xmr_piconero: u64,
}

impl SwapSimulation {
    pub fn new(btc_sats: u64, xmr_piconero: u64) -> Self {
        let mut pre = vec![0u8; 32];
        OsRng.fill_bytes(&mut pre);
        let mut hasher = Sha256::new();
        hasher.update(&pre);
        let h = hasher.finalize().to_vec();
        Self { preimage: pre, hash: h, btc_sats, xmr_piconero }
    }

    /// Maker creates BTC HTLC (simulated) and XMR integrated address
    pub fn maker_create_offer(&self) -> serde_json::Value {
        json!({
            "btc_htlc_hash": hex::encode(&self.hash),
            "xmr_amount": self.xmr_piconero,
        })
    }

    /// Taker observes XMR payment (simulated) and provides a proof object (simulated)
    pub fn taker_provide_proof(&self) -> serde_json::Value {
        // Simulate proof containing txid placeholder and amount
        json!({"txid":"simulated-xmr-txid","amount": self.xmr_piconero })
    }

    /// Maker validates proof (simulated) and provides preimage to redeem BTC HTLC
    pub fn maker_validate_and_reveal(&self, proof: serde_json::Value) -> serde_json::Value {
        // In real flow verify proof on Monero node; here assume proof valid
        json!({"status":"proof_valid","preimage": hex::encode(&self.preimage)})
    }

    /// Taker uses revealed preimage to redeem BTC HTLC (simulated)
    pub fn taker_redeem_with_preimage(&self, preimage_hex: &str) -> serde_json::Value {
        let pre = hex::decode(preimage_hex).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&pre);
        let h = hasher.finalize().to_vec();
        let ok = h == self.hash;
        json!({"redeem_ok": ok})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulate_swap_flow() {
        let sim = SwapSimulation::new(1000, 1000000);
        let offer = sim.maker_create_offer();
        assert!(offer.get("btc_htlc_hash").is_some());
        let proof = sim.taker_provide_proof();
        let reveal = sim.maker_validate_and_reveal(proof);
        assert!(reveal.get("preimage").is_some());
        let prehex = reveal.get("preimage").unwrap().as_str().unwrap();
        let redeem = sim.taker_redeem_with_preimage(prehex);
        assert_eq!(redeem.get("redeem_ok").unwrap().as_bool().unwrap(), true);
    }
}