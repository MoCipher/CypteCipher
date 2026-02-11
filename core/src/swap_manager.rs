use anyhow::Result;
use serde_json::json;
use crate::monero::MoneroClient;
use crate::btc_htlc::{build_htlc_redeem_script, htlc_p2wsh_address};
use bitcoin::util::key::PublicKey;
use bitcoin::network::constants::Network;

/// High-level swap manager that ties BTC HTLC creation and Monero proofs together.
/// This is an orchestrator stub for automating swap steps.

pub struct SwapOffer {
    pub btc_sats: u64,
    pub xmr_piconero: u64,
    pub btc_hash: [u8;32],
    pub recipient_pub: PublicKey,
    pub refund_pub: PublicKey,
    pub locktime: u32,
}

impl SwapOffer {
    pub fn new(btc_sats: u64, xmr_piconero: u64, btc_hash: [u8;32], recipient_pub: PublicKey, refund_pub: PublicKey, locktime: u32) -> Self {
        Self { btc_sats, xmr_piconero, btc_hash, recipient_pub, refund_pub, locktime }
    }

    pub fn prepare_btc_htlc(&self, network: Network) -> serde_json::Value {
        let redeem = build_htlc_redeem_script(&self.btc_hash, &self.recipient_pub, &self.refund_pub, self.locktime);
        let addr = htlc_p2wsh_address(&redeem, network);
        json!({"address": addr.to_string(), "redeem_hex": hex::encode(redeem.to_bytes())})
    }

    pub fn verify_xmr_payment(&self, rpc_url: &str, username: Option<&str>, password: Option<&str>) -> Result<serde_json::Value> {
        let client = MoneroClient::new(rpc_url, username, password);
        // in real flow we'd watch for payment to integrated address and then request proof; here we just call get_balance as placeholder
        let bal = client.get_balance()?;
        Ok(json!({"balance": bal}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use rand::rngs::OsRng;

    #[test]
    fn prepare_swap_offer_btc_htlc() {
        let secp = Secp256k1::new();
        let sk1 = SecretKey::new(&mut OsRng::default());
        let sk2 = SecretKey::new(&mut OsRng::default());
        let pk1 = PublicKey { key: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk1), compressed: true };
        let pk2 = PublicKey { key: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk2), compressed: true };
        let mut h = [0u8;32];
        OsRng.fill_bytes(&mut h);
        let s = SwapOffer::new(1000, 1000000, h, pk1, pk2, 500);
        let out = s.prepare_btc_htlc(Network::Testnet);
        assert!(out.get("address").is_some());
    }
}
