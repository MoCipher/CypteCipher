use anyhow::Result;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Minimal Monero Wallet RPC client wrapper (blocking)
/// Note: This talks to `monero-wallet-rpc` JSON-RPC interface.
pub struct MoneroClient {
    pub rpc_url: String,
    pub client: Client,
    pub auth: Option<(String, String)>,
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcResponse<T> {
    jsonrpc: Option<String>,
    id: Option<String>,
    result: Option<T>,
    error: Option<serde_json::Value>,
}

impl MoneroClient {
    pub fn new(rpc_url: &str, username: Option<&str>, password: Option<&str>) -> Self {
        let client = Client::builder().build().unwrap();
        let auth = match (username, password) {
            (Some(u), Some(p)) => Some((u.to_string(), p.to_string())),
            _ => None,
        };
        Self { rpc_url: rpc_url.to_string(), client, auth }
    }

    fn rpc_call<T: for<'de> Deserialize<'de>>(&self, method: &str, params: serde_json::Value) -> Result<T> {
        let req = json!({"jsonrpc":"2.0","id":"0","method":method,"params":params});
        let mut r = self.client.post(&self.rpc_url);
        if let Some((u,p)) = &self.auth {
            r = r.basic_auth(u, Some(p));
        }
        let resp = r.json(&req).send()?;
        let v: RpcResponse<T> = resp.json()?;
        if let Some(err) = v.error {
            return Err(anyhow::anyhow!("monero rpc error: {}", err));
        }
        if let Some(res) = v.result {
            Ok(res)
        } else {
            Err(anyhow::anyhow!("empty monero rpc response"))
        }
    }

    pub fn get_balance(&self) -> Result<serde_json::Value> {
        // get_balance params: { "account_index": 0 }
        let r: serde_json::Value = self.rpc_call("get_balance", json!({}))?;
        Ok(r)
    }

    pub fn get_address(&self) -> Result<serde_json::Value> {
        let r: serde_json::Value = self.rpc_call("get_address", json!({}))?;
        Ok(r)
    }

    /// Create an integrated address (monero-wallet-rpc: make_integrated_address)
    pub fn make_integrated_address(&self, payment_id: Option<&str>) -> Result<serde_json::Value> {
        let params = if let Some(id) = payment_id { json!({"payment_id": id}) } else { json!({}) };
        let r: serde_json::Value = self.rpc_call("make_integrated_address", params)?;
        Ok(r)
    }

    pub fn transfer(&self, amount: u64, address: &str) -> Result<serde_json::Value> {
        // amount param is in atomic units; convert depending on monero units expectation
        let r: serde_json::Value = self.rpc_call("transfer", json!({"destinations":[{"amount":amount,"address":address}]}))?;
        Ok(r)
    }

    /// Request a tx proof (get_tx_proof) for an outgoing transaction id (or address/proof options)
    pub fn get_tx_proof(&self, txid: &str, address: Option<&str>) -> Result<serde_json::Value> {
        let params = if let Some(a) = address { json!({"txid": txid, "address": a}) } else { json!({"txid": txid}) };
        let r: serde_json::Value = self.rpc_call("get_tx_proof", params)?;
        Ok(r)
    }

    /// Check a tx proof (check_tx_proof)
    pub fn check_tx_proof(&self, txid: &str, address: &str, signature: &str) -> Result<serde_json::Value> {
        let r: serde_json::Value = self.rpc_call("check_tx_proof", json!({"txid": txid, "address": address, "signature": signature}))?;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monero_client_unreachable() {
        // Connect to a likely-unavailable endpoint; expect an error
        let c = MoneroClient::new("http://127.0.0.1:29999/json_rpc", None, None);
        let r = c.get_balance();
        assert!(r.is_err());
    }
}
