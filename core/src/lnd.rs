use anyhow::Result;
use std::process::Command;
use serde_json::Value;

/// Lightweight wrapper that calls `lncli` if available. This is pragmatic for early integration
/// without pulling in gRPC/proto dependencies. For production, use direct gRPC (tonic + protos).
pub struct LndClient {
    pub host: String,
    pub macaroon_path: Option<String>,
}

impl LndClient {
    pub fn new(host: &str, macaroon_path: Option<&str>) -> Self {
        Self { host: host.to_string(), macaroon_path: macaroon_path.map(|s| s.to_string()) }
    }

    /// Call `lncli --rpcserver <host> getinfo` and parse JSON output (requires lncli in PATH)
    pub fn get_info(&self) -> Result<Value> {
        let mut cmd = Command::new("lncli");
        cmd.arg("--rpcserver").arg(&self.host).arg("getinfo");
        if let Some(m) = &self.macaroon_path {
            cmd.arg("--macaroonpath").arg(m);
        }
        let out = cmd.output()?;
        if !out.status.success() {
            return Err(anyhow::anyhow!("lncli call failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
        let s = String::from_utf8_lossy(&out.stdout);
        let v: Value = serde_json::from_str(&s)?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lncli_not_present_returns_err() {
        let c = LndClient::new("127.0.0.1:10009", None);
        let r = c.get_info();
        assert!(r.is_err());
    }
}
