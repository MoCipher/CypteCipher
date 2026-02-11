/// Skeleton Lightning client abstraction
/// Supports external-node connection (e.g., LND/gRPC) and a placeholder for in-process rust-lightning

pub enum LightningBackend {
    ExternalNode { host: String, macaroon_path: Option<String>, tls_cert_path: Option<String> },
    InProcessPlaceholder,
}

pub struct LightningClient {
    backend: LightningBackend,
}

impl LightningClient {
    /// Create client that will connect to an external node (LND/c-lightning adapters can be added)
    pub fn connect_external(host: &str, macaroon_path: Option<&str>, tls_cert_path: Option<&str>) -> Self {
        Self {
            backend: LightningBackend::ExternalNode {
                host: host.to_string(),
                macaroon_path: macaroon_path.map(|s| s.to_string()),
                tls_cert_path: tls_cert_path.map(|s| s.to_string()),
            }
        }
    }

    /// Create an in-process placeholder (use rust-lightning integration later)
    pub fn placeholder() -> Self {
        Self { backend: LightningBackend::InProcessPlaceholder }
    }

    /// Example: return a status string (shows backend mode) - replace with real RPC calls later
    pub fn status(&self) -> String {
        match &self.backend {
            LightningBackend::ExternalNode { host, .. } => format!("connected to external node at {}", host),
            LightningBackend::InProcessPlaceholder => "in-process rust-lightning placeholder".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lightning_placeholder_status() {
        let c = LightningClient::placeholder();
        assert!(c.status().contains("placeholder"));

        let e = LightningClient::connect_external("127.0.0.1:10009", None, None);
        assert!(e.status().contains("127.0.0.1"));
    }
}
