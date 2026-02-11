use anyhow::Result;

/// Hardware wallet trait - minimal abstraction
pub trait HardwareWallet {
    fn get_xpub(&self, account: u32) -> Result<String>;
    fn sign_psbt(&self, psbt_b64: &str) -> Result<String>;
}

/// Ledger hardware wallet stub (placeholder)
pub struct LedgerHw {
    pub connected: bool,
}

impl LedgerHw {
    pub fn new() -> Self {
        // real implementation would use `hidapi` and APDU commands
        Self { connected: false }
    }
}

impl HardwareWallet for LedgerHw {
    fn get_xpub(&self, _account: u32) -> Result<String> {
        Err(anyhow::anyhow!("Ledger integration not implemented - stub"))
    }

    fn sign_psbt(&self, _psbt_b64: &str) -> Result<String> {
        Err(anyhow::anyhow!("Ledger sign_psbt not implemented - stub"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_stub_errors() {
        let l = LedgerHw::new();
        assert!(l.get_xpub(0).is_err());
        assert!(l.sign_psbt("").is_err());
    }
}
