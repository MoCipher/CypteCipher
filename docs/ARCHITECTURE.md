# Architecture (High level)

## Goals
- **Non-custodial**: Users control seeds and private keys.
- **Privacy-first**: No KYC by default; Monero and coin selection for privacy.
- **Multi-currency**: Bitcoin (on-chain & Lightning) and Monero.
- **Secure**: Core crypto in Rust, audited libs, hardware wallet support optional.

## Components
- Core (Rust): seed management, key derivation (BIP32/BIP39), Bitcoin on-chain interactions (rust-bitcoin), Lightning (rust-lightning or external node), Monero interactions (via RPC to `monerod`/`monero-wallet-rpc`), atomic swap scaffolding.
- Bindings: N-API (napi-rs) for desktop & Electron, native wrappers for iOS/Android to call Rust.
- Mobile: React Native (TypeScript) calling native module.
- Desktop: Electron + React using Node bindings.

## Libraries & tools (recommended)
- Bitcoin: `rust-bitcoin`, `bdk` (for wallet abstractions), `rust-lightning` (for Lightning protocol)
- Monero: `monero` crate for primitives and RPC clients OR use JSON-RPC to a `monerod`/`monero-wallet-rpc`
- Node bindings: `napi-rs` or `neon` (napi-rs recommended)
- HD & Mnemonics: `bip39`, `bip32` crates (implement BIP39 with a well-reviewed crate)
- Key storage: integrate with platform KMS / secure enclave and support hardware wallets (Ledger/Trezor)

## Security notes
- Never store cleartext seeds unencrypted on disk.
- Use OS-provided secure storage for seed encryption keys.
- Consider optional passphrase (BIP39 passphrase) and multi-factor unlocking.
- All crypto operations need a formal audit before production.

## Atomic swaps
- BTC↔XMR atomic swaps are possible but complex — require HTLC-like constructs and cooperating protocols or third-party protocols. Start with a research phase and an off-chain exchange mediator if needed.
