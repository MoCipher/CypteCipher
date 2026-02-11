# CrypteCipher

**PR:** Initial scaffold and features added for review.

Secure privacy-first multi-currency wallet (scaffold)

Overview
- Core: Rust library implementing key management, Bitcoin (on-chain + Lightning), Monero (RPC integration), and atomic-swap scaffolding.
- Bindings: Node/N-API bindings to use core from Electron/Node.js.
- Mobile: React Native app (TypeScript) that will use platform-native bindings to call the Rust core.
- Electron: Desktop app skeleton that uses N-API bindings.

Security notes
- Core crypto and key management is implemented in Rust for memory safety.
- Do not ship private keys to servers — default is non-custodial.
- All cryptographic code must be audited before production.

Next steps
1. Review ARCHITECTURE.md in `/docs`.
2. Wire up real libraries and node/native module integration.
3. Add automated tests and security audit.
