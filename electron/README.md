# Electron (Desktop) - CrypteCipher

This folder will contain the Electron-based desktop app.

Notes:
- Use the `cryptec_bindings` Node addon (N-API) to call into the Rust core for cryptographic operations.
- For Bitcoin Lightning, you can either embed a rust-lightning node or connect to an external Lightning node (e.g., `lnd`/`c-lightning`).
- For Monero, consider running a full node or allowing users to configure a remote RPC node.
