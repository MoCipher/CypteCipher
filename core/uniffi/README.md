UniFFI scaffold for CrypteCipher core

This folder contains a UDL interface describing the minimal set of APIs the mobile app will consume on-device.

How to generate bindings (developer machine):

1. Install `uniffi-bindgen` (Rust/Cargo or prebuilt binary).
2. From `core/` run:
   ```bash
   uniffi-bindgen generate uniffi/cryptec.udl -l objc -o bindings/ios
   uniffi-bindgen generate uniffi/cryptec.udl -l java -o bindings/android
   ```
3. Implement platform-specific glue in the generated wrappers and add React Native native modules that call them.

Note: CI currently ships a JS fallback for mobile; UniFFI integration will be enabled in CI once native toolchains are added.
