# Mobile (React Native) - CrypteCipher

This folder will contain the React Native app.

Recommendations:
- Use React Native + TypeScript (or Expo for rapid prototyping).
- For secure key operations on device, implement a native module that calls the Rust core via platform-native linking (Android: JNI/NDK; iOS: static/dynamic lib + Objective-C/Swift wrapper).
- Use platform secure storage (iOS Keychain / Android Keystore) for encrypted seed storage.
- For Monero, prefer using a remote `monerod`/`monero-wallet-rpc` for mobile to save resources, or use a light-weight daemon if available.
