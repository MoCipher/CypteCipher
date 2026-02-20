#!/usr/bin/env bash
set -euo pipefail

UDL=core/uniffi/cryptec.udl
OUT_ANDROID=core/uniffi/bindings/android
OUT_IOS=core/uniffi/bindings/ios

echo "[uniffi-codegen] UDL: $UDL"

if command -v uniffi-bindgen >/dev/null 2>&1; then
  echo "[uniffi-codegen] running uniffi-bindgen (java, objc)"
  uniffi-bindgen generate "$UDL" -l java -o "$OUT_ANDROID"
  uniffi-bindgen generate "$UDL" -l objc -o "$OUT_IOS"
  echo "[uniffi-codegen] generated bindings in $OUT_ANDROID and $OUT_IOS"
else
  echo "[uniffi-codegen] uniffi-bindgen not found; skipping codegen (placeholders must exist)"
fi
