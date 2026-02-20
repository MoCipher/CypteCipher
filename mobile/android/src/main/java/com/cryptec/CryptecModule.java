package com.cryptec;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;

public class CryptecModule extends ReactContextBaseJavaModule {
    public CryptecModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "Cryptec";
    }

    @ReactMethod
    public void generate_mnemonic(int strength, Promise p) {
        // Native implementation should call into UniFFI-generated JNI bridge.
        // Fallback: return an error so JS fallback can be used in dev/CI.
        p.resolve("");
    }

    @ReactMethod
    public void first_receive_address(String mnemonic, Promise p) {
        p.resolve("");
    }

    @ReactMethod
    public void create_psbt(String mnemonic, String to, double sats, Promise p) {
        p.resolve("");
    }

    @ReactMethod
    public void sign_psbt(String mnemonic, String psbt_b64, Promise p) {
        p.resolve("");
    }
}
