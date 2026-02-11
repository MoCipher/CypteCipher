use napi::bindgen_prelude::*;
use napi_derive::napi;

use cryptec_core::{WalletCore, Mnemonic, BdkWallet, LightningClient, encrypt_seed_file, decrypt_seed_file, LndClient, LedgerHw};

#[napi]
fn core_fingerprint() -> String {
    let w = WalletCore::new();
    w.fingerprint()
}

#[napi]
fn core_generate_seed_hex() -> String {
    let s = WalletCore::generate_seed();
    hex::encode(s)
}

#[napi]
fn core_example_btc_privkey_hex() -> String {
    let w = WalletCore::new();
    w.example_btc_privkey_hex()
}

#[napi]
fn generate_mnemonic(strength: u32) -> String {
    // strength should be 128, 160, 192, 224, 256
    let m = Mnemonic::generate(strength as usize);
    m.phrase
}

#[napi]
fn bdk_first_receive_address(phrase: String) -> String {
    // For simplicity use Testnet; in real binding allow network selection
    let w = BdkWallet::new_from_mnemonic(&phrase, "", bitcoin::Network::Testnet).expect("create wallet");
    w.get_new_address().expect("get address")
}

#[napi]
fn bdk_sync_electrum(phrase: String, electrum_url: String) -> String {
    let w = BdkWallet::new_from_mnemonic(&phrase, "", bitcoin::Network::Testnet).expect("create wallet");
    w.sync_with_electrum(&electrum_url).expect("sync");
    "ok".to_string()
}

#[napi]
fn bdk_create_psbt(phrase: String, to_address: String, satoshis: u64) -> String {
    let w = BdkWallet::new_from_mnemonic(&phrase, "", bitcoin::Network::Testnet).expect("create wallet");
    w.create_psbt(&to_address, satoshis).expect("create psbt")
}

#[napi]
fn bdk_sign_psbt(phrase: String, psbt_b64: String) -> String {
    let w = BdkWallet::new_from_mnemonic(&phrase, "", bitcoin::Network::Testnet).expect("create wallet");
    w.sign_psbt_base64(&psbt_b64).expect("sign psbt")
}

#[napi]
fn bdk_create_persistent_wallet(phrase: String, db_path: String) -> String {
    let w = PersistentBdkWallet::new_from_mnemonic_sqlite(&phrase, "", bitcoin::Network::Testnet, &db_path).expect("create persistent");
    w.get_new_address().expect("get address")
}

#[napi]
fn bdk_persistent_sync_electrum(db_path: String, electrum_url: String) -> String {
    // open the wallet using the sqlite DB file path
    // Note: in a full implementation we'd store wallet metadata/config; here we recreate wallet from DB + descriptors
    // For demo purposes require that DB was created with same mnemonic via create_persistent_wallet
    let client = PersistentBdkWallet::new_from_mnemonic_sqlite("", "", bitcoin::Network::Testnet, &db_path);
    if client.is_err() {
        return format!("error: {}", client.err().unwrap());
    }
    let w = client.unwrap();
    w.sync_with_electrum(&electrum_url).expect("sync");
    "ok".to_string()
}

#[napi]
fn encrypt_seed(path: String, password: String) -> String {
    let seed = WalletCore::generate_seed();
    encrypt_seed_file(&seed, &password, &path).expect("encrypt");
    "ok".to_string()
}

#[napi]
fn decrypt_seed(path: String, password: String) -> String {
    let seed = decrypt_seed_file(&path, &password).expect("decrypt");
    hex::encode(seed)
}

#[napi]
fn keystore_generate_db_key(service: String, user: String) -> String {
    crate::keystore::generate_db_master_key(&service, &user).expect("generate key");
    "ok".to_string()
}

#[napi]
fn bdk_create_encrypted_persistent_wallet(phrase: String, db_path_encrypted: String, service: String, user: String) -> String {
    // Uses a temp plaintext DB which is removed after encryption
    let network = bitcoin::Network::Testnet;
    PersistentBdkWallet::create_encrypted_persistent_wallet(&phrase, "", network, &db_path_encrypted, &service, &user).expect("create encrypted wallet");
    "ok".to_string()
}

#[napi]
fn bdk_encrypt_db(plain_path: String, encrypted_path: String, service: String, user: String) -> String {
    // ensures master key exists and encrypts a plain DB file
    if let Err(_) = crate::keystore::get_db_master_key(&service, &user) {
        crate::keystore::generate_db_master_key(&service, &user).expect("generate key");
    }
    PersistentBdkWallet::encrypt_db_file(&plain_path, &encrypted_path, &service, &user).expect("encrypt db");
    "ok".to_string()
}

#[napi]
fn bdk_decrypt_db_to_temp(encrypted_path: String, service: String, user: String) -> String {
    let tmp = PersistentBdkWallet::decrypt_db_to_tempfile(&encrypted_path, &service, &user).expect("decrypt tmp");
    tmp.path().to_str().unwrap().to_string()
}

#[napi]
fn bdk_decrypted_db_close(path: String) -> String {
    // attempt to securely delete the decrypted DB file
    let _ = crate::keystore::secure_delete(&path);
    "ok".to_string()
}

#[napi]
fn bdk_open_inmemory_db(encrypted_path: String, service: String, user: String) -> String {
    let im = InMemoryDb::from_encrypted_file_in_memory(&encrypted_path, &service, &user).expect("open in-memory db");
    let id = crate::wallet_manager::register_inmemory_db(im);
    id
}

#[napi]
fn bdk_inmemory_table_list(handle_id: String) -> String {
    // convenience wrapper using the run query helper to get tables
    let q = "SELECT name FROM sqlite_master WHERE type='table'".to_string();
    crate::wallet_manager::inmemory_run_query(&handle_id, &q).unwrap_or_else(|_| "[]".to_string())
}

#[napi]
fn bdk_inmemory_run_query(handle_id: String, sql: String) -> String {
    crate::wallet_manager::inmemory_run_query(&handle_id, &sql).unwrap_or_else(|_| "[]".to_string())
}

#[napi]
fn bdk_inmemory_export_snapshot(handle_id: String) -> String {
    crate::wallet_manager::inmemory_export_snapshot_base64(&handle_id).unwrap_or_else(|_| "".to_string())
}

#[napi]
fn bdk_close_inmemory_handle(handle_id: String) -> String {
    let _ = crate::wallet_manager::close_inmemory_db(&handle_id);
    "ok".to_string()
}

#[napi]
fn bdk_list_handles() -> String {
    let list = crate::wallet_manager::list_handles();
    serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_string())
}

#[napi]
fn bdk_close_all_handles() -> String {
    let _ = crate::wallet_manager::close_all();
    "ok".to_string()
}

#[napi]
fn monero_get_balance(rpc_url: String, user: Option<String>, pass: Option<String>) -> String {
    let client = MoneroClient::new(&rpc_url, user.as_deref(), pass.as_deref());
    match client.get_balance() {
        Ok(val) => serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string()),
        Err(e) => format!("error: {}", e)
    }
}

#[napi]
fn monero_get_address(rpc_url: String, user: Option<String>, pass: Option<String>) -> String {
    let client = MoneroClient::new(&rpc_url, user.as_deref(), pass.as_deref());
    match client.get_address() {
        Ok(val) => serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string()),
        Err(e) => format!("error: {}", e)
    }
}

#[napi]
fn monero_get_tx_proof(rpc_url: String, user: Option<String>, pass: Option<String>, txid: String, address: Option<String>) -> String {
    let client = MoneroClient::new(&rpc_url, user.as_deref(), pass.as_deref());
    match client.get_tx_proof(&txid, address.as_deref()) {
        Ok(val) => serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string()),
        Err(e) => format!("error: {}", e)
    }
}

#[napi]
fn monero_check_tx_proof(rpc_url: String, user: Option<String>, pass: Option<String>, txid: String, address: String, signature: String) -> String {
    let client = MoneroClient::new(&rpc_url, user.as_deref(), pass.as_deref());
    match client.check_tx_proof(&txid, &address, &signature) {
        Ok(val) => serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string()),
        Err(e) => format!("error: {}", e)
    }
}

#[napi]
fn monero_transfer(rpc_url: String, user: Option<String>, pass: Option<String>, amount: u64, address: String) -> String {
    let client = MoneroClient::new(&rpc_url, user.as_deref(), pass.as_deref());
    match client.transfer(amount, &address) {
        Ok(val) => serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string()),
        Err(e) => format!("error: {}", e)
    }
}

#[napi]
fn monero_create_swap(btc_sats: u64, xmr_piconero: u64, role: String) -> String {
    let r = if role == "maker" { SwapRole::Maker } else { SwapRole::Taker };
    let s = AtomicSwap::new(r, btc_sats, xmr_piconero);
    let js = s.create_swap_contract();
    match js {
        Ok(val) => serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string()),
        Err(e) => format!("error: {}", e)
    }
}

#[napi]
fn monero_make_integrated_address(rpc_url: String, user: Option<String>, pass: Option<String>, payment_id: Option<String>) -> String {
    let client = MoneroClient::new(&rpc_url, user.as_deref(), pass.as_deref());
    match client.make_integrated_address(payment_id.as_deref()) {
        Ok(val) => serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string()),
        Err(e) => format!("error: {}", e)
    }
}

#[napi]
fn monero_simulate_swap(btc_sats: u64, xmr_piconero: u64) -> String {
    let s = SwapSimulation::new(btc_sats, xmr_piconero);
    let offer = s.maker_create_offer();
    let proof = s.taker_provide_proof();
    let reveal = s.maker_validate_and_reveal(proof.clone());
    let prehex = reveal.get("preimage").unwrap().as_str().unwrap().to_string();
    let redeem = s.taker_redeem_with_preimage(&prehex);
    let out = serde_json::json!({"offer": offer, "proof": proof, "reveal": reveal, "redeem": redeem});
    serde_json::to_string(&out).unwrap()
}

#[napi]
fn monero_swap_step(proof: String) -> String {
    let v: serde_json::Value = serde_json::from_str(&proof).unwrap_or_else(|_| serde_json::json!(null));
    let s = AtomicSwap::new(SwapRole::Taker, 0, 0);
    let res = s.validate_and_step(v);
    match res {
        Ok(val) => serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string()),
        Err(e) => format!("error: {}", e)
    }
}

#[napi]
fn lnd_getinfo(host: String, macaroon: Option<String>) -> String {
    let client = LndClient::new(&host, macaroon.as_deref());
    let v = client.get_info();
    match v {
        Ok(val) => serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string()),
        Err(e) => format!("error: {}", e)
    }
}

#[napi]
fn hardware_ledger_status() -> String {
    let l = LedgerHw::new();
    if l.connected { "connected".to_string() } else { "disconnected".to_string() }
}

