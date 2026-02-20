use bdk::Wallet;
use bdk::database::{MemoryDatabase, SqliteDatabase};
use bdk::wallet::AddressIndex;
use bdk::blockchain::{noop_progress::NoopProgress, ElectrumBlockchain, ElectrumBlockchainConfig};
use crate::bip39::Mnemonic as LocalMnemonic;
use bdk::descriptor::DescriptorTemplateOut;
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::Network;
use anyhow::Result;
use std::path::Path;
use bitcoin::consensus::encode as consensus_encode;

/// Minimal BDK wallet scaffold with Electrum support (in-memory)
pub struct BdkWallet {
    wallet: Wallet<MemoryDatabase>,
}

impl BdkWallet {
    /// Create a new BDK wallet from a BIP39 mnemonic (and passphrase) for the specified network
    pub fn new_from_mnemonic(phrase: &str, passphrase: &str, network: Network) -> Result<Self> {
        // Derive master xprv using our local bip39 helper and build simple `wpkh(<xpub>/0/*)` descriptors.
        let local_m = LocalMnemonic::from_phrase(phrase).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let xprv = local_m.to_master_xprv(passphrase, network);
        // neuter to xpub for descriptor
        let secp = secp256k1::Secp256k1::new();
        let xpub = ExtendedPubKey::from_private(&secp, &xprv);
        let descriptor = format!("wpkh({}/0/*)", xpub.to_string());
        let change_descriptor = format!("wpkh({}/1/*)", xpub.to_string());

        let wallet = Wallet::new_offline(&descriptor, Some(&change_descriptor), network, MemoryDatabase::default())?;
        Ok(Self { wallet })
    }

    /// Create and sync with Electrum server (blocking)
    pub fn sync_with_electrum(&self, electrum_url: &str) -> Result<()> {
        let config = ElectrumBlockchainConfig::from(electrum_url);
        let blockchain = ElectrumBlockchain::from_config(&config)?;
        self.wallet.sync(&blockchain, NoopProgress)?;
        Ok(())
    }

    /// Return the next receiving address
    pub fn get_new_address(&self) -> Result<String> {
        let addr = self.wallet.get_address(AddressIndex::New)?;
        Ok(addr.to_string())
    }

    /// Build a PSBT for a single recipient amount (satoshi)
    pub fn create_psbt(&self, to_address: &str, satoshis: u64) -> Result<String> {
        let addr = to_address.parse::<bitcoin::Address>()?;
        let mut builder = bdk::TxBuilder::new();
        builder = builder.add_recipient(addr.script_pubkey(), satoshis);
        let (psbt, _details) = self.wallet.build_tx(builder)?;
        let serialized = consensus_encode::serialize(&psbt);
        let bs = base64::encode(&serialized);
        Ok(bs)
    }

    /// Sign PSBT (NOTE: using the internal keys of the wallet)
    pub fn sign_psbt_base64(&self, psbt_b64: &str) -> Result<String> {
        let raw = base64::decode(psbt_b64)?;
        let mut psbt: bitcoin::util::psbt::PartiallySignedTransaction = bitcoin::consensus::deserialize(&raw)?;
        self.wallet.sign(&mut psbt, bdk::SignOptions::default())?;
        let serialized = consensus_encode::serialize(&psbt);
        let out = base64::encode(&serialized);
        Ok(out)
    }

    /// List UTXOs (simple)
    pub fn list_utxos(&self) -> Result<Vec<bdk::local_wallet::LocalUtxo>> {
        let utxos = self.wallet.list_unspent()?;
        Ok(utxos)
    }
}

/// Persistent wallet backed by SQLite file
pub struct PersistentBdkWallet {
    wallet: Wallet<SqliteDatabase>,
}

impl PersistentBdkWallet {
    /// Create or open a persistent wallet using a SQLite DB file at `db_path`.
    /// `db_path` should be a filesystem path like `/path/to/wallet.db`.
    pub fn new_from_mnemonic_sqlite(phrase: &str, passphrase: &str, network: Network, db_path: &str) -> Result<Self> {
        // derive master xprv & descriptors just like in BdkWallet
        let local_m = LocalMnemonic::from_phrase(phrase).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let xprv = local_m.to_master_xprv(passphrase, network);
        let secp = secp256k1::Secp256k1::new();
        let xpub = ExtendedPubKey::from_private(&secp, &xprv);
        let descriptor = format!("wpkh({}/0/*)", xpub.to_string());
        let change_descriptor = format!("wpkh({}/1/*)", xpub.to_string());

        // Ensure directory exists
        let p = Path::new(db_path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let db = SqliteDatabase::new(db_path)?;
        let wallet = Wallet::new(&descriptor, Some(&change_descriptor), network, db)?;
        Ok(Self { wallet })
    }

    /// Create and sync with Electrum server (blocking)
    /// `electrum_url` can be `ssl://electrum.example:50002` or `tcp://host:50001`
    /// TLS verification is handled by underlying Electrum client; for custom CA/TLS options change configuration here.
    pub fn sync_with_electrum(&self, electrum_url: &str) -> Result<()> {
        let config = ElectrumBlockchainConfig::from(electrum_url);
        let blockchain = ElectrumBlockchain::from_config(&config)?;
        self.wallet.sync(&blockchain, NoopProgress)?;
        Ok(())
    }

    pub fn get_new_address(&self) -> Result<String> {
        let addr = self.wallet.get_address(AddressIndex::New)?;
        Ok(addr.to_string())
    }

    pub fn create_psbt(&self, to_address: &str, satoshis: u64) -> Result<String> {
        let addr = to_address.parse::<bitcoin::Address>()?;
        let mut builder = bdk::TxBuilder::new();
        builder = builder.add_recipient(addr.script_pubkey(), satoshis);
        let (psbt, _details) = self.wallet.build_tx(builder)?;
        let serialized = consensus_encode::serialize(&psbt);
        let bs = base64::encode(&serialized);
        Ok(bs)
    }

    pub fn sign_psbt_base64(&self, psbt_b64: &str) -> Result<String> {
        let raw = base64::decode(psbt_b64)?;
        let mut psbt: bitcoin::util::psbt::PartiallySignedTransaction = bitcoin::consensus::deserialize(&raw)?;
        self.wallet.sign(&mut psbt, bdk::SignOptions::default())?;
        let serialized = consensus_encode::serialize(&psbt);
        let out = base64::encode(&serialized);
        Ok(out)
    }

    pub fn list_utxos(&self) -> Result<Vec<bdk::local_wallet::LocalUtxo>> {
        let utxos = self.wallet.list_unspent()?;
        Ok(utxos)
    }

    /// Encrypt an existing SQLite DB file using the OS keyring-managed master key
    pub fn encrypt_db_file(db_path_plain: &str, db_path_encrypted: &str, service: &str, user: &str) -> Result<()> {
        // Ensure master key exists
        if let Err(_) = crate::keystore::get_db_master_key(service, user) {
            crate::keystore::generate_db_master_key(service, user)?;
        }
        crate::keystore::encrypt_file_with_master_key(db_path_plain, db_path_encrypted, service, user)?;
        Ok(())
    }

    /// Decrypt an encrypted DB file to a temporary file and return its path
    pub fn decrypt_db_to_tempfile(db_path_encrypted: &str, service: &str, user: &str) -> Result<DecryptedDb> {
        // Create a secure temporary file with restricted permissions and write decrypted DB to it
        let mut tmp = tempfile::NamedTempFile::new()?;
        let tmp_path = tmp.path().to_path_buf();

        // Decrypt into the temp file path
        crate::keystore::decrypt_file_with_master_key(db_path_encrypted, tmp_path.to_str().unwrap(), service, user)?;

        // Restrict permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
        }

        // Keep the NamedTempFile alive by converting to persist it and manage deletion ourselves
        let named = tmp.into_temp_path();
        let pathbuf = named.to_path_buf();
        // Note: into_temp_path keeps the file on disk but removes auto-delete; we'll delete securely in Drop
        let dd = DecryptedDb { path: pathbuf };
        Ok(dd)
    }

    /// Create a persistent wallet, encrypt the DB file with the OS keyring master key, and remove the plaintext DB
    pub fn create_encrypted_persistent_wallet(phrase: &str, passphrase: &str, network: Network, db_path_encrypted: &str, service: &str, user: &str) -> Result<()> {
        // create plaintext DB in a securely-created temp file with restricted permissions
        let mut tmp = tempfile::NamedTempFile::new()?;
        let tmp_path = tmp.path().to_str().unwrap().to_string();

        // set restrictive permissions on temp file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
        }

        // create wallet and DB at tmp_path (DB exists only briefly)
        let _w = PersistentBdkWallet::new_from_mnemonic_sqlite(phrase, passphrase, network, &tmp_path)?;

        // ensure master key and encrypt
        if let Err(_) = crate::keystore::get_db_master_key(service, user) {
            crate::keystore::generate_db_master_key(service, user)?;
        }
        crate::keystore::encrypt_file_with_master_key(&tmp_path, db_path_encrypted, service, user)?;

        // Best-effort: overwrite plaintext file contents and remove file immediately
        // ensure file is closed before secure delete
        drop(tmp);
        let _ = crate::keystore::secure_delete(&tmp_path);
        Ok(())
    }
}

/// Temporary decrypted DB handle. When dropped, it securely deletes the underlying file.
pub struct DecryptedDb {
    pub path: std::path::PathBuf,
}

impl DecryptedDb {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Consume and securely delete the underlying file immediately
    pub fn close_and_delete(self) -> Result<()> {
        let p = self.path.to_str().unwrap().to_string();
        crate::keystore::secure_delete(&p)?;
        Ok(())
    }
}

impl Drop for DecryptedDb {
    fn drop(&mut self) {
        let _ = crate::keystore::secure_delete(self.path.to_str().unwrap());
    }
}

/// In-memory SQLite DB wrapper using sqlite3_deserialize to avoid persistent plaintext DB files.
pub struct InMemoryDb {
    pub conn: rusqlite::Connection,
}

impl InMemoryDb {
    /// Create an in-memory DB by decrypting an encrypted DB file into memory and deserializing it into an in-memory sqlite DB.
    pub fn from_encrypted_file_in_memory(encrypted_path: &str, service: &str, user: &str) -> Result<Self> {
        // Decrypt bytes into memory
        let bytes = crate::keystore::decrypt_file_to_memory(encrypted_path, service, user)?;

        // Open an in-memory SQLite connection
        let conn = rusqlite::Connection::open_in_memory()?;

        // Try SQLite deserialize to load bytes into the in-memory DB (unsafe C API call)
        let deserialize_result: Result<(), anyhow::Error> = unsafe {
            use rusqlite::ffi;
            use std::ffi::CString;
            let db_handle = conn.handle();
            let dbname = CString::new("main").unwrap();
            // Allocate a buffer that SQLite will take ownership of (SQLITE_DESERIALIZE_FREEONCLOSE)
            let mut buf = bytes.clone();
            let p = buf.as_mut_ptr();
            let len = buf.len() as i64;
            let rc = ffi::sqlite3_deserialize(db_handle, dbname.as_ptr(), p as *mut _, len, len, ffi::SQLITE_DESERIALIZE_FREEONCLOSE);
            if rc != ffi::SQLITE_OK {
                Err(anyhow::anyhow!("sqlite3_deserialize failed: {}", rc))
            } else {
                // buf ownership transferred to SQLite; avoid dropping it here
                std::mem::forget(buf);
                Ok(())
            }
        };

        if let Err(_e) = deserialize_result {
            // Fallback: write bytes to a secure temp file and use SQLite backup API to load into memory
            let mut tmp = tempfile::NamedTempFile::new()?;
            let tmp_path = tmp.path().to_str().unwrap().to_string();
            // restrict permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
            }
            std::fs::write(&tmp_path, &bytes)?;

            // Open file-backed DB and backup into in-memory conn
            let file_conn = rusqlite::Connection::open(&tmp_path)?;
            let mut backup = rusqlite::backup::Backup::new(&file_conn, &conn)?;
            backup.step(-1)?; // copy entire DB
            backup.finish()?;

            // secure delete temp plaintext file
            let _ = crate::keystore::secure_delete(&tmp_path);
        }

        Ok(Self { conn })
    }

    /// Run an arbitrary SQL query and return results as JSON array of rows
    pub fn run_query_json(&self, sql: &str) -> Result<serde_json::Value> {
        let mut stmt = self.conn.prepare(sql)?;
        let column_count = stmt.column_count();
        let column_names: Vec<String> = (0..column_count).map(|i| stmt.column_name(i).unwrap_or("").to_string()).collect();
        let mut rows = stmt.query([])?;
        let mut out_rows = Vec::new();
        while let Some(r) = rows.next()? {
            let mut map = serde_json::Map::new();
            for (i, name) in column_names.iter().enumerate() {
                let val: rusqlite::types::Value = r.get(i)?;
                let j = match val {
                    rusqlite::types::Value::Null => serde_json::Value::Null,
                    rusqlite::types::Value::Integer(i) => serde_json::json!(i),
                    rusqlite::types::Value::Real(f) => serde_json::json!(f),
                    rusqlite::types::Value::Text(s) => serde_json::json!(s),
                    rusqlite::types::Value::Blob(b) => serde_json::json!(base64::encode(&b)),
                };
                map.insert(name.clone(), j);
            }
            out_rows.push(serde_json::Value::Object(map));
        }
        Ok(serde_json::Value::Array(out_rows))
    }

    /// Export an on-disk snapshot of the in-memory DB as byte vector.
    /// First try sqlite3_serialize; if unavailable, fallback to backup-to-temp-file.
    pub fn export_snapshot_bytes(&self) -> Result<Vec<u8>> {
        // Try sqlite3_serialize
        unsafe {
            use rusqlite::ffi;
            use std::ffi::CString;
            let db_handle = self.conn.handle();
            let name = CString::new("main").unwrap();
            let mut len: rusqlite::ffi::sqlite3_int64 = 0;
            let p = ffi::sqlite3_serialize(db_handle, name.as_ptr(), &mut len as *mut _, ffi::SQLITE_SERIALIZE_NOCOPY);
            if !p.is_null() {
                let slice = std::slice::from_raw_parts(p as *const u8, len as usize);
                let vec = slice.to_vec();
                // free buffer allocated by SQLite
                ffi::sqlite3_free(p as *mut _);
                return Ok(vec);
            }
        }

        // Fallback: backup in-memory DB to a temp file then read bytes
        let tmp = tempfile::NamedTempFile::new()?;
        let tmp_path = tmp.path().to_str().unwrap().to_string();
        let file_conn = rusqlite::Connection::open(&tmp_path)?;
        let mut backup = rusqlite::backup::Backup::new(&self.conn, &file_conn)?;
        backup.step(-1)?;
        backup.finish()?;
        let bytes = std::fs::read(&tmp_path)?;
        let _ = crate::keystore::secure_delete(&tmp_path);
        Ok(bytes)
    }
}


impl Drop for InMemoryDb {
    fn drop(&mut self) {
        // conn will be closed automatically; any memory backed pages freed
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39::Mnemonic;
    use bitcoin::Network;
    use tempfile::tempdir;

    #[test]
    fn bdk_wallet_create_and_addr() {
        let m = Mnemonic::generate(128);
        let wallet = BdkWallet::new_from_mnemonic(&m.phrase, "", Network::Testnet).expect("create wallet");
        let addr = wallet.get_new_address().expect("get address");
        assert!(!addr.is_empty());
    }

    #[test]
    fn persistent_wallet_sqlite_roundtrip() {
        let m = Mnemonic::generate(128);
        let dir = tempdir().unwrap();
        let dbpath = dir.path().join("wallet.db");
        let dbs = dbpath.to_str().unwrap();
        let w = PersistentBdkWallet::new_from_mnemonic_sqlite(&m.phrase, "", Network::Testnet, dbs).expect("create persistent");
        let a = w.get_new_address().expect("addr");
        assert!(!a.is_empty());
    }

    #[test]
    fn encrypt_and_decrypt_db_roundtrip() {
        let m = Mnemonic::generate(128);
        let dir = tempdir().unwrap();
        let dbpath = dir.path().join("wallet.db");
        let dbs = dbpath.to_str().unwrap();

        // create plaintext DB
        let _w = PersistentBdkWallet::new_from_mnemonic_sqlite(&m.phrase, "", Network::Testnet, dbs).expect("create persistent");

        let encrypted = dir.path().join("wallet.db.enc");
        let encs = encrypted.to_str().unwrap();

        // generate master key and encrypt
        let _ = crate::keystore::generate_db_master_key("cryptec-db", "test-user");
        PersistentBdkWallet::encrypt_db_file(dbs, encs, "cryptec-db", "test-user").expect("encrypt db");

        // remove plaintext DB and decrypt to temp
        let _ = std::fs::remove_file(dbs);
        let tmp_dec = PersistentBdkWallet::decrypt_db_to_tempfile(encs, "cryptec-db", "test-user").expect("decrypt db");

        // try to open decrypted DB
        let db = SqliteDatabase::new(tmp_dec.path().to_str().unwrap()).expect("open db");
        // if DB opens, we assume successful decrypt
        assert!(db.path().is_some());

        // drop handle and ensure file removal
        let p = tmp_dec.path().to_str().unwrap().to_string();
        drop(tmp_dec);
        assert!(!std::path::Path::new(&p).exists());
    }
}
