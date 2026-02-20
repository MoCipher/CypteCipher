use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `AesGcm`
use aes_gcm::aead::Aead;
use argon2::{Argon2, password_hash::{SaltString, PasswordHasher, PasswordVerifier}, PasswordHash, PasswordHasher as _};
use rand::rngs::OsRng;
use rand::RngCore;
use base64::{encode as b64encode, decode as b64decode};
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use anyhow::Result;

use keyring::Keyring;

#[derive(Serialize, Deserialize)]
struct EncryptedSeedFile {
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// Derive 32-byte key using Argon2 from password + salt
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    // Use password-hash crate to produce a derived key via Argon2: we will directly hash and then extract bytes
    // Simpler: use Argon2::hash_password_simple to produce a string and then hash it again - but here create PHC and use raw hashing
    use argon2::password_hash::Salt;
    let salt = Salt::new(b64encode(salt).as_str()).expect("salt create");
    let mut out = [0u8; 32];
    // Use Argon2's hash_password_into
    argon2.hash_password_into(password.as_bytes(), salt.as_ref().as_bytes(), &mut out).expect("argon2 derive");
    out
}

/// Encrypt and write seed to file (JSON containing salt, nonce, ciphertext)
pub fn encrypt_seed_file(seed: &[u8; 32], password: &str, path: &str) -> Result<()> {
    // generate salt + nonce
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let keybytes = derive_key(password, &salt);
    let key = Key::from_slice(&keybytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher.encrypt(nonce, seed.as_ref()).expect("encryption");

    let file = EncryptedSeedFile {
        salt: b64encode(&salt),
        nonce: b64encode(&nonce_bytes),
        ciphertext: b64encode(&ct),
    };

    let s = serde_json::to_string_pretty(&file)?;
    fs::write(path, s)?;
    Ok(())
}

/// Decrypt a seed file given a password
pub fn decrypt_seed_file(path: &str, password: &str) -> Result<[u8; 32]> {
    let content = fs::read_to_string(path)?;
    let file: EncryptedSeedFile = serde_json::from_str(&content)?;
    let salt = b64decode(&file.salt)?;
    let nonce_bytes = b64decode(&file.nonce)?;
    let ct = b64decode(&file.ciphertext)?;

    let keybytes = derive_key(password, &salt);
    let key = Key::from_slice(&keybytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let pt = cipher.decrypt(nonce, ct.as_ref())?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&pt[..32]);
    Ok(out)
}

/// Store a password in the OS keyring (optional convenience)
pub fn store_password_in_keyring(service: &str, user: &str, password: &str) -> Result<()> {
    let kr = Keyring::new(service, user);
    kr.set_password(password)?;
    Ok(())
}

/// Retrieve a password from the OS keyring
pub fn retrieve_password_from_keyring(service: &str, user: &str) -> Result<String> {
    let kr = Keyring::new(service, user);
    let pwd = kr.get_password()?;
    Ok(pwd)
}

/// Generate and store a random 32-byte master key in the OS keyring for DB encryption
pub fn generate_db_master_key(service: &str, user: &str) -> Result<()> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let s = b64encode(&key);
    store_password_in_keyring(service, user, &s)?;
    Ok(())
}

/// Retrieve the 32-byte master key from the OS keyring
pub fn get_db_master_key(service: &str, user: &str) -> Result<[u8; 32]> {
    let s = retrieve_password_from_keyring(service, user)?;
    let bytes = b64decode(&s)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[0..32]);
    Ok(out)
}

/// Encrypt an arbitrary file using the master key stored in the OS keyring
pub fn encrypt_file_with_master_key(in_path: &str, out_path: &str, service: &str, user: &str) -> Result<()> {
    let keybytes = get_db_master_key(service, user)?;
    let key = Key::from_slice(&keybytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let data = fs::read(in_path)?;
    let ct = cipher.encrypt(nonce, data.as_ref())?;

    let file = EncryptedSeedFile {
        salt: "".to_string(),
        nonce: b64encode(&nonce_bytes),
        ciphertext: b64encode(&ct),
    };
    let s = serde_json::to_string_pretty(&file)?;
    fs::write(out_path, s)?;
    Ok(())
}

/// Decrypt an arbitrary file previously encrypted with `encrypt_file_with_master_key`
pub fn decrypt_file_with_master_key(in_path: &str, out_path: &str, service: &str, user: &str) -> Result<()> {
    let content = fs::read_to_string(in_path)?;
    let file: EncryptedSeedFile = serde_json::from_str(&content)?;
    let nonce_bytes = b64decode(&file.nonce)?;
    let ct = b64decode(&file.ciphertext)?;

    let keybytes = get_db_master_key(service, user)?;
    let key = Key::from_slice(&keybytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let pt = cipher.decrypt(nonce, ct.as_ref())?;

    // write with restricted permissions
    fs::write(out_path, &pt)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(out_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Decrypt an encrypted file and return the plaintext bytes in memory (avoid writing to disk)
pub fn decrypt_file_to_memory(in_path: &str, service: &str, user: &str) -> Result<Vec<u8>> {
    let content = fs::read_to_string(in_path)?;
    let file: EncryptedSeedFile = serde_json::from_str(&content)?;
    let nonce_bytes = b64decode(&file.nonce)?;
    let ct = b64decode(&file.ciphertext)?;

    let keybytes = get_db_master_key(service, user)?;
    let key = Key::from_slice(&keybytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let pt = cipher.decrypt(nonce, ct.as_ref())?;
    Ok(pt)
}
/// Overwrite the file content with zeros and then remove the file. Best-effort secure delete.
pub fn secure_delete(path: &str) -> Result<()> {
    if !Path::new(path).exists() {
        return Ok(());
    }

    // Platform specific helpers
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        // Prefer `srm -s` (secure rm) if available
        if Command::new("srm").arg("-s").arg(path).status().map(|s| s.success()).unwrap_or(false) {
            return Ok(());
        }
        // Fallback to `shred -u` if available
        if Command::new("shred").arg("-u").arg(path).status().map(|s| s.success()).unwrap_or(false) {
            return Ok(());
        }
        // Fallback to `rm -P` which attempts to overwrite
        if Command::new("rm").arg("-P").arg(path).status().map(|s| s.success()).unwrap_or(false) {
            return Ok(());
        }
        // else fall through to generic overwrite
    }

    #[cfg(target_os = "windows")]
    {
        // Use Windows API `ReplaceFile` as a best-effort removal after overwrite
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;
        use winapi::um::winbase::FILE_FLAG_WRITE_THROUGH;
        use winapi::um::winbase::ReplaceFileW;
        use std::os::windows::prelude::OsStrExt;

        let metadata = fs::metadata(path)?;
        let len = metadata.len();
        let mut f = OpenOptions::new().write(true).custom_flags(FILE_FLAG_WRITE_THROUGH).open(path)?;
        // overwrite multiple patterns (zeros, 0xFF, random)
        let mut remaining = len;
        let mut zeros = vec![0u8; 4096];
        let mut ff = vec![0xFFu8; 4096];
        while remaining > 0 {
            let write_len = std::cmp::min(remaining, zeros.len() as u64) as usize;
            f.write_all(&zeros[0..write_len])?;
            f.flush()?;
            f.write_all(&ff[0..write_len])?;
            f.flush()?;
            let mut rnd = vec![0u8; write_len];
            OsRng.fill_bytes(&mut rnd);
            f.write_all(&rnd)?;
            f.flush()?;
            remaining -= write_len as u64;
        }
        f.sync_all()?;
        drop(f);

        // Attempt to replace the file with an empty temporary file
        let tmp = tempfile::NamedTempFile::new()?;
        let tmp_wstr: Vec<u16> = tmp.path().as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let path_wstr: Vec<u16> = std::path::Path::new(path).as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        unsafe {
            let r = ReplaceFileW(path_wstr.as_ptr(), tmp_wstr.as_ptr(), std::ptr::null(), 0, std::ptr::null_mut(), std::ptr::null_mut());
            if r == 0 {
                // fallback to delete
                let _ = fs::remove_file(path);
            } else {
                let _ = fs::remove_file(tmp.path());
            }
        }
        return Ok(());
    }

    // Generic Unix-like overwrite (including Linux)
    {
        let metadata = fs::metadata(path)?;
        let len = metadata.len();
        let mut f = fs::OpenOptions::new().write(true).open(path)?;
        // overwrite with zeros
        let zeros = vec![0u8; 4096];
        let mut remaining = len;
        while remaining > 0 {
            let write_len = std::cmp::min(remaining, zeros.len() as u64) as usize;
            f.write_all(&zeros[0..write_len])?;
            remaining -= write_len as u64;
        }
        f.sync_all()?;
        drop(f);
        fs::remove_file(path)?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap();
        encrypt_seed_file(&seed, "password123", path).expect("encrypt");
        let out = decrypt_seed_file(path, "password123").expect("decrypt");
        assert_eq!(seed, out);
    }

    #[test]
    fn db_master_key_encrypt_decrypt_file() {
        // prepare sample file
        let tmp_in = NamedTempFile::new().unwrap();
        let in_path = tmp_in.path().to_str().unwrap();
        fs::write(in_path, b"hello-db") .unwrap();

        // generate master key
        let _ = generate_db_master_key("cryptec-db", "test-user");
        let tmp_out = NamedTempFile::new().unwrap();
        let out_path = tmp_out.path().to_str().unwrap();

        encrypt_file_with_master_key(in_path, out_path, "cryptec-db", "test-user").expect("encrypt file");

        // decrypt to another temp path
        let tmp_dec = NamedTempFile::new().unwrap();
        let dec_path = tmp_dec.path().to_str().unwrap();
        decrypt_file_with_master_key(out_path, dec_path, "cryptec-db", "test-user").expect("decrypt file");

        let content = fs::read(dec_path).expect("read");
        assert_eq!(content, b"hello-db");
    }

    #[test]
    fn secure_delete_removes_file() {
        let tmp = NamedTempFile::new().unwrap();
        let p = tmp.path().to_str().unwrap().to_string();
        // write some data
        fs::write(&p, b"sensitive").unwrap();
        assert!(Path::new(&p).exists());
        secure_delete(&p).expect("secure delete");
        assert!(!Path::new(&p).exists());
    }

    // Windows-specific secure delete test will only run on Windows
    #[cfg(target_os = "windows")]
    #[test]
    fn secure_delete_windows_api() {
        let tmp = NamedTempFile::new().unwrap();
        let p = tmp.path().to_str().unwrap().to_string();
        fs::write(&p, b"sensitive").unwrap();
        secure_delete(&p).expect("secure delete windows");
        assert!(!Path::new(&p).exists());
    }

    // macOS-specific test
    #[cfg(target_os = "macos")]
    #[test]
    fn secure_delete_macos_cmd() {
        let tmp = NamedTempFile::new().unwrap();
        let p = tmp.path().to_str().unwrap().to_string();
        fs::write(&p, b"sensitive").unwrap();
        secure_delete(&p).expect("secure delete macos");
        assert!(!Path::new(&p).exists());
    }
}
