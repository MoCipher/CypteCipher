use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use anyhow::Result;

use crate::wallet_bdk::{DecryptedDb, InMemoryDb};

/// Global wallet manager to track decrypted DB handles (temp files) and in-memory DBs.
/// Keys are UUID strings returned to consumers and used to close/inspect handles.

lazy_static::lazy_static! {
    static ref DECRYPTED_DB_HANDLES: Mutex<HashMap<String, Arc<DecryptedDb>>> = Mutex::new(HashMap::new());
    static ref INMEMORY_DB_HANDLES: Mutex<HashMap<String, Arc<InMemoryDb>>> = Mutex::new(HashMap::new());
}

/// Create and register a DecryptedDb and return its handle id
pub fn register_decrypted_db(dd: DecryptedDb) -> String {
    let id = Uuid::new_v4().to_string();
    DECRYPTED_DB_HANDLES.lock().unwrap().insert(id.clone(), Arc::new(dd));
    id
}

/// Close and remove a decrypted db handle by id
pub fn close_decrypted_db(id: &str) -> Result<()> {
    if let Some(dd) = DECRYPTED_DB_HANDLES.lock().unwrap().remove(id) {
        dd.close_and_delete()?;
    }
    Ok(())
}

/// Create and register an InMemoryDb and return its handle id
pub fn register_inmemory_db(im: InMemoryDb) -> String {
    let id = Uuid::new_v4().to_string();
    INMEMORY_DB_HANDLES.lock().unwrap().insert(id.clone(), Arc::new(im));
    id
}

/// Run a SQL query on an in-memory DB handle and return JSON string
pub fn inmemory_run_query(handle_id: &str, sql: &str) -> Result<String> {
    let map = INMEMORY_DB_HANDLES.lock().unwrap();
    if let Some(im) = map.get(handle_id) {
        let r = im.run_query_json(sql)?;
        Ok(serde_json::to_string(&r)?)
    } else {
        Ok("[]".to_string())
    }
}

/// Export snapshot bytes base64-encoded for a handle
pub fn inmemory_export_snapshot_base64(handle_id: &str) -> Result<String> {
    let map = INMEMORY_DB_HANDLES.lock().unwrap();
    if let Some(im) = map.get(handle_id) {
        let b = im.export_snapshot_bytes()?;
        Ok(base64::encode(&b))
    } else {
        Ok("".to_string())
    }
}

/// Close and remove an in-memory db handle
pub fn close_inmemory_db(id: &str) -> Result<()> {
    if let Some(_im) = INMEMORY_DB_HANDLES.lock().unwrap().remove(id) {
        // Drop will free memory
    }
    Ok(())
}

/// Close all handles and attempt secure cleanup
pub fn close_all() -> Result<()> {
    let mut dd = DECRYPTED_DB_HANDLES.lock().unwrap();
    for (_, d) in dd.drain() {
        let _ = d.close_and_delete();
    }
    let mut im = INMEMORY_DB_HANDLES.lock().unwrap();
    im.clear();
    Ok(())
}

/// List handle IDs (for debugging)
pub fn list_handles() -> Vec<String> {
    let mut vec = Vec::new();
    for k in DECRYPTED_DB_HANDLES.lock().unwrap().keys() { vec.push(k.clone()); }
    for k in INMEMORY_DB_HANDLES.lock().unwrap().keys() { vec.push(k.clone()); }
    vec
}