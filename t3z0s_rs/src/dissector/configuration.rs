use crypto::hash::HashType;
use failure::Error;
use lazy_static::lazy_static;
use libc::{c_char, c_int, c_uint, c_void};
use serde::Deserialize;
use std::ffi::CStr;
use std::ffi::OsString;
use std::fs;
use std::option::Option;
use std::sync::RwLock;

use hex;

use crate::dissector::logger::msg;

static DEFAULT_IDENTITY_FILEPATH: &'static str = "identity/identity.json";

#[derive(Deserialize, Clone, Debug, PartialEq)]
/// Node identity information
pub struct Identity {
    pub peer_id: String,
    pub public_key: String,
    pub secret_key: String,
    pub proof_of_work_stamp: String,
}

#[derive(Debug, Clone)]
/// Dissector configuration
pub(crate) struct Config {
    pub identity_json_filepath: String,
    pub identity: Identity, // As loaded from identity_json_filepath
}
impl Config {
    fn default() -> Result<Self, Error> {
        Ok(Self {
            identity_json_filepath: String::from(DEFAULT_IDENTITY_FILEPATH),
            identity: load_identity(&DEFAULT_IDENTITY_FILEPATH)?,
        })
    }
}

// Configuration is stored in global object.
// We use single threaded C code based on callbacks so such singleton like
// object seem acceptable. RwLock should be fast in this case and it doesn't
// require unsafe.
lazy_static! {
    static ref CONFIG_RWLOCK: RwLock<Option<Config>> = RwLock::new(None);
}

/// Load identity from given file path
pub fn load_identity(filepath: &str) -> Result<Identity, Error> {
    let content = fs::read_to_string(filepath)?;
    let mut identity: Identity = serde_json::from_str(&content)?;
    let decoded = hex::decode(&identity.public_key)?;
    identity.public_key = HashType::CryptoboxPublicKeyHash.bytes_to_string(&decoded);
    Ok(identity)
}

/// Load identity from file whose path is stored in C string
fn load_preferences(identity_json_filepath: *const c_char) -> Result<Config, Error> {
    let identity_json_filepath =
        unsafe { CStr::from_ptr(identity_json_filepath).to_str()?.to_owned() };

    let identity = load_identity(&identity_json_filepath)?;

    Ok(Config {
        identity_json_filepath,
        identity,
    })
}

#[no_mangle]
/// Called by Wireshark when module preferences change
pub extern "C" fn t3z0s_preferences_update(identity_json_filepath: *const c_char) {
    if identity_json_filepath.is_null() {
        // Interpret C NULL as a Rust None
        let mut cfg = CONFIG_RWLOCK.write().unwrap();
        *cfg = None;
    } else {
        // Load identity and store it to global object.
        // Use None if identity can not be loaded.
        let cfg_res = load_preferences(identity_json_filepath);
        let mut cfg = CONFIG_RWLOCK.write().unwrap();
        *cfg = match cfg_res {
            Ok(new_cfg) => Some(new_cfg),
            Err(e) => {
                msg(format!("Cannot load configuration: {}", e));
                None
            }
        }
    }
}

// Because we interact with single threaded callback based C code,
// it is practical to use singletons.

/// Return current version of configuration (as specified by last call to t3z0s_preferences_update())
pub(crate) fn get_configuration() -> Option<Config> {
    msg(format!("get_configuration"));
    let cfg = CONFIG_RWLOCK.read().unwrap();
    // TODO: Unecessary clone, maybe use shared-ptr?
    cfg.clone()
}
