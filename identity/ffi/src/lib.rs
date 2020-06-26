#![allow(clippy::not_unsafe_ptr_arg_deref)]
use allo_isolate::Isolate;
use async_std::task;
use ffi_helpers::null_pointer_check;
use ipfs_embed::{Config, Store};
use keystore::bip39::{Language, Mnemonic};
use keystore::{DeviceKey, KeyStore, Password};
use std::{ffi::CStr, os::raw, path::PathBuf};
use substrate_subxt::sp_core::sr25519;
use substrate_subxt::{ClientBuilder, Signer};

use test_client::Runtime;

mod macros;

type Suri = client::Suri<sr25519::Pair>;
type Client = client::Client<Runtime, sr25519::Pair, Store>;

static mut CLIENT: Option<Client> = None;

enum_result! {
  CLIENT_UNKNOWN = -1,
  CLIENT_OK = 1,
  CLIENT_BAD_CSTR = 2,
  CLIENT_SUBXT_CREATE_ERR = 3,
  CLIENT_IPFS_CONFIG_ERR = 4,
  CLIENT_KEYSTORE_OPEN_ERR = 5,
  CLIENT_IPFS_STORE_ERR = 6,
  CLIENT_UNINIT = 7,
  CLIENT_ALREADY_INIT = 8,
  CLIENT_HAS_DEVICE_KEY = 9,
  CLIENT_PASSWORD_TOO_SHORT = 10,
  CLIENT_BAD_SURI = 11,
  CLIENT_BAD_MNEMONIC = 12,
}

struct Paths {
    keystore: PathBuf,
    db: PathBuf,
}

impl Paths {
    fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let keystore = root.join("keystore");
        let db = root.join("db");
        Paths { keystore, db }
    }
}

#[no_mangle]
pub extern "C" fn last_error_length() -> i32 {
    ffi_helpers::error_handling::last_error_length()
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn error_message_utf8(buf: *mut raw::c_char, length: i32) -> i32 {
    ffi_helpers::error_handling::error_message_utf8(buf, length)
}

/// Setup the Sunshine identity client using the provided path as the base path
///
/// ### Safety
/// This assumes that the path is non-null c string.
#[no_mangle]
pub extern "C" fn client_init(port: i64, path: *const raw::c_char) -> i32 {
    // check if we already created the client, and return `CLIENT_ALREADY_INIT`
    // if it is already created to avoid any unwanted work
    // SAFETY:
    // this safe we only check that before doing anything else.
    unsafe {
        if CLIENT.is_some() {
            return CLIENT_ALREADY_INIT;
        }
    }
    let root = cstr!(path);
    let paths = Paths::new(root);
    let isolate = Isolate::new(port);
    let t = isolate.task(async move {
        let keystore = result!(
            KeyStore::open(&paths.keystore).await,
            CLIENT_KEYSTORE_OPEN_ERR
        );
        let subxt = result!(ClientBuilder::new().build().await, CLIENT_SUBXT_CREATE_ERR);
        let config = result!(Config::from_path(&paths.db), CLIENT_IPFS_CONFIG_ERR);
        let store = result!(Store::new(config), CLIENT_IPFS_STORE_ERR);
        let client = Client::new(keystore, subxt, store);
        // SAFETY:
        // this safe since we checked that the client is already not created before.
        unsafe {
            CLIENT.replace(client);
        }
        CLIENT_OK
    });
    task::spawn(t);
    CLIENT_OK
}

/// Check if the current client has a device key already or not
#[no_mangle]
pub extern "C" fn client_has_device_key(port: i64) -> i32 {
    let isolate = Isolate::new(port);
    let client = client!();
    let t = isolate.task(client.has_device_key());
    task::spawn(t);
    CLIENT_OK
}

/// Set a new Key for this device if not already exist.
/// you should call `client_has_device_key` first to see if you have already a key.
///
/// suri is used for testing only.
/// phrase is used to restore a backup
#[no_mangle]
pub extern "C" fn client_key_set(
    port: i64,
    suri: *const raw::c_char,
    password: *const raw::c_char,
    phrase: *const raw::c_char,
) -> i32 {
    let isolate = Isolate::new(port);
    let password = cstr!(password);
    let suri = cstr!(suri, allow_null).and_then(|v| v.parse::<Suri>().ok());
    let mnemonic =
        cstr!(phrase, allow_null).and_then(|p| Mnemonic::from_phrase(p, Language::English).ok());
    let dk = if let Some(mnemonic) = mnemonic {
        Some(result!(
            DeviceKey::from_mnemonic(&mnemonic),
            CLIENT_BAD_MNEMONIC
        ))
    } else if let Some(seed) = suri {
        Some(DeviceKey::from_seed(seed.0))
    } else {
        None
    };
    let password = Password::from(password.to_owned());
    if password.expose_secret().len() < 8 {
        return CLIENT_PASSWORD_TOO_SHORT;
    }
    let client = client!();
    let t = isolate.task(async move {
        let dk = if let Some(dk) = dk {
            dk
        } else {
            DeviceKey::generate().await
        };
        let account_id = result!(client.set_device_key(&dk, &password, false).await, None);
        result!(client.fetch_uid(&account_id).await, None)
    });
    task::spawn(t);
    CLIENT_OK
}

/// Get the account id of the current device as String (if any)
/// Note: the device key must be in unlocked state otherwise `null` is returuned
#[no_mangle]
pub extern "C" fn client_account_id(port: i64) -> i32 {
    let client = client!();
    let isolate = Isolate::new(port);
    let t = isolate.task(async move {
        // TODO
        let signer = result!(client.signer().await, None);
        Some(signer.account_id().to_string())
    });
    task::spawn(t);
    CLIENT_OK
}
