#![allow(clippy::not_unsafe_ptr_arg_deref)]
use allo_isolate::Isolate;
use async_std::task;
use ffi_helpers::null_pointer_check;
use ipfs_embed::{Config, Store};
use keystore::bip39::{Language, Mnemonic};
use keystore::{DeviceKey, KeyStore, Password};
use std::{ffi::CStr, os::raw, path::PathBuf};
use substrate_subxt::balances::{TransferCallExt, TransferEventExt};
use substrate_subxt::sp_core::{crypto::Ss58Codec, sr25519};
use substrate_subxt::{ClientBuilder, Signer};

mod runtime;
use runtime::{Extra, Runtime, Signature, Uid};

mod macros;

type Client = client::Client<Runtime, Signature, Extra, sr25519::Pair, Store>;

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
    unsafe {
        if CLIENT.is_some() {
            return CLIENT_ALREADY_INIT;
        }
    }
    let root = cstr!(path);
    let paths = Paths::new(root);
    let isolate = Isolate::new(port);
    task::spawn(async move {
        let keystore = KeyStore::open(&paths.keystore).await;
        let keystore = isolate_err!(keystore, isolate, CLIENT_KEYSTORE_OPEN_ERR);
        let subxt = ClientBuilder::new().build().await;
        let subxt = isolate_err!(subxt, isolate, CLIENT_SUBXT_CREATE_ERR);
        let config = Config::from_path(&paths.db).map_err(ipfs_embed::Error::Sled);
        let config = isolate_err!(config, isolate, CLIENT_IPFS_CONFIG_ERR);
        let store = Store::new(config);
        let store = isolate_err!(store, isolate, CLIENT_IPFS_STORE_ERR);
        let client = Client::new(keystore, subxt, store);
        unsafe {
            CLIENT.replace(client);
        }
        isolate.post(CLIENT_OK);
        CLIENT_OK
    });
    CLIENT_OK
}

/// Check if the current client has a device key already or not
#[no_mangle]
pub extern "C" fn client_has_device_key(port: i64) -> i32 {
    let isolate = Isolate::new(port);
    task::spawn(async move {
        let client = client!(isolate);
        isolate.post(client.has_device_key().await);
        CLIENT_OK
    });
    CLIENT_OK
}

/// Set a new Key for this device if not already exist.
///
/// suri is used for testing only.
///
/// ### Safety
/// Suri coud be empty string for indicating that we don't have to use it
#[no_mangle]
pub extern "C" fn client_key_set(
    port: i64,
    suri: *const raw::c_char,
    password: *const raw::c_char,
) -> i32 {
    let isolate = Isolate::new(port);
    let suri = cstr!(suri);
    let password = cstr!(password);
    task::spawn(async move {
        let client = client!(isolate);
        let password = Password::from(password.to_owned());
        if password.expose_secret().len() < 8 {
            isolate.post(CLIENT_PASSWORD_TOO_SHORT);
            return CLIENT_PASSWORD_TOO_SHORT;
        }
        CLIENT_OK
    });
    CLIENT_OK
}
