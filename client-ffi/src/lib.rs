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
use suri::Suri;

mod suri;

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
    let t = isolate.task(async move {
        let keystore = result!(
            KeyStore::open(&paths.keystore).await,
            CLIENT_KEYSTORE_OPEN_ERR
        );
        let subxt = result!(ClientBuilder::new().build().await, CLIENT_SUBXT_CREATE_ERR);
        let config = result!(Config::from_path(&paths.db), CLIENT_IPFS_CONFIG_ERR);
        let store = result!(Store::new(config), CLIENT_IPFS_STORE_ERR);
        let client = Client::new(keystore, subxt, store);
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
pub extern "C" fn client_has_device_key(port: i64) {
    let isolate = Isolate::new(port);
    let t = isolate.task(async move {
        let client = client!(isolate);
        isolate.post(client.has_device_key().await);
        CLIENT_OK
    });
    task::spawn(t);
}

/// Set a new Key for this device if not already exist.
///
/// suri is used for testing only.
///
/// ### Safety
/// suri could be empty string for indicating that we don't have to use it
/// phrase could be emoty string for indicating that we don't have to create a device key from it.
#[no_mangle]
pub extern "C" fn client_key_set(
    port: i64,
    suri: *const raw::c_char,
    password: *const raw::c_char,
    phrase: *const raw::c_char,
) -> i32 {
    let isolate = Isolate::new(port);
    let password = cstr!(password);
    let phrase = cstr!(phrase);
    let suri = cstr!(suri);
    let suri = if suri.is_empty() {
        None
    } else {
        Some(result!(suri.parse::<Suri>()).0)
    };
    let dk = if !phrase.is_empty() {
        let mnemonic = result!(Mnemonic::from_phrase(phrase, Language::English));
        Some(result!(DeviceKey::from_mnemonic(&mnemonic)))
    } else if let Some(seed) = suri {
        Some(DeviceKey::from_seed(seed))
    } else {
        None
    };
    let password = Password::from(password.to_owned());
    if password.expose_secret().len() < 8 {
        return CLIENT_PASSWORD_TOO_SHORT;
    }
    let client = client!(isolate);
    let t = isolate.task(async move {
        let dk = if let Some(dk) = dk {
            dk
        } else {
            DeviceKey::generate().await
        };
        // dose not compile
        let account_id = result!(client.set_device_key(&dk, &password, false).await);
        CLIENT_OK
    });
    task::spawn(t);
    CLIENT_OK
}
