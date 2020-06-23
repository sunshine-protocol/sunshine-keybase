use allo_isolate::Isolate;
use async_std::{
    sync::{Arc, Mutex},
    task,
};
use ffi_helpers::null_pointer_check;
use ipfs_embed::{Config, Store};
use keystore::bip39::{Language, Mnemonic};
use keystore::{DeviceKey, KeyStore, Password};
use lazy_static::lazy_static;
use std::{
    ffi::{CStr, CString},
    mem::MaybeUninit,
    os::raw,
    path::PathBuf,
};
use substrate_subxt::balances::{TransferCallExt, TransferEventExt};
use substrate_subxt::sp_core::{crypto::Ss58Codec, sr25519};
use substrate_subxt::{ClientBuilder, Signer};

mod runtime;
use runtime::{Extra, Runtime, Signature, Uid};

mod macros;

mod result;
use result::*;

type Client = client::Client<Runtime, Signature, Extra, sr25519::Pair, Store>;

lazy_static! {
    static ref CLIENT: Arc<Mutex<Option<Client>>> = Arc::new(Mutex::new(None));
}

struct Paths {
    keystore: PathBuf,
    db: PathBuf,
}

impl Paths {
    pub(crate) fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let keystore = root.join("keystore");
        let db = root.join("db");
        Paths { keystore, db }
    }
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn last_error_length() -> i32 {
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
pub unsafe extern "C" fn init_client(port: i64, path: *const raw::c_char) -> i32 {
    let root = cstr!(path);
    let paths = Paths::new(root);
    let isolate = Isolate::new(port);
    task::spawn(async move {
        let keystore = KeyStore::new(&paths.keystore);
        let subxt = ClientBuilder::new().build().await;
        let subxt = isolate_err!(subxt, isolate, CLIENT_SUBXT_CREATE_ERR);
        let config = Config::from_path(&paths.db).map_err(ipfs_embed::Error::Sled);
        let config = isolate_err!(config, isolate, CLIENT_IPFS_CONFIG_ERR);
        let store = Store::new(config);
        let store = isolate_err!(store, isolate, CLIENT_IPFS_STORE_ERR);
        let client = Client::new(keystore, subxt, store);
        let mut c = CLIENT.lock().await;
        c.replace(client);
        isolate.post(CLIENT_OK);
        CLIENT_OK
    });
    CLIENT_OK
}
