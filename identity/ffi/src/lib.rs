pub use {allo_isolate, async_std, client, ipfs_embed, keystore, log, substrate_subxt, utils};

#[cfg(feature = "faucet")]
#[doc(hidden)]
pub use faucet_client;
#[doc(hidden)]
pub mod error;
#[doc(hidden)]
pub mod ffi;
mod macros;

/// Generate the FFI for the provided runtime
///
/// ### Example
/// ```
/// use test_client::Runtime;
/// use sunshine_identity_ffi::impl_ffi;
/// use sunshine_identity_ffi::client::Error;
///
/// async fn setup_client(root: &str) -> Result<Client, Error> {
///     // Client Setup here..
///     # Err(Error::RuntimeInvalid)
/// }
/// impl_ffi!(runtime: Runtime, client: setup_client);
/// ```
#[macro_export]
macro_rules! impl_ffi {
    (client: $client: expr, runtime: $runtime: ty) => {
        impl_ffi!($runtime, $client);
    };
    (runtime: $runtime: ty, client: $client: expr) => {
        use ::std::{ffi::CStr, os::raw, path::PathBuf};
        use allo_isolate::Isolate;
        use async_std::task;
        use client;
        #[cfg(feature = "faucet")]
        use faucet_client;
        use ipfs_embed::{Config, Store};
        use keystore::bip39::{Language, Mnemonic};
        use keystore::{DeviceKey, KeyStore, Password};
        use log::{error, info};
        use substrate_subxt::balances::{Balances, TransferCallExt, TransferEventExt};
        use substrate_subxt::sp_core::sr25519;
        use substrate_subxt::{ClientBuilder, Signer};
        use substrate_subxt::{SignedExtension, SignedExtra};
        #[allow(unused)]
        use $crate::*;

        /// cbindgen:ignore
        type Suri = client::Suri<sr25519::Pair>;
        /// cbindgen:ignore
        type Client = client::Client<$runtime, sr25519::Pair, Store>;

        /// cbindgen:ignore
        static mut CLIENT: Option<Client> = None;

        enum_result! {
          CLIENT_UNKNOWN = -1,
          CLIENT_OK = 1,
          CLIENT_BAD_CSTR = 2,
          CLIENT_CREATE_ERR = 3,
          CLIENT_UNINIT = 4,
          CLIENT_ALREADY_INIT = 5,
        }

        /// Setup the Sunshine identity client using the provided path as the base path
        ///
        /// ### Safety
        /// This assumes that the path is non-null c string.
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
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
            let isolate = Isolate::new(port);
            let t = isolate.task(async move {
                let client: Client = result!($client(root).await, CLIENT_CREATE_ERR);
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

        gen_ffi! {
            /// Set a new Key for this device if not already exist.
            /// you should call `client_has_device_key` first to see if you have already a key.
            ///
            /// suri is used for testing only.
            /// phrase is used to restore a backup
            /// returns a string that is the current device id
            Key::set => fn client_key_set(
                password: *const raw::c_char = cstr!(password),
                suri: *const raw::c_char = cstr!(suri, allow_null),
                paperkey: *const raw::c_char = cstr!(paperkey, allow_null)
            ) -> String;
            /// Lock your account
            /// return `true` if locked, and return an error message if something went wrong
            Key::lock => fn client_key_lock() -> bool;
            /// Unlock your account using the password
            /// return `true` when the account get unlocked, otherwise an error message returned
            Key::unlock => fn client_key_unlock(password: *const raw::c_char = cstr!(password)) -> bool;

            /// Check if the current client has a device key already or not
            Device::has_device_key => fn client_device_has_key() -> bool;
            /// Get current Device ID as string (if any)
            /// otherwise null returned
            Device::current => fn client_device_current() -> Option<String>;
            /// add a new device to your account
            /// the `device` should be in the `ss58` format
            Device::add => fn client_device_add(device: *const raw::c_char = cstr!(device)) -> bool;
            /// remove a device from your account
            /// the `device` should be in the `ss58` fromat
            Device::remove => fn client_device_remove(device: *const raw::c_char = cstr!(device)) -> bool;
            /// get a list of devices that linked to that identifier
            /// returns list of devices ids in `ss58` fromat (as strings) or an error message
            Device::list => fn client_device_list(identifier: *const raw::c_char = cstr!(identifier)) -> Vec<String>;
            /// Generate a new backup paper key that can be used to recover your account
            /// returns a string that contains the phrase, otherwise null if there is an error
            Device::paperkey => fn client_device_paperkey() -> Option<String>;

            /// Get the `UID` of the provided identifier
            ID::resolve => fn client_id_resolve(identifier: *const raw::c_char = cstr!(identifier)) -> Option<String>;
            /// get a list of identities of the provided identifier.
            ID::list => fn client_id_list(identifier: *const raw::c_char = cstr!(identifier)) -> Vec<String>;
            /// prove the current account identity to a service.
            /// the service string should be in the format of `username@service` for example `shekohex@github`
            /// returns a pair (list of two values) the first element is the `instructions` of how to prove the identity
            /// the second element is the `proof` itself where you should follow the instructions and post it somewhere.
            /// otherwise and error returned as string.
            ID::prove => fn client_id_prove(service: *const raw::c_char = cstr!(service)) -> (String, String);
            /// revoke your identity from the provided service
            /// see `client_id_prove` for more information.
            /// returns `true` if the identity revoked.
            ID::revoke => fn client_id_revoke(service: *const raw::c_char = cstr!(service)) -> bool;

            /// Get the balance of an identifier.
            /// returns and string but normally it's a `u128` encoded as string.
            Wallet::balance => fn client_wallet_balance(identifier: *const raw::c_char = cstr!(identifier)) -> String;
            /// Transfer tokens to another account using there `identifier`
            /// returns current account balance after the transaction.
            Wallet::transfer => fn client_wallet_transfer(
                identifier: *const raw::c_char = cstr!(identifier),
                amount: u64 = amount
            ) -> String;

            /// Try to mint the account, this only enabled in testnet and behind a feature flag
            /// returned the minted amount or null if there is any errors
            #[cfg(feature = "faucet")]
            Faucet::mint => fn client_faucet_mint(identifier: *const raw::c_char = cstr!(identifier)) -> String;

        }
    };
}
