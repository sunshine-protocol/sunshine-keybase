pub use {
    allo_isolate, async_std, client, ffi_helpers, ipfs_embed, keystore, log, substrate_subxt, utils,
};

#[cfg(feature = "faucet")]
pub use faucet_client;

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
        use $crate::allo_isolate::Isolate;
        use $crate::async_std::task;
        use $crate::client;
        #[cfg(feature = "faucet")]
        use $crate::faucet_client;
        use $crate::ipfs_embed::{Config, Store};
        use $crate::keystore::bip39::{Language, Mnemonic};
        use $crate::keystore::{DeviceKey, KeyStore, Password};
        use $crate::log::{error, info};
        use $crate::substrate_subxt::balances::{Balances, TransferCallExt, TransferEventExt};
        use $crate::substrate_subxt::sp_core::sr25519;
        use $crate::substrate_subxt::{ClientBuilder, Signer};
        use $crate::substrate_subxt::{SignedExtension, SignedExtra};

        type Suri = client::Suri<sr25519::Pair>;
        type Client = client::Client<$runtime, sr25519::Pair, Store>;

        static mut CLIENT: Option<Client> = None;

        $crate::__enum_result! {
          CLIENT_UNKNOWN = -1,
          CLIENT_OK = 1,
          CLIENT_BAD_CSTR = 2,
          CLIENT_CREATE_ERR = 3,
          CLIENT_UNINIT = 4,
          CLIENT_ALREADY_INIT = 5,
          CLIENT_HAS_DEVICE_KEY = 6,
          CLIENT_PASSWORD_TOO_SHORT = 7,
          CLIENT_BAD_SURI = 8,
          CLIENT_BAD_MNEMONIC = 9,
          CLIENT_BAD_UID = 10,
          CLIENT_FAIL_TO_LOCK = 11,
          CLIENT_LOCKED_OK = 12,
          CLIENT_FAIL_TO_UNLOCK = 13,
          CLIENT_UNLOCKED_OK = 14,
          CLIENT_UNKNOWN_SERVICE = 15,
        }

        #[no_mangle]
        pub extern "C" fn last_error_length() -> i32 {
            $crate::ffi_helpers::error_handling::last_error_length()
        }

        #[allow(clippy::missing_safety_doc)]
        #[no_mangle]
        pub unsafe extern "C" fn error_message_utf8(buf: *mut raw::c_char, length: i32) -> i32 {
            $crate::ffi_helpers::error_handling::error_message_utf8(buf, length)
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
            let root = $crate::__cstr!(path);
            let isolate = Isolate::new(port);
            let t = isolate.task(async move {
                let client: Client = $crate::__result!($client(root).await, CLIENT_CREATE_ERR);
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
            let client = $crate::__client!();
            let t = isolate.task(client.has_device_key());
            task::spawn(t);
            CLIENT_OK
        }

        /// Set a new Key for this device if not already exist.
        /// you should call `client_has_device_key` first to see if you have already a key.
        ///
        /// suri is used for testing only.
        /// phrase is used to restore a backup
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        #[no_mangle]
        pub extern "C" fn client_key_set(
            port: i64,
            suri: *const raw::c_char,
            password: *const raw::c_char,
            phrase: *const raw::c_char,
        ) -> i32 {
            let isolate = Isolate::new(port);
            let password = $crate::__cstr!(password);
            let suri = $crate::__cstr!(suri, allow_null).and_then(|v| v.parse::<Suri>().ok());
            let mnemonic = $crate::__cstr!(phrase, allow_null)
                .and_then(|p| Mnemonic::from_phrase(p, Language::English).ok());
            let dk = if let Some(mnemonic) = mnemonic {
                Some($crate::__result!(
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
            let client = $crate::__client!();
            let t = isolate.task(async move {
                let dk = if let Some(dk) = dk {
                    dk
                } else {
                    DeviceKey::generate().await
                };
                let device_id =
                    $crate::__result!(client.set_device_key(&dk, &password, false).await, None);
                Some(device_id.to_string())
            });
            task::spawn(t);
            CLIENT_OK
        }

        #[cfg(feature = "faucet")]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        #[no_mangle]
        pub extern "C" fn client_faucet_mint(port: i64, identifier: *const raw::c_char) -> i32 {
            let client = $crate::__client!();
            let isolate = Isolate::new(port);
            let identifier = $crate::__cstr!(identifier);
            let t = isolate.task(async move {
                let ss58 = $crate::__result!(identifier.parse::<client::Ss58::<$runtime>>(), 0);
                let mint = $crate::__result!(faucet_client::mint(client.subxt(), &ss58.0).await, 0);
                if let Some(minted) = mint {
                    minted.amount
                } else {
                    0
                }
            });
            task::spawn(t);
            CLIENT_OK
        }

        /// Get the UID of identifier as String (if any)
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        #[no_mangle]
        pub extern "C" fn client_resolve_uid(port: i64, identifier: *const raw::c_char) -> i32 {
            let client = $crate::__client!();
            let isolate = Isolate::new(port);
            let identifier = $crate::__cstr!(identifier, allow_null).and_then(|v| v.parse().ok());
            let t = isolate.task(async move {
                let uid = $crate::__result!(client::resolve(client, identifier).await, None);
                Some(uid.to_string())
            });
            task::spawn(t);
            CLIENT_OK
        }

        /// Get the a list that contains all the client identity data
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        #[no_mangle]
        pub extern "C" fn client_identity(port: i64, uid: *const raw::c_char) -> i32 {
            let client = $crate::__client!();
            let isolate = Isolate::new(port);
            let uid = $crate::__result!($crate::__cstr!(uid).parse(), CLIENT_BAD_UID);
            let t = isolate.task(async move {
                let info: Vec<_> = $crate::__result!(client.identity(uid).await, None)
                    .into_iter()
                    .map(|v| v.to_string())
                    .collect();
                Some(info)
            });
            task::spawn(t);
            CLIENT_OK
        }

        /// Prove the account identity for the provided service and there id
        ///
        /// Current Avalibale Services
        /// Github = 1
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        #[no_mangle]
        pub extern "C" fn client_prove_identity(
            port: i64,
            service: i32,
            id: *const raw::c_char,
        ) -> i32 {
            let client = $crate::__client!();
            let isolate = Isolate::new(port);
            let id = $crate::__cstr!(id);
            let service = match service {
                1 => client::Service::Github(id.to_owned()),
                _ => return CLIENT_UNKNOWN_SERVICE,
            };
            let t = isolate.task(async move {
                let instructions = service.cli_instructions();
                let proof = $crate::__result!(client.prove_identity(service).await, None);
                Some(vec![instructions, proof])
            });
            task::spawn(t);
            CLIENT_OK
        }

        /// Lock the client
        #[no_mangle]
        pub extern "C" fn client_lock(port: i64) -> i32 {
            let client = $crate::__client!();
            let isolate = Isolate::new(port);
            let t = isolate.task(async move {
                $crate::__result!(client.lock().await, CLIENT_FAIL_TO_LOCK);
                CLIENT_LOCKED_OK
            });
            task::spawn(t);
            CLIENT_OK
        }

        /// UnLock the client
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        #[no_mangle]
        pub extern "C" fn client_unlock(port: i64, password: *const raw::c_char) -> i32 {
            let client = $crate::__client!();
            let isolate = Isolate::new(port);
            let password = $crate::__cstr!(password);
            let password = Password::from(password.to_owned());
            let t = isolate.task(async move {
                $crate::__result!(client.unlock(&password).await, CLIENT_FAIL_TO_UNLOCK);
                CLIENT_UNLOCKED_OK
            });
            task::spawn(t);
            CLIENT_OK
        }

        /// Add new paperkey from the current account
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        #[no_mangle]
        pub extern "C" fn client_add_paperkey(port: i64) -> i32 {
            let client = $crate::__client!();
            let isolate = Isolate::new(port);
            let t = isolate.task(async move {
                let mnemonic = $crate::__result!(client.add_paperkey().await, None);
                Some(mnemonic.into_phrase())
            });
            task::spawn(t);
            CLIENT_OK
        }

        /// Get account id
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        #[no_mangle]
        pub extern "C" fn client_current_device_id(port: i64) -> i32 {
            let client = $crate::__client!();
            let isolate = Isolate::new(port);
            let t = isolate.task(async move {
                let signer = $crate::__result!(client.signer().await, None);
                Some(signer.account_id().to_string())
            });
            task::spawn(t);
            CLIENT_OK
        }

        /// Get account balance
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        #[no_mangle]
        pub extern "C" fn client_balance(port: i64, identifier: *const raw::c_char) -> i32 {
            let client = $crate::__client!();
            let isolate = Isolate::new(port);
            let identifier = $crate::__cstr!(identifier, allow_null).and_then(|v| v.parse().ok());
            let t = isolate.task(async move {
                let uid = $crate::__result!(client::resolve(client, identifier).await, None);
                let account = $crate::__result!(client.fetch_account(uid).await, None);
                Some(account.free.to_string())
            });
            task::spawn(t);
            CLIENT_OK
        }

        /// transfer to another account
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        #[no_mangle]
        pub extern "C" fn client_transfer(
            port: i64,
            identifier: *const raw::c_char,
            amount: u128,
        ) -> i32 {
            let client = $crate::__client!();
            let isolate = Isolate::new(port);
            let identifier = $crate::__cstr!(identifier, allow_null).and_then(|v| v.parse().ok());
            let t = isolate.task(async move {
                let uid = $crate::__result!(client::resolve(client, identifier).await, None);
                let signer = $crate::__result!(client.signer().await, None);
                let keys = $crate::__result!(client.fetch_keys(uid, None).await, None);
                let event = $crate::__result!(
                    client
                        .subxt()
                        .transfer_and_watch(&signer, &keys[0].clone().into(), amount.into())
                        .await,
                    None
                );
                let event = $crate::__result!(event.transfer(), None);
                if let Some(e) = event {
                    Some(e.to.to_string())
                } else {
                    None
                }
            });
            task::spawn(t);
            CLIENT_OK
        }
    };
}
