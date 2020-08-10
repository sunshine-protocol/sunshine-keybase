pub use sunshine_ffi_utils as utils;
#[doc(hidden)]
pub mod ffi;

/// Generate the FFI for the provided runtime
///
/// ### Example
/// ```
/// use test_client::Client;
/// use sunshine_identity_ffi::impl_ffi;
///
/// impl_ffi!(client: Client);
/// ```
#[macro_export]
macro_rules! impl_ffi {
    () => {
        use ::std::os::raw;
        #[allow(unused)]
        use $crate::utils::*;
        #[allow(unused)]
        use $crate::ffi::*;

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

            /// Try to mint the current account, this only enabled in testnet and behind a feature flag
            /// returned the minted amount or null if there is any errors
            #[cfg(feature = "faucet")]
            Faucet::mint => fn client_faucet_mint() -> String;

        }
    };
    (client: $client: ty) => {
        gen_ffi!(client = $client);
        $crate::impl_ffi!();
    };
}
