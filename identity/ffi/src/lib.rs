pub use sunshine_ffi_utils as utils;

#[doc(hidden)]
pub mod ffi;

#[doc(hidden)]
#[cfg(feature = "identity-key")]
#[macro_export]
macro_rules! impl_identity_key_ffi {
    () => {
        use $crate::ffi::Key;
        gen_ffi! {
             /// Check if the Keystore is exist and initialized.
            ///
            /// this is useful if you want to check if there is an already created account or not.
            Key::exists => fn client_key_exists() -> bool;
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
            /// Get current UID as string (if any)
            /// otherwise null returned
            Key::uid => fn client_key_uid() -> Option<String>;
        }
    }
}

#[doc(hidden)]
#[cfg(not(feature = "identity-key"))]
#[macro_export]
macro_rules! impl_identity_key_ffi {
    () => {};
}

#[doc(hidden)]
#[cfg(feature = "identity-wallet")]
#[macro_export]
macro_rules! impl_identity_wallet_ffi {
    () => {
        use $crate::ffi::Wallet;
        gen_ffi! {
            /// Get the balance of an identifier.
            /// returns and string but normally it's a `u128` encoded as string.
            Wallet::balance => fn client_wallet_balance(identifier: *const raw::c_char = cstr!(identifier, allow_null)) -> String;
            /// Transfer tokens to another account using there `identifier`
            /// returns current account balance after the transaction.
            Wallet::transfer => fn client_wallet_transfer(
                to: *const raw::c_char = cstr!(to),
                amount: u64 = amount
            ) -> String;
        }
    };
}

#[doc(hidden)]
#[cfg(not(feature = "identity-wallet"))]
#[macro_export]
macro_rules! impl_identity_wallet_ffi {
    () => {};
}


#[doc(hidden)]
#[cfg(feature = "identity-account")]
#[macro_export]
macro_rules! impl_identity_account_ffi {
    () => {
        use $crate::ffi::Account;
        gen_ffi! {
            /// Creates Account for that device id.
            /// returns `true` if it got created.
            Account::create => fn client_account_create(device: *const raw::c_char = cstr!(device)) -> bool;
            /// Changes Current Account Password.
            /// returns `true` if it got updated.
            Account::change_password => fn client_account_change_password(
                to: *const raw::c_char = cstr!(to)
            ) -> bool;
        }
    };
}

#[doc(hidden)]
#[cfg(not(feature = "identity-account"))]
#[macro_export]
macro_rules! impl_identity_account_ffi {
    () => {};
}


#[doc(hidden)]
#[cfg(feature = "identity-device")]
#[macro_export]
macro_rules! impl_identity_device_ffi {
    () => {
        use $crate::ffi::Device;
        gen_ffi! {
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
        }
    };
}

#[doc(hidden)]
#[cfg(not(feature = "identity-device"))]
#[macro_export]
macro_rules! impl_identity_device_ffi {
    () => {};
}

#[doc(hidden)]
#[cfg(feature = "identity-id")]
#[macro_export]
macro_rules! impl_identity_id_ffi {
    () => {
        use $crate::ffi::ID;
        gen_ffi! {
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

        }
    }
}

#[doc(hidden)]
#[cfg(not(feature = "identity-id"))]
#[macro_export]
macro_rules! impl_identity_id_ffi {
    () => {};
}

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
        $crate::impl_identity_key_ffi!();
        $crate::impl_identity_device_ffi!();
        $crate::impl_identity_id_ffi!();
        $crate::impl_identity_wallet_ffi!();
        $crate::impl_identity_account_ffi!();
    };
    (client: $client: ty) => {
        use ::std::os::raw;
        #[allow(unused)]
        use $crate::utils::*;
        gen_ffi!(client = $client);
        $crate::impl_ffi!();
    };
}
