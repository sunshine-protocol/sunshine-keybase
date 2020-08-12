pub use sunshine_ffi_utils as utils;
#[doc(hidden)]
pub mod ffi;

/// Generate the FFI for the provided runtime
///
/// ### Example
/// ```
/// use test_client::Client;
/// use sunshine_faucet_ffi::impl_ffi;
///
/// impl_ffi!(client: Client);
/// ```
#[macro_export]
macro_rules! impl_ffi {
    () => {
        use $crate::ffi::Faucet;
        gen_ffi! {
            /// Try to mint the current account, this only enabled in testnet and behind a feature flag
            /// returned the minted amount or null if there is any errors
            Faucet::mint => fn client_faucet_mint() -> String;
        }
    };
    (client: $client: ty) => {
        #[allow(unused)]
        use $crate::utils::*;
        gen_ffi!(client = $client);
        $crate::impl_ffi!();
    };
}
