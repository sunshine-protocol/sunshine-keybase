use sunshine_faucet_ffi::impl_ffi;
use test_client::Client;

// Test how the macro expands
// cargo expand --package sunshine-faucet-ffi --test impl_ffi_macro -- test_impl_ffi_macro
#[test]
fn test_impl_ffi_macro() {
    impl_ffi!(client: Client);
}
