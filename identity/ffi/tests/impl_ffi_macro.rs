use client::Error;
use sunshine_identity_ffi::impl_ffi;
use test_client::{Client, Runtime};
// Test how the macro expands
// cargo expand --package sunshine-identity-ffi --test impl_ffi_macro -- test_impl_ffi_macro
#[test]
fn test_impl_ffi_macro() {
    impl_ffi!(runtime: Runtime, client: Client);
}
