use client::Error;
use sunshine_identity_ffi::impl_ffi;
use test_client::Runtime;
// Test how the macro expands
// cargo expand --package sunshine-identity-ffi --test impl_ffi_macro -- test_impl_ffi_macro
#[test]
fn test_impl_ffi_macro() {
    async fn setup_client(_root: &str) -> Result<Client, Error> {
        Err(Error::RuntimeInvalid)
    }
    impl_ffi!(runtime: Runtime, client: setup_client);
}
