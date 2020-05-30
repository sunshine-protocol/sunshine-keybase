use crate::mock::*;
use frame_support::assert_ok;

#[test]
fn set_identity() {
    new_test_ext().execute_with(|| {
        assert_eq!(IdentityModule::identity(1), None);
        assert_ok!(IdentityModule::set_identity(Origin::signed(1), 42));
        assert_eq!(IdentityModule::identity(1), Some(42));
    });
}
