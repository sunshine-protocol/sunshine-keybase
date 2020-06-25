use crate::mock::*;
use frame_support::assert_ok;

#[test]
fn set_identity() {
    new_test_ext().execute_with(|| {
        let key1 = Origin::signed(1);
        let key2 = Origin::signed(2);
        assert_ok!(IdentityModule::create_account_for(Origin::signed(0), 1));
        assert_eq!(IdentityModule::identity(0), None);

        assert_ok!(IdentityModule::set_identity(key1.clone(), None, 42));
        assert_eq!(IdentityModule::identity(0), Some(42));

        assert_ok!(IdentityModule::add_key(key1.clone(), 2));
        assert_ok!(IdentityModule::set_identity(key2.clone(), Some(42), 43));
        assert_eq!(IdentityModule::identity(0), Some(43));

        assert_ok!(IdentityModule::remove_key(key1, 2));
        assert!(IdentityModule::set_identity(key2, Some(43), 44).is_err());
        assert_eq!(IdentityModule::identity(0), Some(43));
    });
}

#[test]
fn change_password() {
    new_test_ext().execute_with(|| {
        let key1 = Origin::signed(1);
        let key2 = Origin::signed(2);
        assert_ok!(IdentityModule::create_account_for(Origin::signed(0), 1));
        assert_ok!(IdentityModule::add_key(key1, 2));
        assert!(IdentityModule::change_password(key2.clone(), [0; 32], 0).is_err());
        assert_ok!(IdentityModule::change_password(key2, [0; 32], 1));
    });
}
