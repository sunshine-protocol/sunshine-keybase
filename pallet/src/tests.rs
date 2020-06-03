use crate::mock::*;
use frame_support::assert_ok;

#[test]
fn set_identity() {
    new_test_ext().execute_with(|| {
        let device1 = Origin::signed(1);
        let device2 = Origin::signed(2);
        let mask = [1u8; 32];
        assert_ok!(IdentityModule::create_account(device1.clone(), mask));
        assert_eq!(IdentityModule::identity(0), None);

        assert_ok!(IdentityModule::set_identity(device1.clone(), None, 42));
        assert_eq!(IdentityModule::identity(0), Some(42));

        assert_ok!(IdentityModule::add_device(device1.clone(), 2));
        assert_ok!(IdentityModule::set_identity(device2.clone(), Some(42), 43));
        assert_eq!(IdentityModule::identity(0), Some(43));

        assert_ok!(IdentityModule::remove_device(device1, 2));
        assert!(IdentityModule::set_identity(device2, Some(43), 44).is_err());
        assert_eq!(IdentityModule::identity(0), Some(43));
    });
}

#[test]
fn change_password() {
    new_test_ext().execute_with(|| {
        let device1 = Origin::signed(1);
        let device2 = Origin::signed(2);
        let mask = [1u8; 32];
        assert_ok!(IdentityModule::create_account(device1.clone(), mask));

        assert!(IdentityModule::set_device_mask(device2.clone(), mask, 0).is_err());
        assert_ok!(IdentityModule::add_device(device1.clone(), 2));
        assert!(IdentityModule::set_device_mask(device2.clone(), mask, 1).is_err());
        assert_ok!(IdentityModule::set_device_mask(device2.clone(), mask, 0));

        assert!(IdentityModule::change_password(device2.clone(), mask, 0).is_err());
        assert_ok!(IdentityModule::change_password(device2, mask, 1));

        assert_ok!(IdentityModule::set_device_mask(device1, mask, 1));
    });
}
