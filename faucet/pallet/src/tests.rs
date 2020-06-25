use crate::mock::*;
use frame_support::assert_ok;
use frame_support::traits::StoredMap;

#[test]
fn mint() {
    new_test_ext().execute_with(|| {
        let total_issuance = BalancesModule::total_issuance();
        let free_balance = AccountStore::get(&1).free;
        assert_ok!(FaucetModule::mint(Origin::from(None), 1));
        assert_eq!(BalancesModule::total_issuance(), total_issuance + MINT_UNIT);
        assert_eq!(AccountStore::get(&1).free, free_balance + MINT_UNIT);
    });
}
