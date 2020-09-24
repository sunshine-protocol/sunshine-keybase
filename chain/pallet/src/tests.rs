use crate::mock::*;
use frame_support::assert_ok;
use sunshine_client_utils::codec::trie::TreeEncode;
use sunshine_client_utils::GenericBlock;

type Block = GenericBlock<(), u64, sunshine_client_utils::codec::hasher::TreeHasherBlake2b256>;

#[test]
fn test_block_authoring() {
    new_test_ext().execute_with(|| {
        let key = Origin::signed(1);
        assert_ok!(ChainModule::create_chain(key.clone()));
        let chain_id = 0;

        let block = Block {
            number: 0,
            ancestor: None,
            payload: (),
        }
        .seal()
        .unwrap();
        assert_ok!(ChainModule::author_block(
            key.clone(),
            chain_id,
            *block.offchain.root(),
            block.proof
        ));

        let block = Block {
            number: 1,
            ancestor: Some(*block.offchain.root()),
            payload: (),
        }
        .seal()
        .unwrap();
        assert_ok!(ChainModule::author_block(
            key.clone(),
            chain_id,
            *block.offchain.root(),
            block.proof.clone(),
        ));

        assert!(
            ChainModule::author_block(key, chain_id, *block.offchain.root(), block.proof).is_err()
        );
    });
}
