use crate::mock::*;
use frame_support::assert_ok;
use sunshine_chain_utils::block::GenericBlock;
use sunshine_chain_utils::trie::TreeEncode;

type Block = GenericBlock<()>;

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
            block.offchain.root.clone(),
            block.proof
        ));

        let block = Block {
            number: 1,
            ancestor: Some(block.offchain.root),
            payload: (),
        }
        .seal()
        .unwrap();
        assert_ok!(ChainModule::author_block(
            key.clone(),
            chain_id,
            block.offchain.root.clone(),
            block.proof.clone(),
        ));

        assert!(
            ChainModule::author_block(key, chain_id, block.offchain.root.clone(), block.proof)
                .is_err()
        );
    });
}
