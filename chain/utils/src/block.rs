use crate::trie::{BlockBuilder, Error, OffchainBlock, TreeDecode, TreeEncode};
use parity_scale_codec::{Decode, Encode};
use sp_core::H256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenericBlock<T> {
    pub number: u64,
    pub ancestor: Option<H256>,
    pub payload: T,
}

impl<T: Encode> TreeEncode for GenericBlock<T> {
    fn encode_tree(&self, block: &mut BlockBuilder, _prefix: &[u8], _proof: bool) {
        block.insert(b"number", &self.number, true);
        block.insert(b"ancestor", &self.ancestor, true);
        block.insert(b"payload", &self.payload, false);
    }
}

impl<T: Decode> TreeDecode for GenericBlock<T> {
    fn decode_tree(block: &OffchainBlock, _prefix: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            number: block.get(b"number")?,
            ancestor: block.get(b"ancestor")?,
            payload: block.get(b"payload")?,
        })
    }
}
