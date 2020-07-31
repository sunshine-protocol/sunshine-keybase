use crate::{Layout, VerifyError, H256};
use parity_scale_codec::{Decode, Encode};
use sp_trie::{MemoryDB, TrieConfiguration, TrieDBMut, TrieError, TrieMut};
use std::collections::BTreeMap;
use thiserror::Error;

/// An immutable OffchainBlock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OffchainBlock {
    /// Tree data of the block.
    pub tree: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Root hash.
    pub root: H256,
}

impl OffchainBlock {
    pub fn encode(&self) -> (&H256, Vec<u8>) {
        (&self.root, self.tree.encode())
    }

    pub fn decode(expected: &H256, mut bytes: &[u8]) -> Result<Self, Error> {
        let tree = Decode::decode(&mut bytes)?;
        let root = Layout::trie_root(&tree);
        if root != *expected {
            return Err(Error::RootMissmatch);
        }
        Ok(Self { tree, root })
    }

    pub fn get<K: Encode + ?Sized, V: Decode>(&self, k: &K) -> Result<V, Error> {
        let bytes = k
            .using_encoded(|key| self.tree.get(key))
            .ok_or(Error::MissingKey)?;
        Ok(V::decode(&mut &bytes[..])?)
    }
}

/// An immutable sealed block suitable for insertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedBlock {
    /// Offchain block to publish on ipfs.
    pub offchain: OffchainBlock,
    /// Proof that the key value pairs the chain needs to know
    /// about are contained in the OffchainBlock.
    pub proof: Vec<Vec<u8>>,
    /// List of key value pairs the chain needs to know about.
    pub proof_data: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

impl SealedBlock {
    pub fn verify_proof(&self) -> Result<(), VerifyError> {
        sp_trie::verify_trie_proof::<Layout, _, _, _>(
            &self.offchain.root,
            &self.proof,
            &self.proof_data,
        )
    }
}

#[derive(Default)]
pub struct BlockBuilder(BTreeMap<Vec<u8>, (Option<Vec<u8>>, bool)>);

impl BlockBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn insert<K: Encode + ?Sized, V: Encode + ?Sized>(&mut self, k: &K, v: &V, proof: bool) {
        self.0.insert(k.encode(), (Some(v.encode()), proof));
    }

    pub fn seal(self) -> Result<SealedBlock, Error> {
        let mut db = MemoryDB::default();
        let mut root = H256::default();
        let mut trie = TrieDBMut::<Layout>::new(&mut db, &mut root);
        let mut tree = BTreeMap::new();
        let mut proof_data = Vec::with_capacity(self.0.len());
        for (k, (v, p)) in self.0.into_iter() {
            if p {
                proof_data.push((k.clone(), v.clone()));
            }
            if let Some(v) = v {
                trie.insert(&k, &v)?;
                tree.insert(k, v);
            }
        }
        drop(trie);

        let proof = sp_trie::generate_trie_proof::<Layout, _, _, _>(
            &db,
            root,
            proof_data.iter().map(|(k, _)| k),
        )?;

        Ok(SealedBlock {
            offchain: OffchainBlock { root, tree },
            proof,
            proof_data,
        })
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Decode(#[from] parity_scale_codec::Error),
    #[error("missing key")]
    MissingKey,
    #[error(transparent)]
    Trie(#[from] Box<TrieError<Layout>>),
    #[error("root missmatch")]
    RootMissmatch,
}

pub trait TreeEncode {
    fn encode_tree(&self, block: &mut BlockBuilder, prefix: &[u8], proof: bool);

    fn seal(&self) -> Result<SealedBlock, Error> {
        let mut block = BlockBuilder::new();
        self.encode_tree(&mut block, &[], false);
        block.seal()
    }
}

impl<T: Encode> TreeEncode for T {
    fn encode_tree(&self, block: &mut BlockBuilder, prefix: &[u8], proof: bool) {
        block.insert(prefix, self, proof);
    }
}

pub trait TreeDecode: Sized {
    fn decode_tree(block: &OffchainBlock, prefix: &[u8]) -> Result<Self, Error>;

    fn decode(block: &OffchainBlock) -> Result<Self, Error> {
        Self::decode_tree(block, &[])
    }
}

impl<T: Decode> TreeDecode for T {
    fn decode_tree(block: &OffchainBlock, prefix: &[u8]) -> Result<Self, Error> {
        block.get(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyChain, KeyType, PrivateKey, PublicKey, SecretBox};

    #[derive(Debug, Eq, PartialEq)]
    struct User;
    impl KeyType for User {
        const KEY_TYPE: u8 = 0;
    }

    #[derive(Debug, Eq, PartialEq)]
    struct UserDevices;
    impl KeyType for UserDevices {
        const KEY_TYPE: u8 = 1;
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Block {
        //#[offchain(proof)]
        number: u32,
        //#[offchain(proof)]
        prev: Option<[u8; 32]>, // TODO Cid
        description: String,
        set_user_key: SetUserKey,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct SetUserKey {
        public_key: PublicKey<User>,
        private_key: SecretBox<UserDevices, PrivateKey<User>>,
    }

    impl TreeEncode for SetUserKey {
        fn encode_tree(&self, block: &mut BlockBuilder, prefix: &[u8], proof: bool) {
            (prefix, b"public_key").using_encoded(|prefix| {
                self.public_key.encode_tree(block, prefix, proof);
            });
            (prefix, b"private_key").using_encoded(|prefix| {
                self.private_key.encode_tree(block, prefix, proof);
            });
        }
    }

    impl TreeEncode for Block {
        fn encode_tree(&self, block: &mut BlockBuilder, prefix: &[u8], proof: bool) {
            (prefix, b"number").using_encoded(|prefix| {
                self.number.encode_tree(block, prefix, true);
            });
            (prefix, b"prev").using_encoded(|prefix| {
                self.prev.encode_tree(block, prefix, true);
            });
            (prefix, b"description").using_encoded(|prefix| {
                self.description.encode_tree(block, prefix, proof);
            });
            (prefix, b"set_user_key").using_encoded(|prefix| {
                self.set_user_key.encode_tree(block, prefix, proof);
            });
        }
    }

    impl TreeDecode for SetUserKey {
        fn decode_tree(block: &OffchainBlock, prefix: &[u8]) -> Result<Self, Error> {
            Ok(Self {
                public_key: (prefix, b"public_key")
                    .using_encoded(|prefix| TreeDecode::decode_tree(block, prefix))?,
                private_key: (prefix, b"private_key")
                    .using_encoded(|prefix| TreeDecode::decode_tree(block, prefix))?,
            })
        }
    }

    impl TreeDecode for Block {
        fn decode_tree(block: &OffchainBlock, prefix: &[u8]) -> Result<Self, Error> {
            Ok(Self {
                number: (prefix, b"number")
                    .using_encoded(|prefix| TreeDecode::decode_tree(block, prefix))?,
                prev: (prefix, b"prev")
                    .using_encoded(|prefix| TreeDecode::decode_tree(block, prefix))?,
                description: (prefix, b"description")
                    .using_encoded(|prefix| TreeDecode::decode_tree(block, prefix))?,
                set_user_key: (prefix, b"set_user_key")
                    .using_encoded(|prefix| TreeDecode::decode_tree(block, prefix))?,
            })
        }
    }

    #[test]
    fn test_block() {
        let mut key_chain = KeyChain::new();
        key_chain.insert(PrivateKey::<UserDevices>::new());

        let private_key = PrivateKey::new();
        let public_key = PublicKey::from(&private_key);

        let block = Block {
            number: 0,
            prev: None,
            description: "the genesis block".into(),
            set_user_key: SetUserKey {
                public_key,
                private_key: SecretBox::encrypt(&key_chain, &private_key).unwrap(),
            },
        };
        let sealed_block = block.seal().unwrap();
        sealed_block.verify_proof().unwrap();

        let (root, bytes) = sealed_block.offchain.encode();
        let offchain_block = OffchainBlock::decode(&root, &bytes).unwrap();
        assert_eq!(sealed_block.offchain, offchain_block);

        let block2 = Block::decode(&offchain_block).unwrap();
        assert_eq!(block, block2);

        let private_key2 = block2.set_user_key.private_key.decrypt(&key_chain).unwrap();
        assert_eq!(private_key, private_key2);
    }

    #[test]
    fn test_trie() {
        let mut db = MemoryDB::default();
        let mut root = H256::default();
        let mut trie = TrieDBMut::<Layout>::new(&mut db, &mut root);
        trie.insert(b"prev", b"cid").unwrap();
        trie.insert(b"remove_device_key", b"0").unwrap();
        drop(trie);

        let proof = sp_trie::generate_trie_proof::<Layout, _, _, _>(
            &db,
            root.clone(),
            &[
                &b"prev"[..],
                &b"remove_device_key"[..],
                &b"add_device_key"[..],
            ],
        )
        .unwrap();

        sp_trie::verify_trie_proof::<Layout, _, _, _>(
            &root,
            &proof,
            &[
                (&b"prev"[..], Some(&b"cid"[..])),
                (&b"remove_device_key"[..], Some(&b"0"[..])),
                (&b"add_device_key"[..], None),
            ],
        )
        .unwrap();

        let res = sp_trie::verify_trie_proof::<Layout, _, _, _>(
            &root,
            &proof,
            &[
                (&b"prev"[..], Some(&b"wrong"[..])),
                (&b"remove_device_key"[..], Some(&b"0"[..])),
                (&b"add_device_key"[..], None),
            ],
        );
        assert!(res.is_err());
    }
}
