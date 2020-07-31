#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
pub mod block;
#[cfg(feature = "std")]
pub mod crypto;
pub mod hasher;
#[cfg(feature = "std")]
pub mod trie;

pub use sp_core::H256;
use sp_std::prelude::*;

pub type Layout = sp_trie::Layout<crate::hasher::Blake2Hasher>;
pub type VerifyError = sp_trie::VerifyError<H256, sp_trie::Error>;

pub fn verify_trie_proof<'a, I, K, V>(
    root: &H256,
    proof: &[Vec<u8>],
    items: I,
) -> Result<(), VerifyError>
where
    I: IntoIterator<Item = &'a (K, Option<V>)>,
    K: 'a + AsRef<[u8]>,
    V: 'a + AsRef<[u8]>,
{
    sp_trie::verify_trie_proof::<Layout, I, K, V>(&root, proof, items)
}
