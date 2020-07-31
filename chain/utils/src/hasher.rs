use crate::H256;
use hash256_std_hasher::Hash256StdHasher;
use hash_db::Hasher;

#[derive(Debug)]
pub struct Blake2Hasher;

impl Hasher for Blake2Hasher {
    type Out = H256;
    type StdHasher = Hash256StdHasher;
    const LENGTH: usize = 32;

    fn hash(data: &[u8]) -> Self::Out {
        let mut hash = [0; 32];
        hash.copy_from_slice(blake2_rfc::blake2b::blake2b(32, &[], data).as_bytes());
        hash.into()
    }
}
