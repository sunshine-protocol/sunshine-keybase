use frame_support::Parameter;
use parity_scale_codec::{Decode, Encode};
use sp_core::Hasher;
use sp_runtime::traits::{CheckedAdd, CheckedSub, Member};
use std::marker::PhantomData;
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt::{module, Call, Event, Store};
use substrate_subxt::{sp_core, sp_runtime};
use sunshine_client_utils::codec::Cid;

#[module]
pub trait Chain: System {
    /// Chain ID type.
    type ChainId: Parameter + Member + Copy + Default + CheckedAdd + From<u8> + Into<u64>;

    /// Trie hasher.
    #[module(ignore)]
    type TrieHasher: Hasher<Out = Self::TrieHash>;

    /// Trie hash.
    type TrieHash: Parameter
        + Member
        + AsRef<[u8]>
        + AsMut<[u8]>
        + Eq
        + Default
        + Copy
        + core::hash::Hash
        + Into<Cid>;

    /// Block number type.
    type Number: Parameter
        + Member
        + Copy
        + Default
        + CheckedAdd
        + CheckedSub
        + From<u8>
        + Encode
        + Ord
        + Into<u64>;
}

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct AuthoritiesStore<T: Chain> {
    #[store(returns = Vec<<T as System>::AccountId>)]
    pub chain_id: T::ChainId,
}

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct ChainRootStore<T: Chain> {
    #[store(returns = Option<T::TrieHash>)]
    pub chain_id: T::ChainId,
}

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct ChainHeightStore<T: Chain> {
    #[store(returns = T::Number)]
    pub chain_id: T::ChainId,
}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct CreateChainCall<T: Chain> {
    pub _runtime: PhantomData<T>,
}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct AddAuthorityCall<'a, T: Chain> {
    pub chain_id: T::ChainId,
    pub authority: &'a <T as System>::AccountId,
}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct RemoveAuthorityCall<'a, T: Chain> {
    pub chain_id: T::ChainId,
    pub authority: &'a <T as System>::AccountId,
}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct AuthorBlockCall<'a, T: Chain> {
    pub chain_id: T::ChainId,
    pub root: T::TrieHash,
    pub proof: &'a [Vec<u8>],
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct NewChainEvent<T: Chain> {
    pub chain_id: T::ChainId,
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct NewBlockEvent<T: Chain> {
    pub chain_id: T::ChainId,
    pub number: T::Number,
    pub who: <T as System>::AccountId,
    pub root: T::TrieHash,
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct AuthorityAddedEvent<T: Chain> {
    pub chain_id: T::ChainId,
    pub number: T::Number,
    pub who: <T as System>::AccountId,
    pub authority: <T as System>::AccountId,
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct AuthorityRemovedEvent<T: Chain> {
    pub chain_id: T::ChainId,
    pub number: T::Number,
    pub who: <T as System>::AccountId,
    pub authority: <T as System>::AccountId,
}
