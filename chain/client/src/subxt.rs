use frame_support::Parameter;
use parity_scale_codec::{Decode, Encode};
use sp_core::H256;
use sp_runtime::traits::{CheckedAdd, Member};
use std::marker::PhantomData;
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt::{module, Call, Event, Store};
use substrate_subxt::{sp_core, sp_runtime};

#[module]
pub trait Chain: System {
    /// Chain ID type.
    type ChainId: Parameter + Member + Copy + Default + CheckedAdd + From<u8>;

    /// Block number type.
    type Number: Parameter + Member + Copy + Default + CheckedAdd + From<u8> + Encode;
}

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct AuthoritiesStore<T: Chain> {
    #[store(returns = Vec<<T as System>::AccountId>)]
    pub chain_id: T::ChainId,
}

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct ChainRootStore<T: Chain> {
    #[store(returns = Option<H256>)]
    pub chain_id: T::ChainId,
}

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct ChainNumberStore<T: Chain> {
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
    pub root: H256,
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
    pub root: H256,
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
