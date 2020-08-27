//! Chain module.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

use frame_support::dispatch::DispatchResult;
use frame_support::{decl_error, decl_event, decl_module, decl_storage, Parameter};
use frame_system::{ensure_signed, Trait as System};
use orml_utilities::OrderedSet;
use parity_scale_codec::Encode;
use sp_core::Hasher;
use sp_runtime::traits::{CheckedAdd, Member};
use sp_std::prelude::*;
use sp_trie::Layout;

/// The pallet's configuration trait.
pub trait Trait: System {
    /// Chain ID type.
    type ChainId: Parameter + Member + Copy + Default + CheckedAdd + From<u8>;

    /// Block number type.
    type Number: Parameter + Member + Copy + Default + CheckedAdd + From<u8> + Encode + Ord;

    /// Trie hasher.
    type TrieHasher: Hasher<Out = Self::TrieHash>;

    /// Trie hash.
    type TrieHash: Parameter
        + Member
        + AsRef<[u8]>
        + AsMut<[u8]>
        + Eq
        + Default
        + Copy
        + core::hash::Hash;

    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as System>::Event>;
}

decl_storage! {
    trait Store for Module<T: Trait> as ChainModule {
        ChainIdCounter: T::ChainId;

        pub Authorities get(fn authorities): map
            hasher(blake2_128_concat) T::ChainId
            => OrderedSet<<T as System>::AccountId>;

        pub ChainRoot get(fn chain_head): map
            hasher(blake2_128_concat) T::ChainId
            => Option<T::TrieHash>;

        pub ChainHeight get(fn block_number): map
            hasher(blake2_128_concat) T::ChainId
            => <T as Trait>::Number;
    }
}

decl_event! {
    pub enum Event<T>
    where
        AccountId = <T as System>::AccountId,
        Number = <T as Trait>::Number,
        ChainId = <T as Trait>::ChainId,
        TrieHash = <T as Trait>::TrieHash,
    {
        NewChain(ChainId),
        NewBlock(ChainId, Number, AccountId, TrieHash),
        AuthorityAdded(ChainId, Number, AccountId, AccountId),
        AuthorityRemoved(ChainId, Number, AccountId, AccountId),
    }
}

decl_error! {
    pub enum Error for Module<T: Trait> {
        /// Unauthorized to create a block for the chain.
        Unauthorized,
        /// Invalid proof occurs when the block number or
        /// the previous block don't match what's on chain.
        /// This can occur due to a race condition, and the
        /// user needs to resubmit with updated fields.
        InvalidProof,
        /// ChainId overflow.
        ChainIdOverflow,
        /// Block number overflow.
        BlockNumberOverflow,
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        type Error = Error<T>;

        fn deposit_event() = default;

        /// Create a new chain.
        #[weight = 0]
        pub fn create_chain(origin) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let chain_id = <ChainIdCounter<T>>::get();
            let next_chain_id = chain_id
                .checked_add(&1u8.into())
                .ok_or(Error::<T>::ChainIdOverflow)?;
            <ChainIdCounter<T>>::put(next_chain_id);
            Self::deposit_event(RawEvent::NewChain(chain_id));
            Self::add_authority_to_chain(chain_id, who.clone(), who);
            Ok(())
        }

        /// Add an authority.
        #[weight = 0]
        pub fn add_authority(
            origin,
            chain_id: T::ChainId,
            authority: <T as System>::AccountId,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::ensure_authorized(chain_id, &who)?;
            Self::add_authority_to_chain(chain_id, who, authority);
            Ok(())
        }

        /// Remove an authority.
        #[weight = 0]
        pub fn remove_authority(origin, chain_id: T::ChainId, authority: <T as System>::AccountId) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::ensure_authorized(chain_id, &who)?;
            Self::remove_authority_from_chain(chain_id, who, authority);
            Ok(())
        }

        /// Author block.
        #[weight = 0]
        pub fn author_block(
            origin,
            chain_id: T::ChainId,
            root: T::TrieHash,
            proof: Vec<Vec<u8>>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::ensure_authorized(chain_id, &who)?;
            let ancestor = <ChainRoot<T>>::get(chain_id);
            let number = <ChainHeight<T>>::get(chain_id);
            let height = number.checked_add(&1u8.into())
                .ok_or(Error::<T>::BlockNumberOverflow)?;
            sp_trie::verify_trie_proof::<Layout<T::TrieHasher>, _, _, _>(
                &root,
                &proof,
                &[
                    (&b"number"[..], Some(number.encode())),
                    (&b"ancestor"[..], Some(ancestor.encode())),
                ],
            ).map_err(|_| Error::<T>::InvalidProof)?;
            <ChainRoot<T>>::insert(chain_id, root);
            <ChainHeight<T>>::insert(chain_id, height);
            Self::deposit_event(RawEvent::NewBlock(chain_id, number, who, root));
            Ok(())
        }
    }
}

impl<T: Trait> Module<T> {
    fn height(chain_id: T::ChainId) -> T::Number {
        <ChainHeight<T>>::get(chain_id)
    }

    fn is_authority(chain_id: T::ChainId, who: &<T as System>::AccountId) -> bool {
        <Authorities<T>>::get(chain_id).contains(who)
    }

    fn ensure_authorized(
        chain_id: T::ChainId,
        who: &<T as System>::AccountId,
    ) -> Result<(), Error<T>> {
        if Self::is_authority(chain_id, who) {
            Ok(())
        } else {
            Err(Error::<T>::Unauthorized)
        }
    }

    fn add_authority_to_chain(
        chain_id: T::ChainId,
        who: <T as System>::AccountId,
        authority: <T as System>::AccountId,
    ) {
        if !Self::is_authority(chain_id, &authority) {
            <Authorities<T>>::mutate(chain_id, |authorities| {
                authorities.insert(authority.clone())
            });
            let number = Self::height(chain_id);
            Self::deposit_event(RawEvent::AuthorityAdded(chain_id, number, who, authority));
        }
    }

    fn remove_authority_from_chain(
        chain_id: T::ChainId,
        who: <T as System>::AccountId,
        authority: <T as System>::AccountId,
    ) {
        if Self::is_authority(chain_id, &authority) {
            <Authorities<T>>::mutate(chain_id, |authorities| authorities.remove(&authority));
            let number = Self::height(chain_id);
            Self::deposit_event(RawEvent::AuthorityRemoved(chain_id, number, who, authority));
        }
    }
}
