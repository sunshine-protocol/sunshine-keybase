//! Identity module.
#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{decl_error, decl_event, decl_module, decl_storage, dispatch, Parameter};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::Member;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

/// The pallet's configuration trait.
pub trait Trait: system::Trait {
    /// Cid type.
    type Cid: Parameter + Member;

    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_storage! {
    trait Store for Module<T: Trait> as IdentityModule {
        pub Identity get(fn identity):
            map hasher(blake2_128_concat) <T as system::Trait>::AccountId => Option<T::Cid>;
    }
}

decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as system::Trait>::AccountId,
        Cid = <T as Trait>::Cid,
    {
        IdentityUpdated(AccountId, Cid),
    }
);

decl_error! {
    pub enum Error for Module<T: Trait> {
        /// Proof needs to be provided that the parent of the new identity
        /// cid is the old identity cid.
        InvalidProof
    }
}

decl_module! {
    /// The module declaration.
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        // Initializing errors
        type Error = Error<T>;

        // Initializing events
        fn deposit_event() = default;

        /// Sets the identity.
        #[weight = 0]
        pub fn set_identity(origin, cid: T::Cid) -> dispatch::DispatchResult {
            let who = ensure_signed(origin)?;
            // TODO: require a proof that the parent of cid is the current cid.
            <Identity<T>>::insert(who.clone(), cid.clone());
            Self::deposit_event(RawEvent::IdentityUpdated(who, cid));
            Ok(())
        }
    }
}
