//! Identity module.
#![cfg_attr(not(feature = "std"), no_std)]

use codec::FullCodec;
use frame_support::dispatch::DispatchResult;
use frame_support::traits::StoredMap;
use frame_support::{decl_error, decl_event, decl_module, decl_storage, ensure, Parameter};
use frame_system::{ensure_signed, Trait as System};
use orml_utilities::OrderedSet;
use sp_runtime::traits::{CheckedAdd, Member};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

/// The pallet's configuration trait.
pub trait Trait: System {
    /// User ID type.
    type Uid: Parameter + Member + Copy + Default + CheckedAdd + From<u8>;

    /// Cid type.
    type Cid: Parameter + Member;

    /// Mask type.
    type Mask: Parameter + Member;

    /// Generation type.
    type Gen: Parameter + Member + Copy + Default + CheckedAdd + From<u8> + Ord;

    /// Data to be associated with an account.
    type AccountData: Member + FullCodec + Clone + Default;

    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as System>::Event>;
}

decl_storage! {
    trait Store for Module<T: Trait> as IdentityModule {
        UidCounter: T::Uid;

        pub UidLookup get(fn key): map
            hasher(blake2_128_concat) <T as System>::AccountId
            => Option<T::Uid>;

        pub Keys get(fn keys): map
            hasher(blake2_128_concat) T::Uid
            => OrderedSet<<T as System>::AccountId>;

        pub Identity get(fn identity): map
            hasher(blake2_128_concat) T::Uid
            => Option<T::Cid>;

        pub PasswordGen get(fn gen): map
            hasher(blake2_128_concat) T::Uid
            => T::Gen;

        pub PasswordMask get(fn mask): double_map
            hasher(blake2_128_concat) T::Uid,
            hasher(blake2_128_concat) T::Gen
            => Option<T::Mask>;

        pub Account get(fn account): map
            hasher(blake2_128_concat) T::Uid
            => <T as Trait>::AccountData;
    }
}

decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as System>::AccountId,
        Uid = <T as Trait>::Uid,
        Cid = <T as Trait>::Cid,
        Mask = <T as Trait>::Mask,
        Gen = <T as Trait>::Gen,
    {
        AccountCreated(Uid),
        KeyAdded(Uid, AccountId),
        KeyRemoved(Uid, AccountId),
        IdentityChanged(Uid, Cid),
        PasswordChanged(Uid, Gen, Mask),
    }
);

decl_error! {
    pub enum Error for Module<T: Trait> {
        /// No account.
        NoAccount,
        /// Uid overflow.
        UidOverflow,
        /// Key in use.
        KeyInUse,
        /// Unauthorized to remove key.
        Unauthorized,
        /// Cant remove self.
        CantRemoveSelf,
        /// Prev cid missmatch.
        PrevCidMissmatch,
        /// Password gen overflow.
        PasswordGenOverflow,
        /// Password gen missmatch.
        PasswordGenMissmatch,
    }
}

decl_module! {
    /// The module declaration.
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        // Initialize errors.
        type Error = Error<T>;

        // Initialize events.
        fn deposit_event() = default;

        /// Create account.
        #[weight = 0]
        pub fn create_account_for(origin, key: <T as System>::AccountId) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            Self::ensure_key_unused(&key)?;

            Self::create_account(key)?;
            Ok(())
        }

        /// Add a key.
        #[weight = 0]
        pub fn add_key(origin, key: <T as System>::AccountId) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let uid = Self::ensure_uid(&who)?;
            Self::ensure_key_unused(&key)?;

            Self::add_key_to_uid(uid, key);
            Ok(())
        }

        /// Remove a key.
        #[weight = 0]
        pub fn remove_key(origin, key: <T as System>::AccountId) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let uid = Self::ensure_uid(&who)?;
            // Prevent user from locking himself out.
            ensure!(who != key, Error::<T>::CantRemoveSelf);
            ensure!(<UidLookup<T>>::get(&key) == Some(uid), Error::<T>::Unauthorized);

            Self::remove_key_from_uid(uid, key);
            Ok(())
        }

        /// Change password.
        #[weight = 0]
        pub fn change_password(origin, mask: T::Mask, gen: T::Gen) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let uid = Self::ensure_uid(&who)?;
            ensure!(
                gen == <PasswordGen<T>>::get(uid)
                    .checked_add(&1u8.into())
                    .ok_or(Error::<T>::PasswordGenOverflow)?,
                Error::<T>::PasswordGenMissmatch
            );

            <PasswordGen<T>>::insert(uid, gen);
            <PasswordMask<T>>::insert(uid, gen, mask.clone());
            Self::deposit_event(RawEvent::PasswordChanged(uid, gen, mask));
            Ok(())
        }

        /// Set the identity.
        #[weight = 0]
        pub fn set_identity(origin, prev_cid: Option<T::Cid>, new_cid: T::Cid) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let uid = Self::ensure_uid(&who)?;
            ensure!(<Identity<T>>::get(uid) == prev_cid, Error::<T>::PrevCidMissmatch);

            <Identity<T>>::insert(uid, new_cid.clone());
            Self::deposit_event(RawEvent::IdentityChanged(uid, new_cid));
            Ok(())
        }
    }
}

impl<T: Trait> Module<T> {
    fn ensure_uid(key: &<T as System>::AccountId) -> Result<T::Uid, Error<T>> {
        let uid = <UidLookup<T>>::get(&key).ok_or(Error::<T>::NoAccount)?;
        if !<Keys<T>>::get(uid).contains(key) {
            return Err(Error::<T>::Unauthorized);
        }
        Ok(uid)
    }

    fn ensure_key_unused(key: &<T as System>::AccountId) -> Result<(), Error<T>> {
        if <UidLookup<T>>::get(&key).is_some() {
            Err(Error::<T>::KeyInUse)
        } else {
            Ok(())
        }
    }

    fn create_account(key: <T as System>::AccountId) -> Result<T::Uid, Error<T>> {
        let uid = <UidCounter<T>>::get();
        let next_uid = uid
            .checked_add(&1u8.into())
            .ok_or(Error::<T>::UidOverflow)?;
        let gen = T::Gen::from(0u8);
        <UidCounter<T>>::put(next_uid);
        <PasswordGen<T>>::insert(uid, gen);
        Self::deposit_event(RawEvent::AccountCreated(uid));
        Self::add_key_to_uid(uid, key);
        Ok(uid)
    }

    fn add_key_to_uid(uid: T::Uid, key: <T as System>::AccountId) {
        <UidLookup<T>>::insert(key.clone(), uid);
        <Keys<T>>::mutate(uid, |keys| keys.insert(key.clone()));
        Self::deposit_event(RawEvent::KeyAdded(uid, key));
    }

    fn remove_key_from_uid(uid: T::Uid, key: <T as System>::AccountId) {
        // The lookup can't be removed in case someone sends a transaction
        // to an old key or the same key being added to a different account
        // after being revoked.
        <Keys<T>>::mutate(uid, |keys| keys.remove(&key));
        Self::deposit_event(RawEvent::KeyRemoved(uid, key));
    }
}

impl<T: Trait> StoredMap<<T as System>::AccountId, <T as Trait>::AccountData> for Module<T> {
    fn get(k: &<T as System>::AccountId) -> <T as Trait>::AccountData {
        if let Some(uid) = <UidLookup<T>>::get(k) {
            <Account<T>>::get(&uid)
        } else {
            <T as Trait>::AccountData::default()
        }
    }

    fn is_explicit(k: &<T as System>::AccountId) -> bool {
        <UidLookup<T>>::get(k).is_some()
    }

    fn mutate<R>(
        k: &<T as System>::AccountId,
        f: impl FnOnce(&mut <T as Trait>::AccountData) -> R,
    ) -> R {
        if <UidLookup<T>>::get(k).is_none() {
            Self::create_account(k.clone()).ok();
        }
        if let Some(uid) = <UidLookup<T>>::get(k) {
            <Account<T>>::mutate(&uid, f)
        } else {
            // This should only happen if uid overflows.
            f(&mut <T as Trait>::AccountData::default())
        }
    }

    fn mutate_exists<R>(
        k: &<T as System>::AccountId,
        f: impl FnOnce(&mut Option<<T as Trait>::AccountData>) -> R,
    ) -> R {
        if <UidLookup<T>>::get(k).is_none() {
            Self::create_account(k.clone()).ok();
        }
        if let Some(uid) = <UidLookup<T>>::get(k) {
            <Account<T>>::mutate_exists(&uid, f)
        } else {
            // This should only happen if uid overflows.
            f(&mut None)
        }
    }

    fn try_mutate_exists<R, E>(
        k: &<T as System>::AccountId,
        f: impl FnOnce(&mut Option<<T as Trait>::AccountData>) -> Result<R, E>,
    ) -> Result<R, E> {
        if <UidLookup<T>>::get(k).is_none() {
            Self::create_account(k.clone()).ok();
        }
        if let Some(uid) = <UidLookup<T>>::get(k) {
            <Account<T>>::try_mutate_exists(&uid, f)
        } else {
            // This should only happen if uid overflows.
            f(&mut None)
        }
    }

    fn remove(k: &<T as System>::AccountId) {
        if let Some(uid) = <UidLookup<T>>::get(k) {
            <Account<T>>::remove(&uid);
        }
    }
}
