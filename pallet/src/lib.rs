//! Identity module.
#![cfg_attr(not(feature = "std"), no_std)]

use codec::FullCodec;
use frame_support::dispatch::DispatchResult;
use frame_support::traits::StoredMap;
use frame_support::{decl_error, decl_event, decl_module, decl_storage, ensure, Parameter};
use frame_system::{self as system, ensure_signed, Trait as System};
use sp_runtime::traits::{CheckedAdd, Member};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

/// The pallet's configuration trait.
pub trait Trait: System {
    /// Uid type.
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

        pub Device get(fn device): map
            hasher(blake2_128_concat) <T as System>::AccountId
            => Option<T::Uid>;

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
        DeviceAdded(Uid, AccountId),
        DeviceRemoved(Uid, AccountId),
        IdentityChanged(Uid, Cid),
        PasswordChanged(Uid, Gen, Mask),
    }
);

decl_error! {
    pub enum Error for Module<T: Trait> {
        /// No account.
        NoAccount,
        /// Failed to create account.
        CantCreateAccount,
        /// Failed to add device.
        CantAddDevice,
        /// Failed to remove device.
        CantRemoveDevice,
        /// Failed to set device mask.
        CantSetDeviceMask,
        /// Failed to change password.
        CantChangePassword,
        /// Failed to set identity.
        CantSetIdentity,
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
        pub fn create_account_for(origin, device: <T as System>::AccountId) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            ensure!(<Device<T>>::get(&device).is_none(), Error::<T>::CantCreateAccount);

            let uid = Self::create_account(&device)?;
            Self::deposit_event(RawEvent::AccountCreated(uid));
            Self::deposit_event(RawEvent::DeviceAdded(uid, device));

            Ok(())
        }

        /// Add a device.
        #[weight = 0]
        pub fn add_device(origin, device: <T as System>::AccountId) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let uid = <Device<T>>::get(&who).ok_or(Error::<T>::NoAccount)?;
            ensure!(<Device<T>>::get(&device).is_none(), Error::<T>::CantAddDevice);

            <Device<T>>::insert(device.clone(), uid);
            Self::deposit_event(RawEvent::DeviceAdded(uid, device));
            Ok(())
        }

        /// Remove a device.
        #[weight = 0]
        pub fn remove_device(origin, device: <T as System>::AccountId) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let uid = <Device<T>>::get(&who).ok_or(Error::<T>::NoAccount)?;
            ensure!(who != device, Error::<T>::CantRemoveDevice);
            ensure!(<Device<T>>::get(&device) == Some(uid), Error::<T>::CantRemoveDevice);

            <Device<T>>::remove(&device);
            Self::deposit_event(RawEvent::DeviceRemoved(uid, device));
            Ok(())
        }

        /// Change password.
        #[weight = 0]
        pub fn change_password(origin, mask: T::Mask, gen: T::Gen) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let uid = <Device<T>>::get(&who).ok_or(Error::<T>::NoAccount)?;
            ensure!(
                gen == <PasswordGen<T>>::get(uid)
                    .checked_add(&1u8.into())
                    .ok_or(Error::<T>::CantChangePassword)?,
                Error::<T>::CantChangePassword
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
            let uid = <Device<T>>::get(&who).ok_or(Error::<T>::NoAccount)?;
            ensure!(<Identity<T>>::get(uid) == prev_cid, Error::<T>::CantSetIdentity);

            <Identity<T>>::insert(uid, new_cid.clone());
            Self::deposit_event(RawEvent::IdentityChanged(uid, new_cid));
            Ok(())
        }
    }
}

impl<T: Trait> Module<T> {
    fn create_account(device: &<T as System>::AccountId) -> Result<T::Uid, Error<T>> {
        let uid = <UidCounter<T>>::get();
        let next_uid = uid.checked_add(&1u8.into()).ok_or(Error::<T>::CantCreateAccount)?;
        let gen = T::Gen::from(0u8);
        <UidCounter<T>>::put(next_uid);
        <PasswordGen<T>>::insert(uid, gen);
        <Device<T>>::insert(device.clone(), uid);
        Ok(uid)
    }
}

impl<T: Trait> StoredMap<<T as System>::AccountId, <T as Trait>::AccountData> for Module<T> {
    fn get(k: &<T as System>::AccountId) -> <T as Trait>::AccountData {
        if let Some(uid) = <Device<T>>::get(k) {
            <Account<T>>::get(&uid)
        } else {
            <T as Trait>::AccountData::default()
        }
    }

    fn is_explicit(k: &<T as System>::AccountId) -> bool {
        <Device<T>>::get(k).is_some()
    }

    fn mutate<R>(
        k: &<T as System>::AccountId,
        f: impl FnOnce(&mut <T as Trait>::AccountData) -> R,
    ) -> R {
        if <Device<T>>::get(k).is_none() {
            Self::create_account(k).ok();
        }
        if let Some(uid) = <Device<T>>::get(k) {
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
        if <Device<T>>::get(k).is_none() {
            Self::create_account(k).ok();
        }
        if let Some(uid) = <Device<T>>::get(k) {
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
        if <Device<T>>::get(k).is_none() {
            Self::create_account(k).ok();
        }
        if let Some(uid) = <Device<T>>::get(k) {
            <Account<T>>::try_mutate_exists(&uid, f)
        } else {
            // This should only happen if uid overflows.
            f(&mut None)
        }
    }

    fn remove(k: &<T as System>::AccountId) {
        if let Some(uid) = <Device<T>>::get(k) {
            <Account<T>>::remove(&uid);
        }
    }
}
