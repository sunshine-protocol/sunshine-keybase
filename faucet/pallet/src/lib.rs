//! Faucet module.
#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::decl_module;
use frame_support::dispatch::DispatchResult;
use frame_support::traits::Currency;
use frame_system::{ensure_none, Trait as System};
use pallet_balances::{self as balances, Trait as Balances};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

/// The pallet's configuration trait.
pub trait Trait: Balances {
    const MINT_UNIT: Self::Balance;
}

decl_module! {
    /// The module declaration.
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        /// Mint balance into an account.
        #[weight = 0]
        pub fn mint(origin, key: <T as System>::AccountId) -> DispatchResult {
            let _ = ensure_none(origin)?;
            let imbalance = <balances::Module<T> as Currency<<T as System>::AccountId>>::deposit_creating(&key, T::MINT_UNIT);
            drop(imbalance);
            Ok(())
        }
    }
}
