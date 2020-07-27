//! Faucet module.
#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::dispatch::DispatchResult;
use frame_support::traits::Currency;
use frame_support::unsigned::{TransactionSource, TransactionValidity, ValidateUnsigned};
use frame_support::{decl_event, decl_module};
use frame_system::{self as system, ensure_none, Trait as System};
use pallet_balances::{self as balances, Trait as Balances};
use sp_runtime::transaction_validity::ValidTransaction;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

/// The pallet's configuration trait.
pub trait Trait: Balances {
    const MINT_UNIT: Self::Balance;
    type Event: From<Event<Self>> + Into<<Self as System>::Event>;
}

decl_module! {
    /// The module declaration.
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        // Initialize events.
        fn deposit_event() = default;

        /// Mint balance into an account.
        #[weight = 0]
        pub fn mint(origin, key: <T as System>::AccountId) -> DispatchResult {
            let _ = ensure_none(origin)?;
            let imbalance = <balances::Module<T> as Currency<<T as System>::AccountId>>::deposit_creating(&key, T::MINT_UNIT);
            drop(imbalance);
            Self::deposit_event(RawEvent::Minted(key, T::MINT_UNIT));
            Ok(())
        }
    }
}

decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as System>::AccountId,
        Balance = <T as Balances>::Balance,
    {
        Minted(AccountId, Balance),
    }
);

impl<T: Trait> ValidateUnsigned for Module<T> {
    type Call = Call<T>;

    fn validate_unsigned(_source: TransactionSource, _call: &Self::Call) -> TransactionValidity {
        let current_block = <system::Module<T>>::block_number();
        ValidTransaction::with_tag_prefix("Faucet")
            .and_provides(current_block)
            .build()
    }
}
