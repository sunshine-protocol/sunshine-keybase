//! Split module for delegating and managing secret sharing
#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::dispatch::DispatchResult;
use frame_support::{decl_error, decl_event, decl_module, decl_storage, ensure, Parameter};
use frame_system::{ensure_signed, Trait as System};
use orml_utilities::OrderedSet;
use parity_scale_codec::{Decode, Encode};
use sp_core::Hasher;
use sp_runtime::traits::{CheckedAdd, Member};
use sp_std::prelude::*;

#[cfg(test)]
mod tests;

#[derive(Encode, Decode, sp_runtime::RuntimeDebug)]
/// Membership info for each group
pub struct Group<Id, AccountId> {
    pub id: Id,
    pub acc: AccountId,
    pub set: OrderedSet<AccountId>,
}
pub type Gov<T> = Group<<T as Trait>::SecretId, <T as System>::AccountId>;

#[derive(Encode, Decode, sp_runtime::RuntimeDebug)]
pub struct Commit<Hash> {
    pub hash: Hash,
    pub proven: Option<bool>,
}
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, sp_runtime::RuntimeDebug)]
pub struct Threshold {
    // Some(true) proofs submitted count
    pub yes_ct: u8,
    // Some(false) proofs submitted count
    pub no_ct: u8,
    // Threshold required
    pub req: u8,
    // Fault tolerance (required no_ct to trigger explicit fault)
    pub tol: u8,
    // Total
    pub all: u8,
}
impl Threshold {
    pub fn new(req: u8, tol: u8, all: u8) -> Self {
        core::debug_assert!(req <= all && tol <= all);
        Threshold {
            yes_ct: 0u8,
            no_ct: 0u8,
            req,
            tol,
            all,
        }
    }
}

#[derive(Encode, Decode, sp_runtime::RuntimeDebug)]
/// Recovery State
/// - score contains the threshold state
/// - state contains all commits by the dealer + the state of preimage proofs from secret share holders
pub struct RecoverySt<Id, Hash> {
    pub id: Id,
    pub score: Threshold,
    pub state: Vec<Commit<Hash>>,
}
pub type RecSt<T> =
    RecoverySt<(<T as Trait>::SecretId, <T as Trait>::RoundId), <T as System>::Hash>;

/// The pallet's configuration trait.
pub trait Trait: System {
    /// Secret group unique identifier
    type SecretId: Parameter + Member + Copy + Default + CheckedAdd + From<u8>;

    /// Round identifier
    type RoundId: Parameter + Member + Copy + Default + CheckedAdd + From<u8> + Encode + Ord;

    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as System>::Event>;
}

decl_event! {
    pub enum Event<T>
    where
        AccountId = <T as System>::AccountId,
        SecretId = <T as Trait>::SecretId,
        RoundId = <T as Trait>::RoundId,
    {
        // _, _, total members
        NewGroup(AccountId, SecretId, u8),
        SplitSecret(SecretId, RoundId, Threshold),
        MemberRemoved(SecretId, AccountId),
        MemberAdded(SecretId, AccountId),
        ValidPreImage(SecretId, RoundId, AccountId, Threshold),
        InvalidPreImage(SecretId, RoundId, AccountId, Threshold),
    }
}

decl_error! {
    pub enum Error for Module<T: Trait> {
        Unauthorized,
        InvalidProof,
        SecretIdOverflow,
        RoundIdOverflow,
        SecretGroupDNE,
        ToleranceLEQSize,
        ThresholdLEQSize,
        NoSecretSplit,
        MinOneSharePerMem,
        NoChangesAllowedForRound,
        ThresholdNotInitializedAt0,
        MustWaitUntilNextRoundAfterMembershipChanges,
    }
}

decl_storage! {
    trait Store for Module<T: Trait> as SecretModule {
        SecretIdCounter: T::SecretId;

        /// The set of accounts that will hold secret shares to reconstruct secrets
        pub Groups get(fn groups): map
            hasher(blake2_128_concat) T::SecretId
            => Option<Gov<T>>;

        /// Commitments made by the Dealer (user) && proofs of PreImage knowledge by Secret Holders
        pub Commits get(fn commits): double_map
            hasher(blake2_128_concat) T::SecretId,
            hasher(blake2_128_concat) T::RoundId
            => Option<RecSt<T>>;

        /// Current round
        pub Round get(fn round): map
            hasher(blake2_128_concat) T::SecretId
            => T::RoundId;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        type Error = Error<T>;

        fn deposit_event() = default;

        /// Create a new group for secret splitting.
        #[weight = 0]
        pub fn create_group(origin, set: Vec<T::AccountId>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let secret_id = <SecretIdCounter<T>>::get();
            let next_secret_id = secret_id
                .checked_add(&1u8.into())
                .ok_or(Error::<T>::SecretIdOverflow)?;
            let set = OrderedSet::from(set);
            let size = set.0.len();
            let group = Group {
                id: secret_id,
                acc: who.clone(),
                set,
            };
            <Groups<T>>::insert(secret_id, group);
            let next_round: T::RoundId = 1u8.into();
            <Round<T>>::insert(secret_id, next_round);
            <SecretIdCounter<T>>::put(next_secret_id);
            Self::deposit_event(RawEvent::NewGroup(who, secret_id, size as u8));
            Ok(())
        }
        /// Dealer publishes commitments (hashes) of encrypted secret shares
        #[weight = 0]
        pub fn split_secret(origin, id: T::SecretId, commit: Vec<T::Hash>, threshold: Threshold) -> DispatchResult {
            let user = ensure_signed(origin)?;
            let group = <Groups<T>>::get(id).ok_or(Error::<T>::SecretGroupDNE)?;
            ensure!(group.acc == user, Error::<T>::Unauthorized);
            let total = group.set.0.len();
            ensure!(commit.len() == total, Error::<T>::MinOneSharePerMem);
            ensure!(threshold.all == total as u8, Error::<T>::MinOneSharePerMem);
            ensure!(threshold.req <= total as u8, Error::<T>::ThresholdLEQSize);
            ensure!(threshold.tol <= total as u8, Error::<T>::ToleranceLEQSize);
            ensure!(threshold.yes_ct == 0u8 && threshold.no_ct == 0u8, Error::<T>::ThresholdNotInitializedAt0);
            let this_round = <Round<T>>::get(id);
            let next_round = this_round
                .checked_add(&1u8.into())
                .ok_or(Error::<T>::RoundIdOverflow)?;
            let state = RecoverySt {
                id: (id, this_round),
                score: threshold,
                state: commit.into_iter().map(|x| Commit { hash: x, proven: None }).collect(),
            };
            <Commits<T>>::insert(id, this_round, state);
            <Round<T>>::insert(id, next_round);
            Self::deposit_event(RawEvent::SplitSecret(id, this_round, threshold));
            Ok(())
        }
        /// Remove member from group
        #[weight = 0]
        pub fn remove_member(origin, id: T::SecretId, acc: T::AccountId) -> DispatchResult {
            let user = ensure_signed(origin)?;
            let mut group = <Groups<T>>::get(id).ok_or(Error::<T>::SecretGroupDNE)?;
            ensure!(group.acc == user, Error::<T>::Unauthorized);
            if group.set.remove(&acc) {
                <Groups<T>>::insert(id, group);
                Self::deposit_event(RawEvent::MemberRemoved(id, acc));
            }
            Ok(())
        }
        /// Add member to group
        #[weight = 0]
        pub fn add_member(origin, id: T::SecretId, acc: T::AccountId) -> DispatchResult {
            let user = ensure_signed(origin)?;
            let mut group = <Groups<T>>::get(id).ok_or(Error::<T>::SecretGroupDNE)?;
            ensure!(group.acc == user, Error::<T>::Unauthorized);
            if group.set.insert(acc.clone()) {
                <Groups<T>>::insert(id, group);
                Self::deposit_event(RawEvent::MemberAdded(id, acc));
            }
            Ok(())
        }
        /// Submit proof of preimage knowledge (by holder)
        #[weight = 0]
        pub fn publish_proof(origin, id: T::SecretId, proof: Vec<u8>) -> DispatchResult {
            let holder = ensure_signed(origin)?;
            let group = <Groups<T>>::get(id).ok_or(Error::<T>::SecretGroupDNE)?;
            if let Ok(index) = group.set.0.binary_search(&holder) {
                let round = <Round<T>>::get(id);
                let mut commit = <Commits<T>>::get(id, round).ok_or(Error::<T>::NoSecretSplit)?;
                ensure!(commit.state.len() == group.set.0.len(), Error::<T>::MustWaitUntilNextRoundAfterMembershipChanges);
                let proof = <T as System>::Hashing::hash(&proof);
                if let Some(c) = commit.state.get(index) {
                    if c.proven.is_some() {
                        // Proof Already Published For This Round so Cannot be Changed
                        return Err(Error::<T>::NoChangesAllowedForRound.into());
                    }
                    if c.hash == proof {
                        commit.state[index] = Commit { proven: Some(true), ..*c };
                        commit.score.yes_ct += 1u8;
                        let score = commit.score;
                        <Commits<T>>::insert(id, round, commit);
                        Self::deposit_event(RawEvent::ValidPreImage(id, round, holder, score));
                    } else {
                        commit.state[index] = Commit { proven: Some(false), ..*c };
                        commit.score.no_ct += 1u8;
                        let score = commit.score;
                        <Commits<T>>::insert(id, round, commit);
                        Self::deposit_event(RawEvent::InvalidPreImage(id, round, holder, score));
                    }
                }
                Ok(())
            } else {
                Err(Error::<T>::Unauthorized.into())
            }
        }
    }
}
