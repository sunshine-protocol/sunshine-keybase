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

#[derive(Encode, Decode, sp_runtime::RuntimeDebug)]
/// Membership info for each group
pub struct Group<Id, AccountId> {
    pub id: Id,
    pub acc: AccountId,
    pub set: OrderedSet<AccountId>,
}
pub type Gov<T> = Group<<T as Trait>::SecretId, <T as System>::AccountId>;

#[derive(Encode, Decode, sp_runtime::RuntimeDebug)]
pub struct Proof<Hash> {
    pub hash: Hash,
    pub proven: Option<bool>,
}
#[derive(Encode, Decode, sp_runtime::RuntimeDebug)]
pub struct Threshold {
    // Some(true) proofs submitted count
    pub yes_ct: u8,
    // Some(false) proofs submitted count
    pub no_ct: u8,
    // Threshold required
    pub req: u8,
    // Fault tolerance (required no_ct to trigger explicit fault)
    pub tol: u8,
}
impl Threshold {
    pub fn new(req: u8, tol: u8) -> Self {
        Threshold {
            yes_ct: 0u8,
            no_ct: 0u8,
            req,
            tol,
        }
    }
}

#[derive(Encode, Decode, sp_runtime::RuntimeDebug)]
/// Recovery State
/// The hash is the commitment for the relevant holder
/// The Option<bool> shows if the holder has committed the preimage
/// - Some(true) => proved via preimage
/// - Some(false) => proof failed for preimage (speaker-listener fault equivalence => use fault tolerance)
/// - None => proof not submitted by group member (index corresponds to position of AccountId in Group OrderedSet)
pub struct RecoverySt<Id, Hash> {
    pub id: Id,
    pub thresh: Threshold,
    pub proofs: Vec<Proof<Hash>>,
}
pub type RecSt<T> =
    RecoverySt<(<T as Trait>::SecretId, <T as Trait>::RoundId), <T as System>::Hash>;

/// The pallet's configuration trait.
pub trait Trait: System {
    /// Secret ID type.
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
        /// Account opens new group with identifier and number of accounts
        NewGroup(AccountId, SecretId, u8),
        /// Secret, Round, CommitHash, Required, Tolerance, Total
        SplitSecret(SecretId, RoundId, u8, u8, u8),
        MemberRemoved(SecretId, AccountId),
        MemberAdded(SecretId, AccountId),
        /// _, _, _,  Current Yes Count, Current No Count, Required, Tolerance, Total
        ValidProofPublished(SecretId, RoundId, AccountId, u8, u8, u8, u8, u8),
        InvalidProofPublished(SecretId, RoundId, AccountId, u8, u8, u8, u8, u8),
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
        MustWaitUntilNextRoundAfterMembershipChanges,
    }
}

decl_storage! {
    trait Store for Module<T: Trait> as ChainModule {
        SecretIdCounter: T::SecretId;

        /// The set of accounts that will hold secret shares to reconstruct secrets
        pub Groups get(fn groups): map
            hasher(blake2_128_concat) T::SecretId
            => Option<Gov<T>>;

        /// Commitments made by the Dealer (user) && proofs by Secret Holders
        pub Commits get(fn commits): double_map
            hasher(blake2_128_concat) T::SecretId,
            hasher(blake2_128_concat) T::RoundId
            => Option<RecSt<T>>;

        /// Latest round
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
            // next round is Round 1 (just like secret_id semantics)
            let next_round: T::RoundId = 1u8.into();
            <Round<T>>::insert(secret_id, next_round);
            <SecretIdCounter<T>>::put(next_secret_id);
            Self::deposit_event(RawEvent::NewGroup(who, secret_id, size as u8));
            Ok(())
        }
        /// Dealer publishes commitments (hashes) of encrypted secret shares
        #[weight = 0]
        pub fn split_secret(origin, id: T::SecretId, commit: Vec<T::Hash>, required: u8, tolerance: u8) -> DispatchResult {
            let user = ensure_signed(origin)?;
            let group = <Groups<T>>::get(id).ok_or(Error::<T>::SecretGroupDNE)?;
            ensure!(group.acc == user, Error::<T>::Unauthorized);
            let total = group.set.0.len();
            ensure!(commit.len() == total, Error::<T>::MinOneSharePerMem);
            ensure!(required <= total as u8, Error::<T>::ThresholdLEQSize);
            ensure!(tolerance <= total as u8, Error::<T>::ToleranceLEQSize);
            let this_round = <Round<T>>::get(id);
            let next_round = this_round
                .checked_add(&1u8.into())
                .ok_or(Error::<T>::RoundIdOverflow)?;
            let state = RecoverySt {
                id: (id, this_round),
                thresh: Threshold::new(required, tolerance),
                proofs: commit.into_iter().map(|x| Proof { hash: x, proven: None }).collect(),
            };
            <Commits<T>>::insert(id, this_round, state);
            <Round<T>>::insert(id, next_round);
            Self::deposit_event(RawEvent::SplitSecret(id, this_round, required, tolerance, total as u8));
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
                ensure!(commit.proofs.len() == group.set.0.len(), Error::<T>::MustWaitUntilNextRoundAfterMembershipChanges);
                let proof = <T as System>::Hashing::hash(&proof);
                if let Some(c) = commit.proofs.get(index) {
                    if c.proven.is_some() {
                        // Proof Already Published For This Round so Cannot be Changed
                        return Err(Error::<T>::NoChangesAllowedForRound.into());
                    }
                    if c.hash == proof {
                        commit.proofs[index] = Proof { proven: Some(true), ..*c };
                        commit.thresh.yes_ct += 1u8;
                        let (y, n, r, t, tt) = (
                            commit.thresh.yes_ct,
                            commit.thresh.no_ct,
                            commit.thresh.req,
                            commit.thresh.tol,
                            commit.proofs.len() as u8
                        );
                        <Commits<T>>::insert(id, round, commit);
                        Self::deposit_event(RawEvent::ValidProofPublished(id, round, holder, y, n, r, t, tt));
                    } else {
                        commit.proofs[index] = Proof { proven: Some(false), ..*c };
                        commit.thresh.no_ct += 1u8;
                        let (y, n, r, t, tt) = (
                            commit.thresh.yes_ct,
                            commit.thresh.no_ct,
                            commit.thresh.req,
                            commit.thresh.tol,
                            commit.proofs.len() as u8
                        );
                        <Commits<T>>::insert(id, round, commit);
                        Self::deposit_event(RawEvent::InvalidProofPublished(id, round, holder, y, n, r, t, tt));
                    }
                }
                Ok(())
            } else {
                Err(Error::<T>::Unauthorized.into())
            }
        }
    }
}
