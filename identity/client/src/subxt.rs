//! Subxt calls.
use codec::{Decode, Encode, FullCodec};
use core::fmt::Display;
use frame_support::Parameter;
use libipld::cid::Cid;
use std::str::FromStr;
use substrate_subxt::sp_runtime::traits::{CheckedAdd, Member};
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt::{module, Call, Event, Store};

#[module]
pub trait Identity: System {
    type Uid: Parameter + Member + Copy + Default + CheckedAdd + Into<u64> + FromStr + Display;

    type Cid: Parameter + Member + Default + From<Cid> + Into<Cid>;

    type Mask: Parameter + Member + Default;

    type Gen: Parameter + Member + Copy + Default + CheckedAdd + From<u16> + Into<u16> + Ord;

    type IdAccountData: Member + FullCodec + Clone + Default;
}

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct UidLookupStore<'a, T: Identity> {
    #[store(returns = Option<T::Uid>)]
    key: &'a <T as System>::AccountId,
}

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct KeysStore<T: Identity> {
    #[store(returns = Vec<<T as System>::AccountId>)]
    uid: T::Uid,
}

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct IdentityStore<T: Identity> {
    #[store(returns = Option<T::Cid>)]
    uid: T::Uid,
}

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct PasswordGenStore<T: Identity> {
    #[store(returns = T::Gen)]
    uid: T::Uid,
}

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct PasswordMaskStore<T: Identity> {
    #[store(returns = Option<T::Mask>)]
    uid: T::Uid,
    gen: T::Gen,
}

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct AccountStore<T: Identity> {
    #[store(returns = T::IdAccountData)]
    uid: T::Uid,
}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct CreateAccountForCall<'a, T: Identity> {
    key: &'a <T as System>::AccountId,
}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct AddKeyCall<'a, T: Identity> {
    key: &'a <T as System>::AccountId,
}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct RemoveKeyCall<'a, T: Identity> {
    key: &'a <T as System>::AccountId,
}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct ChangePasswordCall<'a, T: Identity> {
    password_mask: &'a T::Mask,
    gen: T::Gen,
}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct SetIdentityCall<'a, T: Identity> {
    prev_cid: &'a Option<T::Cid>,
    new_cid: &'a T::Cid,
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct AccountCreatedEvent<T: Identity> {
    uid: T::Uid,
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct KeyAddedEvent<T: Identity> {
    uid: T::Uid,
    key: <T as System>::AccountId,
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct KeyRemovedEvent<T: Identity> {
    uid: T::Uid,
    key: <T as System>::AccountId,
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct IdentityChangedEvent<T: Identity> {
    uid: T::Uid,
    cid: T::Cid,
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct PasswordChangedEvent<T: Identity> {
    uid: T::Uid,
    gen: T::Gen,
    mask: T::Mask,
}
