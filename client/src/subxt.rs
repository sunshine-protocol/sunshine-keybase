//! Subxt calls.
use codec::{Decode, Encode, FullCodec};
use core::convert::TryInto;
use frame_support::Parameter;
use libipld::cid::{Cid, Error as CidError};
use std::str::FromStr;
use substrate_subxt::sp_runtime::traits::{CheckedAdd, Member};
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt::{module, Call, Event, Store};

#[module]
pub trait Identity: System {
    type Uid: Parameter + Member + Copy + Default + CheckedAdd + Into<u64> + FromStr;

    type Cid: Parameter + Member + Default + From<Cid> + TryInto<Cid, Error = CidError>;

    type Mask: Parameter + Member + Default + From<[u8; 32]> + Into<[u8; 32]>;

    type Gen: Parameter + Member + Copy + Default + CheckedAdd + From<u8> + Ord;

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
    gen: T::Uid,
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

#[cfg(test)]
mod tests {
    use super::*;
    use libipld::cid::{Cid, Codec};
    use libipld::multihash::Sha2_256;
    use substrate_subxt::{
        ClientBuilder, KusamaRuntime as NodeTemplateRuntime, PairSigner, Signer,
    };
    use utils_identity::cid::CidBytes;

    impl Identity for NodeTemplateRuntime {
        type Uid = u8;
        type Cid = CidBytes;
        type Mask = [u8; 32];
        type Gen = u8;
        type IdAccountData = ();
    }

    #[async_std::test]
    #[ignore]
    async fn test_set_identity() {
        env_logger::try_init().ok();
        let client = ClientBuilder::<NodeTemplateRuntime>::new()
            .build()
            .await
            .unwrap();
        let signer = PairSigner::new(sp_keyring::AccountKeyring::Alice.pair());
        let cid = CidBytes::from(&Cid::new_v1(Codec::Raw, Sha2_256::digest(b"hello_world")));
        let uid = client
            .create_account_for_and_watch(&signer, signer.account_id())
            .await
            .unwrap()
            .account_created()
            .unwrap()
            .unwrap()
            .uid;
        let event = client
            .set_identity_and_watch(&signer, &None, &cid)
            .await
            .unwrap()
            .identity_changed()
            .unwrap()
            .unwrap();
        assert_eq!(event.uid, uid);
        assert_eq!(event.cid, cid);
        let cid2 = client.identity(uid, None).await.unwrap().unwrap();
        assert_eq!(cid, cid2);
    }
}
