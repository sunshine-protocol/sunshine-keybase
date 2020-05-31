//! Subxt calls.
use codec::{Decode, Encode};
use core::convert::TryInto;
use core::marker::PhantomData;
use frame_support::Parameter;
use libipld::cid::{Cid, Error as CidError};
use substrate_subxt::sp_runtime::traits::Member;
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt::{module, Call, Event, Store};

#[module]
pub trait Identity: System {
    type Cid: Parameter + Member + Default + From<Cid> + TryInto<Cid, Error = CidError>;
}

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct IdentityStore<'a, T: Identity> {
    #[store(returns = Option<T::Cid>)]
    who: &'a <T as System>::AccountId,
}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct SetIdentityCall<'a, T: Identity> {
    _runtime: PhantomData<T>,
    cid: &'a T::Cid,
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct IdentityUpdatedEvent<T: Identity> {
    who: <T as System>::AccountId,
    cid: T::Cid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use libipld::cid::{Cid, Codec};
    use libipld::multihash::Sha2_256;
    use substrate_subxt::{
        ClientBuilder, KusamaRuntime as NodeTemplateRuntime, PairSigner, Signer,
    };
    use utils_identity::CidBytes;

    impl Identity for NodeTemplateRuntime {
        type Cid = CidBytes;
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
        let event = client
            .set_identity_and_watch(&signer, &cid)
            .await
            .unwrap()
            .identity_updated()
            .unwrap()
            .unwrap();
        assert_eq!(&event.who, signer.account_id());
        assert_eq!(event.cid, cid);
        let cid2 = client.identity(signer.account_id()).await.unwrap().unwrap();
        assert_eq!(cid, cid2);
    }
}
