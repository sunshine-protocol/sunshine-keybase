use crate::claim::{Claim, ClaimBody, ProofParams, Service, UnsignedClaim};
use crate::error::Error;
use crate::subxt::{Identity, IdentityStoreExt, IdentityUpdatedEventExt, SetIdentityCallExt};
use codec::{Decode, Encode};
use core::convert::TryInto;
use ipld_block_builder::{Cache, Codec};
use libipld::cid::Cid;
use libipld::store::Store;
use std::time::Duration;
use substrate_subxt::sp_core::Pair;
use substrate_subxt::sp_runtime::traits::{IdentifyAccount, SignedExtension, Verify};
use substrate_subxt::system::System;
use substrate_subxt::{PairSigner, SignedExtra, Signer};

pub mod claim;
pub mod error;
//mod github;
pub mod subxt;

pub struct Client<I, P, T, S, E>
where
    I: Store,
    P: Pair,
    T: Identity + 'static,
    <T as System>::AccountId: Into<<T as System>::Address>,
    S: Encode + From<P::Signature> + Verify + Send + Sync + 'static,
    <S as Verify>::Signer: From<P::Public> + IdentifyAccount<AccountId = <T as System>::AccountId>,
    E: SignedExtra<T> + 'static,
{
    subxt: substrate_subxt::Client<T, S, E>,
    signer: PairSigner<T, S, E, P>,
    cache: Cache<I, Codec, Claim>,
    root: Option<Cid>,
}

impl<I, P, T, S, E> Client<I, P, T, S, E>
where
    I: Store,
    P: Pair,
    T: Identity + Send + Sync + 'static,
    <T as System>::AccountId: Into<<T as System>::Address>,
    S: Decode + Encode + From<P::Signature> + Verify + Send + Sync + 'static,
    <S as Verify>::Signer: From<P::Public> + IdentifyAccount<AccountId = <T as System>::AccountId>,
    E: SignedExtra<T> + SignedExtension + Send + Sync + 'static,
    <<E as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
{
    pub async fn new(
        subxt: substrate_subxt::Client<T, S, E>,
        store: I,
        pair: P,
    ) -> Result<Self, Error> {
        let mut client = Self {
            signer: PairSigner::new(pair.clone()),
            subxt,
            cache: Cache::new(store, Codec::new(), 32),
            root: None,
        };
        client.root = client.identity_cid(client.signer.account_id()).await?;
        Ok(client)
    }

    async fn identity_cid(
        &self,
        account_id: &<T as System>::AccountId,
    ) -> Result<Option<Cid>, Error> {
        if let Some(bytes) = self.subxt.identity(account_id, None).await? {
            Ok(Some(bytes.try_into()?))
        } else {
            Ok(None)
        }
    }

    async fn create_claim(
        &mut self,
        body: ClaimBody,
        expire_in: Option<Duration>,
    ) -> Result<Claim, Error> {
        let claim = UnsignedClaim::new(
            &mut self.cache,
            body,
            self.root.clone(),
            expire_in.unwrap_or_else(|| Duration::from_millis(u64::MAX)),
        )
        .await?;
        Claim::new::<S, _>(self.signer.signer(), claim)
    }

    async fn submit_claim(&mut self, claim: Claim) -> Result<(), Error> {
        let root = self.cache.insert(claim).await?;
        let cid = T::Cid::from(root.clone());
        self.subxt
            .set_identity_and_watch(&self.signer, &cid)
            .await?
            .identity_updated()?;
        self.root = Some(root);
        Ok(())
    }

    pub async fn prove_ownership(&mut self, service: Service) -> Result<String, Error> {
        let claim = self.create_claim(ClaimBody::Ownership(service.clone()), None).await?;
        let params = ProofParams {
            account_id: self.signer.account_id().to_string(),
            object: claim.claim().to_json()?,
            signature: claim.signature(),
        };
        let proof = service.proof(&params);
        self.submit_claim(claim).await?;
        Ok(proof)
    }

    pub async fn revoke_claim(&mut self, claim: u32) -> Result<(), Error> {
        let claim = self.create_claim(ClaimBody::Revoke(claim), None).await?;
        self.submit_claim(claim).await?;
        Ok(())
    }

    pub async fn claims(
        &mut self,
        account_id: &<T as System>::AccountId,
    ) -> Result<Vec<ClaimBody>, Error> {
        let mut claims = vec![];
        let mut next = self.identity_cid(account_id).await?;
        while let Some(cid) = next {
            let claim = self.cache.get(&cid).await?;
            if claim.verify::<S>(account_id).is_ok() {
                claims.push(claim.claim().body().clone());
            }
            next = claim.claim().prev().cloned();
        }
        Ok(claims)
    }

    /*pub async fn identity(&self, account_id: &<T as System>::AccountId) -> Result<(), Error> {

    }

    pub async fn resolve(&self, id: &Identifier<T>) -> Result<<T as System>::AccountId, Error> {
        todo!()
    }*/
}

#[cfg(test)]
mod tests {
    use super::*;
    use libipld::mem::MemStore;
    use substrate_subxt::balances::{AccountData, Balances};
    use substrate_subxt::system::System;
    use substrate_subxt::{sp_core, sp_runtime, ClientBuilder};
    use utils_identity::CidBytes;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Runtime;

    impl System for Runtime {
        type Index = u32;
        type BlockNumber = u32;
        type Hash = sp_core::H256;
        type Hashing = sp_runtime::traits::BlakeTwo256;
        type AccountId =
            <<sp_runtime::MultiSignature as Verify>::Signer as IdentifyAccount>::AccountId;
        type Address = Self::AccountId;
        type Header = sp_runtime::generic::Header<Self::BlockNumber, Self::Hashing>;
        type Extrinsic = sp_runtime::OpaqueExtrinsic;
        type AccountData = AccountData<<Self as Balances>::Balance>;
    }

    impl Balances for Runtime {
        type Balance = u128;
    }

    impl Identity for Runtime {
        type Cid = CidBytes;
    }

    #[async_std::test]
    #[ignore]
    async fn make_claim() {
        env_logger::try_init().ok();
        let subxt = ClientBuilder::<Runtime>::new().build().await.unwrap();
        let store = MemStore::default();
        let pair = sp_keyring::AccountKeyring::Alice.pair();
        let mut client = Client::new(subxt, store, pair.clone()).await.unwrap();
        assert_eq!(client.claims(&pair.public().into()).await.unwrap().len(), 0);
        client
            .prove_ownership(Service::Github("dvc94ch".into()))
            .await
            .unwrap();
        assert_eq!(client.claims(&pair.public().into()).await.unwrap().len(), 1);
    }
}
