use crate::claim::{Claim, ClaimBody, UnsignedClaim};
use codec::{Decode, Encode};
use core::convert::TryInto;
use ipld_block_builder::{Cache, Codec};
use libipld::cid::Cid;
use libipld::store::Store;
use std::time::Duration;
use substrate_subxt::sp_core::crypto::{Pair, Ss58Codec};
use substrate_subxt::sp_runtime::traits::{IdentifyAccount, SignedExtension, Verify};
use substrate_subxt::system::System;
use substrate_subxt::{PairSigner, SignedExtra, Signer};

mod claim;
mod error;
mod github;
mod subxt;

pub use claim::{IdentityInfo, IdentityStatus, Service, ServiceParseError};
pub use error::Error;
pub use github::Error as GithubError;
pub use subxt::*;

pub struct Client<I, T, S, E>
where
    I: Store,
    T: Identity + Send + Sync + 'static,
    <T as System>::AccountId: Into<<T as System>::Address> + Ss58Codec,
    S: Encode + Verify + Send + Sync + 'static,
    <S as Verify>::Signer: IdentifyAccount<AccountId = <T as System>::AccountId>,
    E: SignedExtra<T> + SignedExtension + Send + Sync + 'static,
    <<E as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
{
    subxt: substrate_subxt::Client<T, S, E>,
    cache: Cache<I, Codec, Claim>,
}

impl<I, T, S, E> Client<I, T, S, E>
where
    I: Store,
    T: Identity + Send + Sync + 'static,
    <T as System>::AccountId: Into<<T as System>::Address> + Ss58Codec,
    S: Decode + Encode + Verify + Send + Sync + 'static,
    <S as Verify>::Signer: IdentifyAccount<AccountId = <T as System>::AccountId>,
    E: SignedExtra<T> + SignedExtension + Send + Sync + 'static,
    <<E as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
{
    pub fn new(subxt: substrate_subxt::Client<T, S, E>, store: I) -> Self {
        Self {
            subxt,
            cache: Cache::new(store, Codec::new(), 32),
        }
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

    async fn create_claim<P>(
        &mut self,
        body: ClaimBody,
        expire_in: Option<Duration>,
        signer: &PairSigner<T, S, E, P>,
    ) -> Result<Claim, Error>
    where
        P: Pair,
        S: From<P::Signature>,
        S::Signer: From<P::Public>,
    {
        let prev = self.identity_cid(signer.account_id()).await?;
        let claim = UnsignedClaim::new(
            &mut self.cache,
            body,
            prev,
            expire_in.unwrap_or_else(|| Duration::from_millis(u64::MAX)),
        )
        .await?;
        Claim::new::<S, _>(signer.signer(), claim)
    }

    async fn submit_claim(
        &mut self,
        claim: Claim,
        signer: &(dyn Signer<T, S, E> + Send + Sync),
    ) -> Result<(), Error> {
        let root = self.cache.insert(claim).await?;
        let cid = T::Cid::from(root);
        self.subxt
            .set_identity_and_watch(signer, &cid)
            .await?
            .identity_updated()?;
        Ok(())
    }

    pub async fn prove_ownership<P>(
        &mut self,
        service: Service,
        signer: &PairSigner<T, S, E, P>,
    ) -> Result<String, Error>
    where
        P: Pair,
        S: From<P::Signature>,
        S::Signer: From<P::Public>,
    {
        let claim = self
            .create_claim(ClaimBody::Ownership(service.clone()), None, signer)
            .await?;
        let account_id = signer.account_id().to_string();
        let proof = service.proof(&account_id, &claim)?;
        self.submit_claim(claim, signer).await?;
        Ok(proof)
    }

    pub async fn revoke_claim<P>(
        &mut self,
        claim: u32,
        signer: &PairSigner<T, S, E, P>,
    ) -> Result<(), Error>
    where
        P: Pair,
        S: From<P::Signature>,
        S::Signer: From<P::Public>,
    {
        let claim = self
            .create_claim(ClaimBody::Revoke(claim), None, signer)
            .await?;
        self.submit_claim(claim, signer).await?;
        Ok(())
    }

    async fn claims(&mut self, account_id: &<T as System>::AccountId) -> Result<Vec<Claim>, Error> {
        let mut claims = vec![];
        let mut next = self.identity_cid(account_id).await?;
        while let Some(cid) = next {
            let claim = self.cache.get(&cid).await?;
            next = claim.claim().prev().cloned();
            if claim.verify::<S>(account_id).is_ok() {
                claims.push(claim);
            }
        }
        Ok(claims)
    }

    pub async fn identity(
        &mut self,
        account_id: &<T as System>::AccountId,
    ) -> Result<Vec<IdentityInfo>, Error> {
        let claims = self.claims(account_id).await?;
        let account_id = account_id.to_string();
        let mut identities = vec![];
        let mut proofs = vec![];
        for claim in claims.iter().rev() {
            match claim.claim().body() {
                ClaimBody::Ownership(service) => {
                    let status = if claim.claim().expired() {
                        IdentityStatus::Expired
                    } else {
                        IdentityStatus::ProofNotFound
                    };
                    if let Ok(proof) = service.proof(&account_id, claim) {
                        identities.push(IdentityInfo {
                            service: service.clone(),
                            seqno: claim.claim().seqno(),
                            status,
                        });
                        proofs.push(proof);
                    }
                }
                ClaimBody::Revoke(seqno) => {
                    if let Some(mut id) = identities.iter_mut().find(|id| id.seqno == *seqno) {
                        id.status = IdentityStatus::Revoked;
                    }
                }
            }
        }
        for (mut id, proof) in identities.iter_mut().zip(proofs.iter()) {
            if id.status == IdentityStatus::ProofNotFound {
                match &id.service {
                    Service::Github(username) => {
                        if let Ok(url) = github::verify_identity(&username, proof).await {
                            id.status = IdentityStatus::Active(url);
                        }
                    }
                }
            }
        }
        Ok(identities)
    }

    pub async fn resolve(&mut self, service: &Service) -> Result<<T as System>::AccountId, Error> {
        let accounts = match service {
            Service::Github(username) => github::resolve_identity(&username).await?,
        };
        for account in accounts {
            let account_id = match <T as System>::AccountId::from_string(&account) {
                Ok(account_id) => account_id,
                Err(_) => continue,
            };
            for id in self.identity(&account_id).await? {
                if &id.service == service {
                    return Ok(account_id);
                }
            }
        }
        Err(Error::ResolveFailure)
    }
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
        let signer = PairSigner::new(pair);
        let mut client = Client::new(subxt, store);
        assert_eq!(client.claims(signer.account_id()).await.unwrap().len(), 0);
        client
            .prove_ownership(Service::Github("dvc94ch".into()), &signer)
            .await
            .unwrap();
        assert_eq!(client.claims(signer.account_id()).await.unwrap().len(), 1);
    }
}
