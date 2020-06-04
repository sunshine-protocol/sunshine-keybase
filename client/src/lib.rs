use crate::claim::{Claim, ClaimBody, UnsignedClaim};
use codec::{Decode, Encode};
use core::convert::TryInto;
use core::marker::PhantomData;
use ipld_block_builder::{Cache, Codec};
use keystore::{DeviceKey, KeyStore, Password};
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

pub struct Client<T, S, E, P, I>
where
    T: Identity + Send + Sync + 'static,
    <T as System>::AccountId: Into<<T as System>::Address> + Ss58Codec,
    S: Encode + Verify + Send + Sync + 'static,
    <S as Verify>::Signer: IdentifyAccount<AccountId = <T as System>::AccountId>,
    E: SignedExtra<T> + SignedExtension + Send + Sync + 'static,
    <<E as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    P: Pair,
    I: Store,
{
    _marker: PhantomData<P>,
    keystore: KeyStore,
    subxt: substrate_subxt::Client<T, S, E>,
    cache: Cache<I, Codec, Claim>,
}

impl<T, S, E, P, I> Client<T, S, E, P, I>
where
    T: Identity + Send + Sync + 'static,
    <T as System>::AccountId: Into<<T as System>::Address> + Ss58Codec,
    S: Decode + Encode + From<P::Signature> + Verify + Send + Sync + 'static,
    <S as Verify>::Signer: From<P::Public> + IdentifyAccount<AccountId = <T as System>::AccountId>,
    E: SignedExtra<T> + SignedExtension + Send + Sync + 'static,
    <<E as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    P: Pair,
    <P as Pair>::Public: Into<<T as System>::AccountId>,
    <P as Pair>::Seed: From<[u8; 32]>,
    I: Store,
{
    pub fn new(keystore: KeyStore, subxt: substrate_subxt::Client<T, S, E>, store: I) -> Self {
        Self {
            _marker: PhantomData,
            keystore,
            subxt,
            cache: Cache::new(store, Codec::new(), 32),
        }
    }

    pub fn set_device_key(
        &self,
        dk: &DeviceKey,
        password: &Password,
        force: bool,
    ) -> Result<<T as System>::AccountId, Error> {
        if self.keystore.is_initialized() && !force {
            return Err(Error::KeystoreInitialized);
        }
        let pair = P::from_seed(&P::Seed::from(*dk.expose_secret()));
        self.keystore.initialize(&dk, &password)?;
        Ok(pair.public().into())
    }

    pub fn signer(&self) -> Result<PairSigner<T, S, E, P>, Error> {
        // fetch device key from disk every time to make sure account is unlocked.
        let dk = self.keystore.device_key()?;
        Ok(PairSigner::new(P::from_seed(&P::Seed::from(
            *dk.expose_secret(),
        ))))
    }

    pub fn password(&self) -> Result<Password, Error> {
        Ok(self.keystore.password()?)
    }

    pub fn lock(&self) -> Result<(), Error> {
        Ok(self.keystore.lock()?)
    }

    pub fn unlock(&self, password: &Password) -> Result<(), Error> {
        self.keystore.unlock(password)?;
        Ok(())
    }

    pub async fn create_account_for(&self, device: &<T as System>::AccountId) -> Result<(), Error> {
        let signer = self.signer()?;
        self.subxt
            .create_account_for_and_watch(&signer, device)
            .await?
            .account_created()?;
        Ok(())
    }

    pub async fn add_device(&self, device: &<T as System>::AccountId) -> Result<(), Error> {
        let signer = self.signer()?;
        self.subxt
            .add_device_and_watch(&signer, device)
            .await?
            .device_added()?;
        Ok(())
    }

    pub async fn remove_device(&self, device: &<T as System>::AccountId) -> Result<(), Error> {
        let signer = self.signer()?;
        self.subxt
            .remove_device_and_watch(&signer, device)
            .await?
            .device_removed()?;
        Ok(())
    }

    async fn identity_cid(
        &self,
        account_id: &<T as System>::AccountId,
    ) -> Result<Option<Cid>, Error> {
        if let Some(uid) = self.subxt.device(account_id, None).await? {
            if let Some(bytes) = self.subxt.identity(uid, None).await? {
                return Ok(Some(bytes.try_into()?));
            }
        }
        Ok(None)
    }

    async fn create_claim(
        &mut self,
        body: ClaimBody,
        expire_in: Option<Duration>,
        signer: &PairSigner<T, S, E, P>,
    ) -> Result<Claim, Error> {
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
        let prev = claim.claim().prev().cloned().map(T::Cid::from);
        let root = self.cache.insert(claim).await?;
        let cid = T::Cid::from(root);
        self.subxt
            .set_identity_and_watch(signer, &prev, &cid)
            .await?
            .identity_changed()?;
        Ok(())
    }

    pub async fn prove_ownership(&mut self, service: Service) -> Result<String, Error> {
        let signer = self.signer()?;
        let claim = self
            .create_claim(ClaimBody::Ownership(service.clone()), None, &signer)
            .await?;
        let account_id = signer.account_id().to_string();
        let proof = service.proof(&account_id, &claim)?;
        self.submit_claim(claim, &signer).await?;
        Ok(proof)
    }

    pub async fn revoke_claim(&mut self, claim: u32) -> Result<(), Error> {
        let signer = self.signer()?;
        let claim = self
            .create_claim(ClaimBody::Revoke(claim), None, &signer)
            .await?;
        self.submit_claim(claim, &signer).await?;
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
    use utils_identity::cid::CidBytes;

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
        type Uid = u8;
        type Cid = CidBytes;
        type Mask = [u8; 32];
        type Gen = u8;
    }

    #[async_std::test]
    #[ignore]
    async fn make_claim() {
        env_logger::try_init().ok();
        let subxt = ClientBuilder::<Runtime>::new().build().await.unwrap();
        let store = MemStore::default();
        let keystore = KeyStore::new("/tmp/keystore");
        let account_id = sp_keyring::AccountKeyring::Alice.to_account_id();
        let mut client = Client::<_, _, _, sp_core::sr25519::Pair, _>::new(keystore, subxt, store);
        assert_eq!(client.claims(&account_id).await.unwrap().len(), 0);
        client
            .prove_ownership(Service::Github("dvc94ch".into()))
            .await
            .unwrap();
        assert_eq!(client.claims(&account_id).await.unwrap().len(), 1);
    }
}
