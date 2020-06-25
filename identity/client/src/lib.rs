use crate::claim::{Claim, ClaimBody, UnsignedClaim};
use async_std::sync::Mutex;
use codec::{Decode, Encode};
use core::convert::TryInto;
use core::marker::PhantomData;
use ipld_block_builder::{Cache, Codec};
use keystore::bip39::{Language, Mnemonic, MnemonicType};
use keystore::{DeviceKey, KeyStore, Mask, Password};
use libipld::cid::Cid;
use libipld::store::Store;
use std::collections::HashMap;
use std::time::Duration;
use std::time::UNIX_EPOCH;
use substrate_subxt::sp_core::crypto::{Pair, Ss58Codec};
use substrate_subxt::sp_runtime::traits::{IdentifyAccount, SignedExtension, Verify};
use substrate_subxt::system::System;
use substrate_subxt::{PairSigner, Runtime, SignedExtra, Signer};

mod claim;
mod error;
mod github;
mod service;
mod subxt;

pub use claim::{IdentityInfo, IdentityStatus};
pub use error::{Error, Result};
pub use service::{Service, ServiceParseError};
pub use subxt::*;

pub struct Client<T, P, I>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    P: Pair,
    I: Store,
{
    _marker: PhantomData<P>,
    keystore: KeyStore,
    subxt: substrate_subxt::Client<T>,
    cache: Mutex<Cache<I, Codec, Claim>>,
}

impl<T, P, I> Client<T, P, I>
where
    T: Runtime + Identity,
    <T as System>::AccountId: Into<<T as System>::Address> + Ss58Codec,
    T::Signature: Decode + From<P::Signature>,
    <T::Signature as Verify>::Signer:
        From<P::Public> + IdentifyAccount<AccountId = <T as System>::AccountId>,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    P: Pair,
    <P as Pair>::Public: Into<<T as System>::AccountId>,
    <P as Pair>::Seed: From<[u8; 32]>,
    I: Store,
{
    pub fn new(keystore: KeyStore, subxt: substrate_subxt::Client<T>, store: I) -> Self {
        Self {
            _marker: PhantomData,
            keystore,
            subxt,
            cache: Mutex::new(Cache::new(store, Codec::new(), 32)),
        }
    }

    pub async fn has_device_key(&self) -> bool {
        self.keystore.is_initialized().await
    }

    pub async fn set_device_key(
        &self,
        dk: &DeviceKey,
        password: &Password,
        force: bool,
    ) -> Result<<T as System>::AccountId> {
        if self.has_device_key().await && !force {
            return Err(Error::KeystoreInitialized);
        }
        let pair = P::from_seed(&P::Seed::from(*dk.expose_secret()));
        self.keystore.initialize(&dk, &password).await?;
        Ok(pair.public().into())
    }

    pub async fn signer(&self) -> Result<PairSigner<T, P>> {
        // fetch device key from disk every time to make sure account is unlocked.
        let dk = self.keystore.device_key().await?;
        Ok(PairSigner::new(P::from_seed(&P::Seed::from(
            *dk.expose_secret(),
        ))))
    }

    pub async fn lock(&self) -> Result<()> {
        Ok(self.keystore.lock().await?)
    }

    pub async fn unlock(&self, password: &Password) -> Result<()> {
        self.keystore.unlock(password).await?;
        Ok(())
    }

    pub async fn create_account_for(&self, key: &<T as System>::AccountId) -> Result<()> {
        let signer = self.signer().await?;
        self.subxt
            .create_account_for_and_watch(&signer, key)
            .await?
            .account_created()?;
        Ok(())
    }

    pub async fn add_paperkey(&self) -> Result<Mnemonic> {
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        let dk = DeviceKey::from_mnemonic(&mnemonic).unwrap();
        let pair = P::from_seed(&P::Seed::from(*dk.expose_secret()));
        self.add_key(&pair.public().into()).await?;
        Ok(mnemonic)
    }

    pub async fn add_key(&self, key: &<T as System>::AccountId) -> Result<()> {
        let signer = self.signer().await?;
        self.subxt
            .add_key_and_watch(&signer, key)
            .await?
            .key_added()?;
        Ok(())
    }

    pub async fn remove_key(&self, key: &<T as System>::AccountId) -> Result<()> {
        let signer = self.signer().await?;
        self.subxt
            .remove_key_and_watch(&signer, key)
            .await?
            .key_removed()?;
        Ok(())
    }

    pub async fn change_password(&self, password: &Password) -> Result<()> {
        let signer = self.signer().await?;
        let mask = self.keystore.change_password_mask(password).await?;
        let gen = self.keystore.gen() + 1;
        self.subxt
            .change_password_and_watch(&signer, &T::Mask::from(*mask), T::Gen::from(gen))
            .await?;
        Ok(())
    }

    pub async fn update_password(&mut self) -> Result<()> {
        let signer = self.signer().await?;
        let uid = self
            .fetch_uid(signer.account_id())
            .await?
            .ok_or(Error::NoAccount)?;
        let pgen = self.subxt.password_gen(uid, None).await?.into();
        let gen = self.keystore.gen();
        for g in gen..pgen {
            let mask = self
                .subxt
                .password_mask(uid, T::Gen::from(g + 1), None)
                .await?
                .ok_or(Error::RuntimeInvalid)?;
            self.keystore
                .apply_mask(&Mask::new(mask.into()), g + 1)
                .await?;
        }
        Ok(())
    }

    async fn set_identity(&self, claim: Claim, signer: &PairSigner<T, P>) -> Result<()> {
        let prev = claim.claim().prev.clone();
        let mut cache = self.cache.lock().await;
        let root = cache.insert(claim).await?;
        drop(cache);
        let prev_cid = prev.clone().map(T::Cid::from);
        let root_cid = T::Cid::from(root);
        self.subxt
            .set_identity_and_watch(signer, &prev_cid, &root_cid)
            .await?
            .identity_changed()?;
        if let Some(prev) = prev {
            let mut cache = self.cache.lock().await;
            cache.unpin(&prev).await?;
            drop(cache);
        }
        Ok(())
    }

    pub async fn fetch_uid(&self, key: &<T as System>::AccountId) -> Result<Option<T::Uid>> {
        Ok(self.subxt.uid_lookup(key, None).await?)
    }

    pub async fn fetch_keys(
        &self,
        uid: T::Uid,
        hash: Option<T::Hash>,
    ) -> Result<Vec<<T as System>::AccountId>> {
        Ok(self.subxt.keys(uid, hash).await?)
    }

    pub async fn fetch_account(&self, uid: T::Uid) -> Result<T::IdAccountData> {
        Ok(self.subxt.account(uid, None).await?)
    }

    async fn fetch_identity(&self, uid: T::Uid) -> Result<Option<Cid>> {
        if let Some(bytes) = self.subxt.identity(uid, None).await? {
            Ok(Some(bytes.try_into()?))
        } else {
            Ok(None)
        }
    }

    async fn create_claim(
        &self,
        body: ClaimBody,
        expire_in: Option<Duration>,
        signer: &PairSigner<T, P>,
        uid: T::Uid,
    ) -> Result<Claim> {
        let genesis = self.subxt.genesis().as_ref().to_vec();
        let block = self
            .subxt
            .block_hash(None)
            .await?
            .ok_or(Error::NoBlockHash)?
            .as_ref()
            .to_vec();
        let prev = self.fetch_identity(uid).await?;
        let prev_seqno = if let Some(prev) = prev.as_ref() {
            let mut cache = self.cache.lock().await;
            cache.get(prev).await?.claim().seqno
        } else {
            0
        };
        let public = signer.account_id().to_ss58check();
        let expire_in = expire_in
            .unwrap_or_else(|| Duration::from_millis(u64::MAX))
            .as_millis() as u64;
        let ctime = UNIX_EPOCH.elapsed().unwrap().as_millis() as u64;
        let claim = UnsignedClaim {
            genesis,
            block,
            uid: uid.into(),
            public,
            prev,
            seqno: prev_seqno + 1,
            ctime,
            expire_in,
            body,
        };
        let signature: T::Signature = signer.signer().sign(&claim.to_bytes()?).into();
        let signature = Encode::encode(&signature);
        Ok(Claim::new(claim, signature))
    }

    pub async fn prove_identity(&self, service: Service) -> Result<String> {
        let signer = self.signer().await?;
        let uid = self
            .fetch_uid(signer.account_id())
            .await?
            .ok_or(Error::NoAccount)?;
        let claim = self
            .create_claim(ClaimBody::Ownership(service.clone()), None, &signer, uid)
            .await?;
        let proof = service.proof(&claim)?;
        self.set_identity(claim, &signer).await?;
        Ok(proof)
    }

    pub async fn revoke_identity(&self, service: Service) -> Result<()> {
        let signer = self.signer().await?;
        let uid = self
            .fetch_uid(signer.account_id())
            .await?
            .ok_or(Error::NoAccount)?;
        let id = self
            .identity(uid)
            .await?
            .into_iter()
            .find(|id| id.service == service && id.status != IdentityStatus::Revoked);
        if let Some(id) = id {
            let seqno = id.claims.last().unwrap().claim().seqno;
            let claim = self
                .create_claim(ClaimBody::Revoke(seqno), None, &signer, uid)
                .await?;
            self.set_identity(claim, &signer).await?;
        }
        Ok(())
    }

    async fn verify_claim(&self, uid: T::Uid, claim: &Claim) -> Result<()> {
        if claim.claim().uid != uid.into() {
            return Err(Error::InvalidClaim("uid"));
        }
        if &claim.claim().genesis[..] != self.subxt.genesis().as_ref() {
            return Err(Error::InvalidClaim("genesis"));
        }
        let prev_seqno = if let Some(prev) = claim.claim().prev.as_ref() {
            let mut cache = self.cache.lock().await;
            cache.get(prev).await?.claim().seqno
        } else {
            0
        };
        if claim.claim().seqno != prev_seqno + 1 {
            return Err(Error::InvalidClaim("seqno"));
        }
        let block = Decode::decode(&mut &claim.claim().block[..])?;
        let keys = self.fetch_keys(uid, Some(block)).await?;
        let key = keys
            .iter()
            .find(|k| k.to_ss58check() == claim.claim().public)
            .ok_or(Error::InvalidClaim("key"))?;
        let bytes = claim.claim().to_bytes()?;
        let signature: T::Signature = Decode::decode(&mut claim.signature())?;
        if !signature.verify(&bytes[..], key) {
            return Err(Error::InvalidClaim("signature"));
        }
        Ok(())
    }

    pub async fn identity(&self, uid: T::Uid) -> Result<Vec<IdentityInfo>> {
        let mut claims = vec![];
        let mut next = self.fetch_identity(uid).await?;
        while let Some(cid) = next {
            let mut cache = self.cache.lock().await;
            let claim = cache.get(&cid).await?;
            drop(cache);
            next = claim.claim().prev.clone();
            self.verify_claim(uid, &claim).await?;
            claims.push(claim);
        }
        let mut ids = HashMap::<Service, Vec<Claim>>::new();
        for claim in claims.iter().rev() {
            match claim.claim().body.clone() {
                ClaimBody::Ownership(service) => {
                    ids.entry(service.clone()).or_default().push(claim.clone());
                }
                ClaimBody::Revoke(seqno) => {
                    if let Some(claim2) = claims.get(seqno as usize - 1) {
                        if let ClaimBody::Ownership(service) = &claim2.claim().body {
                            ids.entry(service.clone()).or_default().push(claim.clone());
                        }
                    }
                }
            }
        }
        let mut info = vec![];
        for (service, claims) in ids.into_iter() {
            let mut status = IdentityStatus::ProofNotFound;
            let mut proof = None;
            for claim in &claims {
                match &claim.claim().body {
                    ClaimBody::Ownership(_) => {
                        if claim.claim().expired() {
                            status = IdentityStatus::Expired;
                        } else {
                            proof = Some(claim);
                        }
                    }
                    ClaimBody::Revoke(seqno) => {
                        if let Some(p) = proof {
                            if p.claim().seqno == *seqno {
                                status = IdentityStatus::Revoked;
                                proof = None;
                            }
                        }
                    }
                }
            }
            if status == IdentityStatus::ProofNotFound {
                if let Some(proof) = proof {
                    if let Ok(proof_url) = service.verify(proof.signature()).await {
                        status = IdentityStatus::Active(proof_url);
                    }
                }
            }
            info.push(IdentityInfo {
                service,
                claims,
                status,
            });
        }
        Ok(info)
    }

    pub async fn resolve(&self, service: &Service) -> Result<T::Uid> {
        let uids = service.resolve().await?;
        for uid in uids {
            if let Ok(uid) = uid.parse() {
                for id in self.identity(uid).await? {
                    if &id.service == service {
                        if let IdentityStatus::Active(_) = &id.status {
                            return Ok(uid);
                        }
                    }
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
    use sp_core::sr25519::Pair;
    use sp_core::Pair as _;
    use substrate_subxt::{sp_core, ClientBuilder};
    use test_client::identity::{Client, Service};
    use test_client::mock::{test_node, AccountKeyring, TempDir, TestNode};
    use test_client::Runtime;

    async fn build_client(node: TestNode) -> (Client<Runtime, Pair, MemStore>, TempDir) {
        let tmp = TempDir::new("sunshine-identity-").expect("failed to create tempdir");
        let subxt = ClientBuilder::new().set_client(node).build().await.unwrap();
        let store = MemStore::default();
        let keystore = KeyStore::open(tmp.path()).await.unwrap();
        let client = Client::new(keystore, subxt, store);
        (client, tmp)
    }

    async fn test_client() -> (Client<Runtime, Pair, MemStore>, TestNode, TempDir, TempDir) {
        let (node, tmp1) = test_node();
        let (client, tmp2) = build_client(node.clone()).await;
        let seed = Pair::from_string_with_seed("//Alice", None)
            .unwrap()
            .1
            .unwrap();
        client
            .set_device_key(
                &DeviceKey::from_seed(seed),
                &Password::from("password".to_string()),
                true,
            )
            .await
            .unwrap();
        (client, node, tmp1, tmp2)
    }

    #[async_std::test]
    async fn prove_identity() {
        let (client, _, _tmp1, _tmp2) = test_client().await;
        let account_id = AccountKeyring::Alice.to_account_id();
        let uid = client.fetch_uid(&account_id).await.unwrap().unwrap();
        assert_eq!(client.identity(uid).await.unwrap().len(), 0);
        client
            .prove_identity(Service::Github("dvc94ch".into()))
            .await
            .unwrap();
        assert_eq!(client.identity(uid).await.unwrap().len(), 1);
    }

    #[async_std::test]
    async fn change_password() {
        let (mut client1, subxt, _tmp1, _tmp2) = test_client().await;
        let (client2, _tmp3) = build_client(subxt).await;
        client2
            .set_device_key(
                &DeviceKey::generate().await,
                &Password::from("password".to_string()),
                true,
            )
            .await
            .unwrap();
        let signer2 = client2.signer().await.unwrap();
        client1.add_key(signer2.account_id()).await.unwrap();

        let password = Password::from("password2".to_string());
        client2.change_password(&password).await.unwrap();
        client1.update_password().await.unwrap();
        client1.lock().await.unwrap();
        client1.unlock(&password).await.unwrap();
        client1.signer().await.unwrap();
    }
}
