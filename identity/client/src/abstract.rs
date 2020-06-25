use crate::{Client, Identity, IdentityInfo, Result, Service};
use async_trait::async_trait;
use codec::Decode;
use keystore::bip39::Mnemonic;
use keystore::{DeviceKey, Password};
use libipld::store::Store;
use sp_core::crypto::{Pair, Ss58Codec};
use sp_runtime::traits::{IdentifyAccount, SignedExtension, Verify};
use substrate_subxt::{sp_core, sp_runtime, system::System, Runtime, Signer, SignedExtra};

#[async_trait]
pub trait AbstractClient<T: Runtime + Identity, P: Pair> {
    async fn has_device_key(&self) -> bool;
    async fn set_device_key(
        &self,
        dk: &DeviceKey,
        password: &Password,
        force: bool,
    ) -> Result<T::AccountId>;
    async fn signer(&self) -> Result<Box<dyn Signer<T>>>;
    async fn lock(&self) -> Result<()>;
    async fn unlock(&self, password: &Password) -> Result<()>;
    async fn create_account_for(&self, key: &T::AccountId) -> Result<()>;
    async fn add_paperkey(&self) -> Result<Mnemonic>;
    async fn add_key(&self, key: &T::AccountId) -> Result<()>;
    async fn remove_key(&self, key: &T::AccountId) -> Result<()>;
    async fn change_password(&self, password: &Password) -> Result<()>;
    async fn fetch_uid(&self, key: &T::AccountId) -> Result<Option<T::Uid>>;
    async fn fetch_keys(&self, uid: T::Uid, hash: Option<T::Hash>) -> Result<Vec<T::AccountId>>;
    async fn fetch_account(&self, uid: T::Uid) -> Result<T::IdAccountData>;
    async fn prove_identity(&self, service: Service) -> Result<String>;
    async fn revoke_identity(&self, service: Service) -> Result<()>;
    async fn identity(&self, uid: T::Uid) -> Result<Vec<IdentityInfo>>;
    async fn resolve(&self, service: &Service) -> Result<T::Uid>;
}

#[async_trait]
impl<T, P, I> AbstractClient<T, P> for Client<T, P, I>
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
    I: Store + Send + Sync,
{
    async fn has_device_key(&self) -> bool {
        self.has_device_key().await
    }

    async fn set_device_key(
        &self,
        dk: &DeviceKey,
        password: &Password,
        force: bool,
    ) -> Result<T::AccountId> {
        self.set_device_key(dk, password, force).await
    }

    async fn signer(&self) -> Result<Box<dyn Signer<T>>> {
        Ok(Box::new(self.signer().await?))
    }

    async fn lock(&self) -> Result<()> {
        self.lock().await
    }

    async fn unlock(&self, password: &Password) -> Result<()> {
        self.unlock(password).await
    }

    async fn create_account_for(&self, key: &T::AccountId) -> Result<()> {
        self.create_account_for(key).await
    }

    async fn add_paperkey(&self) -> Result<Mnemonic> {
        self.add_paperkey().await
    }

    async fn add_key(&self, key: &T::AccountId) -> Result<()> {
        self.add_key(key).await
    }

    async fn remove_key(&self, key: &T::AccountId) -> Result<()> {
        self.remove_key(key).await
    }

    async fn change_password(&self, password: &Password) -> Result<()> {
        self.change_password(password).await
    }

    async fn fetch_uid(&self, key: &T::AccountId) -> Result<Option<T::Uid>> {
        self.fetch_uid(key).await
    }

    async fn fetch_keys(&self, uid: T::Uid, hash: Option<T::Hash>) -> Result<Vec<T::AccountId>> {
        self.fetch_keys(uid, hash).await
    }

    async fn fetch_account(&self, uid: T::Uid) -> Result<T::IdAccountData> {
        self.fetch_account(uid).await
    }

    async fn prove_identity(&self, service: Service) -> Result<String> {
        self.prove_identity(service).await
    }

    async fn revoke_identity(&self, service: Service) -> Result<()> {
        self.revoke_identity(service).await
    }

    async fn identity(&self, uid: T::Uid) -> Result<Vec<IdentityInfo>> {
        self.identity(uid).await
    }

    async fn resolve(&self, service: &Service) -> Result<T::Uid> {
        self.resolve(service).await
    }
}
