mod claim;
mod client;
mod error;
mod github;
mod service;
mod subxt;
mod utils;

pub use claim::{Claim, IdentityInfo, IdentityStatus};
pub use error::Error;
pub use service::{Service, ServiceParseError};
pub use subxt::*;
pub use utils::{resolve, Identifier};

use codec::Decode;
use ipld_block_builder::{Cache, Codec};
use sp_core::crypto::{Pair, Ss58Codec};
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::convert::TryInto;
use substrate_subxt::{
    sp_core, sp_runtime, system::System, EventSubscription, Runtime, SignedExtension, SignedExtra,
};
use sunshine_client_utils::{
    async_trait,
    crypto::{bip39::Mnemonic, keychain::KeyType, secrecy::SecretString},
    keystore, Client, Result,
};

#[async_trait]
pub trait IdentityClient<R: Runtime + Identity>: Client<R> {
    async fn create_account_for(&self, key: &<R as System>::AccountId) -> Result<()>;
    async fn add_paperkey(&self) -> Result<Mnemonic>;
    async fn add_key(&self, key: &<R as System>::AccountId) -> Result<()>;
    async fn remove_key(&self, key: &<R as System>::AccountId) -> Result<()>;
    async fn change_password(&self, password: &SecretString) -> Result<()>;
    async fn update_password(&mut self) -> Result<()>;
    async fn subscribe_password_changes(&self) -> Result<EventSubscription<R>>;
    async fn fetch_uid(&self, key: &<R as System>::AccountId) -> Result<Option<R::Uid>>;
    async fn fetch_keys(
        &self,
        uid: R::Uid,
        hash: Option<<R as System>::Hash>,
    ) -> Result<Vec<<R as System>::AccountId>>;
    async fn fetch_account(&self, uid: R::Uid) -> Result<R::IdAccountData>;
    async fn prove_identity(&self, service: Service) -> Result<String>;
    async fn revoke_identity(&self, service: Service) -> Result<()>;
    async fn identity(&self, uid: R::Uid) -> Result<Vec<IdentityInfo>>;
    async fn resolve(&self, service: &Service) -> Result<R::Uid>;
}

#[async_trait]
impl<R, C, K> IdentityClient<R> for C
where
    R: Runtime + Identity<Gen = u16, Mask = [u8; 32]>,
    <<R::Extra as SignedExtra<R>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    R::AccountId: Into<R::Address> + Ss58Codec,
    R::Signature: From<<<C::KeyType as KeyType>::Pair as Pair>::Signature> + Decode,
    <R::Signature as Verify>::Signer: From<<<C::KeyType as KeyType>::Pair as Pair>::Public>
        + TryInto<<<C::KeyType as KeyType>::Pair as Pair>::Public>
        + IdentifyAccount<AccountId = R::AccountId>
        + Clone
        + Send
        + Sync,
    C: Client<R, KeyType = K, Keystore = keystore::Keystore<K>>,
    C::OffchainClient: Cache<Codec, Claim>,
    K: KeyType + 'static,
{
    async fn create_account_for(&self, key: &<R as System>::AccountId) -> Result<()> {
        client::create_account_for(self, key).await
    }

    async fn add_paperkey(&self) -> Result<Mnemonic> {
        client::add_paperkey::<_, _, C::KeyType>(self).await
    }

    async fn add_key(&self, key: &<R as System>::AccountId) -> Result<()> {
        client::add_key(self, key).await
    }

    async fn remove_key(&self, key: &<R as System>::AccountId) -> Result<()> {
        client::remove_key(self, key).await
    }

    async fn change_password(&self, password: &SecretString) -> Result<()> {
        client::change_password(self, password).await
    }

    async fn update_password(&mut self) -> Result<()> {
        client::update_password(self).await
    }

    async fn subscribe_password_changes(&self) -> Result<EventSubscription<R>> {
        client::subscribe_password_changes(self).await
    }

    async fn fetch_uid(&self, key: &<R as System>::AccountId) -> Result<Option<R::Uid>> {
        client::fetch_uid(self, key).await
    }

    async fn fetch_keys(
        &self,
        uid: R::Uid,
        hash: Option<<R as System>::Hash>,
    ) -> Result<Vec<<R as System>::AccountId>> {
        client::fetch_keys(self, uid, hash).await
    }

    async fn fetch_account(&self, uid: R::Uid) -> Result<R::IdAccountData> {
        client::fetch_account(self, uid).await
    }

    async fn prove_identity(&self, service: Service) -> Result<String> {
        client::prove_identity(self, service).await
    }

    async fn revoke_identity(&self, service: Service) -> Result<()> {
        client::revoke_identity(self, service).await
    }

    async fn identity(&self, uid: R::Uid) -> Result<Vec<IdentityInfo>> {
        client::identity(self, uid).await
    }

    async fn resolve(&self, service: &Service) -> Result<R::Uid> {
        client::resolve(self, service).await
    }
}
