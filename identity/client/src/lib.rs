mod claim;
mod client;
mod error;
mod github;
mod service;
mod subxt;
mod utils;

pub use claim::{Claim, IdentityInfo, IdentityStatus};
pub use service::{Service, ServiceParseError};
pub use subxt::*;
pub use utils::{resolve, Identifier};

use codec::Decode;
use libipld::cache::Cache;
use libipld::cbor::DagCborCodec;
use sp_core::crypto::{Pair, Ss58Codec};
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::convert::TryInto;
use substrate_subxt::{
    sp_core, sp_runtime, system::System, EventSubscription, Runtime, SignedExtension, SignedExtra,
};
use sunshine_client_utils::{
    async_trait,
    crypto::{bip39::Mnemonic, keychain::KeyType, secrecy::SecretString},
    keystore, Client, Node, OffchainConfig, Result,
};

#[async_trait]
pub trait IdentityClient<N: Node>: Client<N>
where
    N::Runtime: Identity,
{
    async fn create_account_for(&self, key: &<N::Runtime as System>::AccountId) -> Result<()>;
    async fn add_paperkey(&self) -> Result<Mnemonic>;
    async fn add_key(&self, key: &<N::Runtime as System>::AccountId) -> Result<()>;
    async fn remove_key(&self, key: &<N::Runtime as System>::AccountId) -> Result<()>;
    async fn change_password(&self, password: &SecretString) -> Result<()>;
    async fn update_password(&mut self) -> Result<()>;
    async fn subscribe_password_changes(&self) -> Result<EventSubscription<N::Runtime>>;
    async fn fetch_uid(
        &self,
        key: &<N::Runtime as System>::AccountId,
    ) -> Result<Option<<N::Runtime as Identity>::Uid>>;
    async fn fetch_keys(
        &self,
        uid: <N::Runtime as Identity>::Uid,
        hash: Option<<N::Runtime as System>::Hash>,
    ) -> Result<Vec<<N::Runtime as System>::AccountId>>;
    async fn fetch_account(
        &self,
        uid: <N::Runtime as Identity>::Uid,
    ) -> Result<<N::Runtime as Identity>::IdAccountData>;
    async fn prove_identity(&self, service: Service) -> Result<String>;
    async fn revoke_identity(&self, service: Service) -> Result<()>;
    async fn identity(&self, uid: <N::Runtime as Identity>::Uid) -> Result<Vec<IdentityInfo>>;
    async fn resolve(&self, service: &Service) -> Result<<N::Runtime as Identity>::Uid>;
}

#[async_trait]
impl<N, C, K> IdentityClient<N> for C
where
    N: Node,
    N::Runtime: Identity<Gen = u16, Mask = [u8; 32]>,
    <<<N::Runtime as Runtime>::Extra as SignedExtra<N::Runtime>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    <N::Runtime as System>::AccountId: Into<<N::Runtime as System>::Address> + Ss58Codec,
    <N::Runtime as Runtime>::Signature: From<<<C::KeyType as KeyType>::Pair as Pair>::Signature> + Decode,
    <<N::Runtime as Runtime>::Signature as Verify>::Signer: From<<<C::KeyType as KeyType>::Pair as Pair>::Public>
        + TryInto<<<C::KeyType as KeyType>::Pair as Pair>::Public>
        + IdentifyAccount<AccountId = <N::Runtime as System>::AccountId>
        + Clone
        + Send
        + Sync,
    C: Client<N, KeyType = K, Keystore = keystore::Keystore<K>>,
    C::OffchainClient: Cache<OffchainConfig<N>, DagCborCodec, Claim>,
    K: KeyType + 'static,
{
    async fn create_account_for(&self, key: &<N::Runtime as System>::AccountId) -> Result<()> {
        client::create_account_for(self, key).await
    }

    async fn add_paperkey(&self) -> Result<Mnemonic> {
        client::add_paperkey::<_, _, C::KeyType>(self).await
    }

    async fn add_key(&self, key: &<N::Runtime as System>::AccountId) -> Result<()> {
        client::add_key(self, key).await
    }

    async fn remove_key(&self, key: &<N::Runtime as System>::AccountId) -> Result<()> {
        client::remove_key(self, key).await
    }

    async fn change_password(&self, password: &SecretString) -> Result<()> {
        client::change_password(self, password).await
    }

    async fn update_password(&mut self) -> Result<()> {
        client::update_password(self).await
    }

    async fn subscribe_password_changes(&self) -> Result<EventSubscription<N::Runtime>> {
        client::subscribe_password_changes(self).await
    }

    async fn fetch_uid(&self, key: &<N::Runtime as System>::AccountId) -> Result<Option<<N::Runtime as Identity>::Uid>> {
        client::fetch_uid(self, key).await
    }

    async fn fetch_keys(
        &self,
        uid: <N::Runtime as Identity>::Uid,
        hash: Option<<N::Runtime as System>::Hash>,
    ) -> Result<Vec<<N::Runtime as System>::AccountId>> {
        client::fetch_keys(self, uid, hash).await
    }

    async fn fetch_account(&self, uid: <N::Runtime as Identity>::Uid) -> Result<<N::Runtime as Identity>::IdAccountData> {
        client::fetch_account(self, uid).await
    }

    async fn prove_identity(&self, service: Service) -> Result<String> {
        client::prove_identity(self, service).await
    }

    async fn revoke_identity(&self, service: Service) -> Result<()> {
        client::revoke_identity(self, service).await
    }

    async fn identity(&self, uid: <N::Runtime as Identity>::Uid) -> Result<Vec<IdentityInfo>> {
        client::identity(self, uid).await
    }

    async fn resolve(&self, service: &Service) -> Result<<N::Runtime as Identity>::Uid> {
        client::resolve(self, service).await
    }
}
