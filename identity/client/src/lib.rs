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

use async_trait::async_trait;
use codec::Decode;
use ipld_block_builder::{Cache, Codec};
use sp_core::crypto::Ss58Codec;
use sp_runtime::traits::{IdentifyAccount, Verify};
use substrate_subxt::{
    sp_core, sp_runtime, system::System, EventSubscription, Runtime, SignedExtension, SignedExtra,
};
use sunshine_core::{bip39::Mnemonic, ChainClient, SecretString};

#[async_trait]
pub trait IdentityClient<T: Runtime + Identity>: ChainClient<T> {
    async fn create_account_for(&self, key: &<T as System>::AccountId) -> Result<(), Self::Error>;
    async fn add_paperkey(&self) -> Result<Mnemonic, Self::Error>;
    async fn add_key(&self, key: &<T as System>::AccountId) -> Result<(), Self::Error>;
    async fn remove_key(&self, key: &<T as System>::AccountId) -> Result<(), Self::Error>;
    async fn change_password(&self, password: &SecretString) -> Result<(), Self::Error>;
    async fn update_password(&mut self) -> Result<(), Self::Error>;
    async fn subscribe_password_changes(&self) -> Result<EventSubscription<T>, Self::Error>;
    async fn fetch_uid(
        &self,
        key: &<T as System>::AccountId,
    ) -> Result<Option<T::Uid>, Self::Error>;
    async fn fetch_keys(
        &self,
        uid: T::Uid,
        hash: Option<<T as System>::Hash>,
    ) -> Result<Vec<<T as System>::AccountId>, Self::Error>;
    async fn fetch_account(&self, uid: T::Uid) -> Result<T::IdAccountData, Self::Error>;
    async fn prove_identity(&self, service: Service) -> Result<String, Self::Error>;
    async fn revoke_identity(&self, service: Service) -> Result<(), Self::Error>;
    async fn identity(&self, uid: T::Uid) -> Result<Vec<IdentityInfo>, Self::Error>;
    async fn resolve(&self, service: &Service) -> Result<T::Uid, Self::Error>;
}

#[async_trait]
impl<T, C> IdentityClient<T> for C
where
    T: Runtime + Identity<Gen = u16, Mask = [u8; 32]>,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
    C::OffchainClient: Cache<Codec, Claim>,
    C::Error: From<Error>,
    T::AccountId: Ss58Codec,
    T::Signature: Decode,
    <T::Signature as Verify>::Signer: IdentifyAccount<AccountId = T::AccountId>,
{
    async fn create_account_for(&self, key: &<T as System>::AccountId) -> Result<(), C::Error> {
        client::create_account_for(self, key).await
    }

    async fn add_paperkey(&self) -> Result<Mnemonic, C::Error> {
        client::add_paperkey(self).await
    }

    async fn add_key(&self, key: &<T as System>::AccountId) -> Result<(), C::Error> {
        client::add_key(self, key).await
    }

    async fn remove_key(&self, key: &<T as System>::AccountId) -> Result<(), C::Error> {
        client::remove_key(self, key).await
    }

    async fn change_password(&self, password: &SecretString) -> Result<(), C::Error> {
        client::change_password(self, password).await
    }

    async fn update_password(&mut self) -> Result<(), C::Error> {
        client::update_password(self).await
    }

    async fn subscribe_password_changes(&self) -> Result<EventSubscription<T>, C::Error> {
        client::subscribe_password_changes(self).await
    }

    async fn fetch_uid(&self, key: &<T as System>::AccountId) -> Result<Option<T::Uid>, C::Error> {
        client::fetch_uid(self, key).await
    }

    async fn fetch_keys(
        &self,
        uid: T::Uid,
        hash: Option<<T as System>::Hash>,
    ) -> Result<Vec<<T as System>::AccountId>, C::Error> {
        client::fetch_keys(self, uid, hash).await
    }

    async fn fetch_account(&self, uid: T::Uid) -> Result<T::IdAccountData, C::Error> {
        client::fetch_account(self, uid).await
    }

    async fn prove_identity(&self, service: Service) -> Result<String, C::Error> {
        client::prove_identity(self, service).await
    }

    async fn revoke_identity(&self, service: Service) -> Result<(), C::Error> {
        client::revoke_identity(self, service).await
    }

    async fn identity(&self, uid: T::Uid) -> Result<Vec<IdentityInfo>, C::Error> {
        client::identity(self, uid).await
    }

    async fn resolve(&self, service: &Service) -> Result<T::Uid, C::Error> {
        client::resolve(self, service).await
    }
}
