use async_trait::async_trait;
use keybase_keystore::{bip39::Mnemonic, NotEnoughEntropyError};
pub use secrecy::SecretString;
use sp_core::crypto::{Pair, PublicError, SecretStringError, Ss58Codec};
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::str::FromStr;
pub use substrate_subxt::Signer as ChainSigner;
use substrate_subxt::{
    sp_core, sp_runtime, system::System, PairSigner, Runtime, SignedExtension, SignedExtra,
};
use thiserror::Error;

#[async_trait]
pub trait ChainClient<T: Runtime>: Send + Sync {
    type Keystore: Keystore<T>;
    type OffchainClient: Send + Sync;
    type Error: std::error::Error
        + Send
        + From<<Self::Keystore as Keystore<T>>::Error>
        + From<substrate_subxt::Error>
        + From<codec::Error>
        + From<libipld::error::Error>;

    fn keystore(&self) -> &Self::Keystore;

    fn chain_client(&self) -> &substrate_subxt::Client<T>;
    fn chain_signer(&self) -> Result<&(dyn ChainSigner<T> + Send + Sync), Self::Error> {
        Ok(self.keystore().chain_signer()?)
    }

    fn offchain_client(&self) -> &Self::OffchainClient;
    fn offchain_signer(&self) -> Result<&dyn OffchainSigner<T>, Self::Error> {
        Ok(self.keystore().offchain_signer()?)
    }
}

#[async_trait]
pub trait Keystore<T: Runtime>: Send + Sync {
    type Key: Key<T>;
    type Error: std::error::Error;

    fn chain_signer(&self) -> Result<&(dyn ChainSigner<T> + Send + Sync), Self::Error>;
    fn offchain_signer(&self) -> Result<&dyn OffchainSigner<T>, Self::Error>;

    async fn set_key(
        &mut self,
        key: &Self::Key,
        password: &SecretString,
        force: bool,
    ) -> Result<(), Self::Error>;
    async fn lock(&mut self) -> Result<(), Self::Error>;
    async fn unlock(&mut self, password: &SecretString) -> Result<(), Self::Error>;

    async fn gen(&self) -> u16;
    async fn change_password_mask(&self, password: &SecretString) -> Result<[u8; 32], Self::Error>;
    async fn apply_mask(&self, mask: &[u8; 32], gen: u16) -> Result<(), Self::Error>;
}

#[async_trait]
pub trait Key<T: Runtime>: Sized + Send + Sync {
    async fn generate() -> Self;
    fn from_mnemonic(mnemonic: &Mnemonic) -> Result<Self, NotEnoughEntropyError>;
    fn from_suri(suri: &str) -> Result<Self, InvalidSuri>;
    fn to_account_id(&self) -> <T as System>::AccountId;
}

pub trait OffchainSigner<T: Runtime>: Send + Sync {
    fn sign(&self, payload: &[u8]) -> T::Signature;
}

impl<T: Runtime, P: Pair> OffchainSigner<T> for PairSigner<T, P>
where
    T::AccountId: Into<T::Address>,
    T::Signature: From<P::Signature>,
    <T::Signature as Verify>::Signer: From<P::Public> + IdentifyAccount<AccountId = T::AccountId>,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
{
    fn sign(&self, payload: &[u8]) -> T::Signature {
        self.signer().sign(payload).into()
    }
}

#[derive(Debug, Error)]
#[error("Invalid suri encoded key pair: {0:?}")]
pub struct InvalidSuri(pub SecretStringError);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ss58<T: System>(pub T::AccountId);

#[derive(Debug, Error)]
#[error("Invalid ss58 encoded public key: {0:?}")]
pub struct InvalidSs58(pub PublicError);

impl<T: System> FromStr for Ss58<T>
where
    T::AccountId: Ss58Codec,
{
    type Err = InvalidSs58;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            <T::AccountId as Ss58Codec>::from_string(string).map_err(InvalidSs58)?,
        ))
    }
}
