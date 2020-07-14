use async_trait::async_trait;
pub use keybase_keystore::{bip39, Error, Mask, NotEnoughEntropyError, Password};
use keybase_keystore::{bip39::Mnemonic, DeviceKey};
use sp_core::Pair;
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::marker::PhantomData;
use std::path::PathBuf;
use substrate_subxt::{
    sp_core, sp_runtime, system::System, PairSigner, Runtime, SignedExtension, SignedExtra,
};
use sunshine_core::{ChainSigner, InvalidSuri, OffchainSigner, SecretString};

pub struct Keystore<T: Runtime, P: Pair<Seed = [u8; 32]>> {
    keystore: keybase_keystore::KeyStore,
    signer: Option<PairSigner<T, P>>,
}

impl<T: Runtime, P: Pair<Seed = [u8; 32]>> Keystore<T, P>
where
    T::AccountId: Into<T::Address>,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    T::Signature: From<P::Signature>,
    <T::Signature as Verify>::Signer: From<P::Public> + IdentifyAccount<AccountId = T::AccountId>,
{
    pub async fn open(path: PathBuf) -> Result<Self, Error> {
        let keystore = keybase_keystore::KeyStore::open(path).await?;
        let signer = if keystore.is_initialized().await {
            let key = Key::from_seed(keystore.device_key().await?);
            Some(key.to_signer())
        } else {
            None
        };
        Ok(Self { keystore, signer })
    }
}

#[async_trait]
impl<T: Runtime, P: Pair<Seed = [u8; 32]>> sunshine_core::Keystore<T> for Keystore<T, P>
where
    T::AccountId: Into<T::Address>,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    T::Signature: From<P::Signature>,
    <T::Signature as Verify>::Signer: From<P::Public> + IdentifyAccount<AccountId = T::AccountId>,
{
    type Key = Key<T, P>;
    type Error = Error;

    fn chain_signer(&self) -> Option<&(dyn ChainSigner<T> + Send + Sync)> {
        self.signer.as_ref().map(|s| s as _)
    }

    fn offchain_signer(&self) -> Option<&dyn OffchainSigner<T>> {
        self.signer.as_ref().map(|s| s as _)
    }

    async fn set_device_key(
        &mut self,
        device_key: &Self::Key,
        password: &SecretString,
        force: bool,
    ) -> Result<(), Error> {
        self.keystore
            .initialize(&device_key.key, &Password::new(password), force)
            .await?;
        self.signer = Some(device_key.to_signer());
        Ok(())
    }

    async fn lock(&mut self) -> Result<(), Self::Error> {
        self.signer = None;
        Ok(self.keystore.lock().await?)
    }

    async fn unlock(&mut self, password: &SecretString) -> Result<(), Self::Error> {
        let key = Key::from_seed(self.keystore.unlock(&Password::new(password)).await?);
        self.signer = Some(key.to_signer());
        Ok(())
    }

    async fn gen(&self) -> u16 {
        self.keystore.gen().await
    }

    async fn change_password_mask(&self, password: &SecretString) -> Result<[u8; 32], Self::Error> {
        Ok(*self
            .keystore
            .change_password_mask(&Password::new(password))
            .await?)
    }

    async fn apply_mask(&self, mask: &[u8; 32], gen: u16) -> Result<(), Self::Error> {
        self.keystore.apply_mask(&Mask::new(*mask), gen).await
    }
}

pub struct Key<T: Runtime, P: Pair<Seed = [u8; 32]>> {
    _marker: PhantomData<(T, P)>,
    key: DeviceKey,
}

impl<T: Runtime, P: Pair<Seed = [u8; 32]>> Key<T, P> {
    fn from_seed(key: DeviceKey) -> Self {
        Self {
            _marker: PhantomData,
            key,
        }
    }

    fn to_signer(&self) -> PairSigner<T, P>
    where
        T::AccountId: Into<T::Address>,
        <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
        T::Signature: From<P::Signature>,
        <T::Signature as Verify>::Signer:
            From<P::Public> + IdentifyAccount<AccountId = T::AccountId>,
    {
        PairSigner::new(P::from_seed(self.key.expose_secret()))
    }
}

#[async_trait]
impl<T: Runtime, P: Pair<Seed = [u8; 32]>> sunshine_core::Key<T> for Key<T, P>
where
    <T::Signature as Verify>::Signer: From<P::Public> + IdentifyAccount<AccountId = T::AccountId>,
{
    async fn generate() -> Self {
        Self::from_seed(DeviceKey::generate().await)
    }

    fn from_mnemonic(mnemonic: &Mnemonic) -> Result<Self, NotEnoughEntropyError> {
        Ok(Self::from_seed(DeviceKey::from_mnemonic(mnemonic)?))
    }

    fn from_suri(suri: &str) -> Result<Self, InvalidSuri> {
        let (_, seed) = P::from_string_with_seed(suri, None).map_err(InvalidSuri)?;
        Ok(Self::from_seed(DeviceKey::from_seed(seed.unwrap().into())))
    }

    fn to_account_id(&self) -> <T as System>::AccountId {
        let public = P::from_seed(self.key.expose_secret()).public();
        let signer: <T::Signature as Verify>::Signer = public.into();
        signer.into_account()
    }
}
