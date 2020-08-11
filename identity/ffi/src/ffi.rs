use std::marker::PhantomData;
use substrate_subxt::{
    balances::{AccountData, Balances, TransferCallExt, TransferEventExt},
    sp_core::crypto::Ss58Codec,
    system::System,
    Runtime, SignedExtension, SignedExtra,
};
use sunshine_client_utils::crypto::{
    bip39::Mnemonic,
    keychain::TypedPair,
    keystore::Keystore,
    secrecy::{ExposeSecret, SecretString},
    ss58::Ss58,
};
use sunshine_client_utils::Result;
#[cfg(feature = "faucet")]
use sunshine_faucet_client::{Faucet as SunshineFaucet, FaucetClient};
use sunshine_ffi_utils::async_std::sync::RwLock;
use sunshine_identity_client::{resolve, Identifier, Identity, IdentityClient, Service};
use thiserror::Error;

macro_rules! make {
    ($name: ident) => {
        #[derive(Clone, Debug)]
        pub struct $name<'a, C, R>
        where
            C: IdentityClient<R> + Send + Sync,
            R: Runtime + Identity,
        {
            client: &'a RwLock<C>,
            _runtime: PhantomData<R>,
        }

        impl<'a, C, R> $name<'a, C, R>
        where
            C: IdentityClient<R> + Send + Sync,
            R: Runtime + Identity,
        {
            pub fn new(client: &'a RwLock<C>) -> Self {
                Self {
                    client,
                    _runtime: PhantomData,
                }
            }
        }
    };
    ($($name: ident),+) => {
        $(
            make!($name);
        )+
    }
}

make!(Key, Account, Device, ID, Wallet);

impl<'a, C, R> Key<'a, C, R>
where
    C: IdentityClient<R> + Send + Sync,
    R: Runtime + Identity,
{
    pub async fn set(
        &self,
        password: impl Into<&str>,
        suri: Option<impl Into<&str>>,
        paperkey: Option<impl Into<&str>>,
    ) -> Result<String> {
        let password = SecretString::new(password.into().to_string());
        if password.expose_secret().len() < 8 {
            return Err(Error::PasswordTooShort.into());
        }
        let dk = if let Some(paperkey) = paperkey {
            let mnemonic = Mnemonic::parse(paperkey.into())?;
            TypedPair::<C::KeyType>::from_mnemonic(&mnemonic)?
        } else if let Some(suri) = suri {
            TypedPair::<C::KeyType>::from_suri(suri.into())?
        } else {
            TypedPair::<C::KeyType>::generate().await
        };

        self.client
            .write()
            .await
            .set_key(dk, &password, false)
            .await?;
        let account_id = self.client.read().await.signer()?.account_id().to_string();
        Ok(account_id)
    }

    pub async fn lock(&self) -> Result<bool> {
        self.client.write().await.lock().await?;
        Ok(true)
    }

    pub async fn unlock(&self, password: impl Into<&str>) -> Result<bool> {
        let password = SecretString::new(password.into().to_string());
        self.client.write().await.unlock(&password).await?;
        Ok(true)
    }
}

impl<'a, C, R> Account<'a, C, R>
where
    C: IdentityClient<R> + Send + Sync,
    R: Runtime + Identity,
    <R as System>::AccountId: Ss58Codec,
{
    pub async fn create(&self, device: impl Into<&str>) -> Result<bool> {
        let device: Ss58<R> = device.into().parse()?;
        self.client
            .read()
            .await
            .create_account_for(&device.0)
            .await?;
        Ok(true)
    }

    pub async fn change_password(&self, password: impl Into<&str>) -> Result<bool> {
        let password = SecretString::new(password.into().to_string());
        if password.expose_secret().len() < 8 {
            return Err(Error::PasswordTooShort.into());
        }
        self.client.read().await.change_password(&password).await?;
        Ok(true)
    }
}

impl<'a, C, R> Device<'a, C, R>
where
    C: IdentityClient<R> + Send + Sync,
    R: Runtime + Identity,
    <R as System>::AccountId: Ss58Codec,
{
    pub async fn current(&self) -> Result<String> {
        let client = self.client.read().await;
        let signer = client.signer()?;
        Ok(signer.account_id().to_string())
    }

    pub async fn has_device_key(&self) -> Result<bool> {
        Ok(self.client.read().await.keystore().is_initialized().await?)
    }

    pub async fn add(&self, device: impl Into<&str>) -> Result<bool> {
        let device: Ss58<R> = device.into().parse()?;
        self.client.read().await.add_key(&device.0).await?;
        Ok(true)
    }

    pub async fn remove(&self, device: impl Into<&str>) -> Result<bool> {
        let device: Ss58<R> = device.into().parse()?;
        self.client.read().await.remove_key(&device.0).await?;
        Ok(true)
    }

    pub async fn list(&self, identifier: impl Into<&str>) -> Result<Vec<String>> {
        let client = self.client.read().await;
        let identifier: Identifier<R> = identifier.into().parse()?;
        let uid = resolve(&*client, Some(identifier)).await?;
        let list = client
            .fetch_keys(uid, None)
            .await?
            .into_iter()
            .map(|key| key.to_ss58check())
            .collect();
        Ok(list)
    }

    pub async fn paperkey(&self) -> Result<String> {
        let mnemonic = self.client.read().await.add_paperkey().await?;
        Ok(mnemonic.as_str().into())
    }
}

impl<'a, C, R> ID<'a, C, R>
where
    C: IdentityClient<R> + Send + Sync,
    R: Runtime + Identity,
    <R as System>::AccountId: Ss58Codec,
{
    pub async fn resolve(&self, identifier: impl Into<&str>) -> Result<String> {
        let identifier: Identifier<R> = identifier.into().parse()?;
        let client = self.client.read().await;
        let uid = resolve(&*client, Some(identifier)).await?;
        Ok(uid.to_string())
    }

    pub async fn list(&self, identifier: impl Into<&str>) -> Result<Vec<String>> {
        let client = self.client.read().await;
        let identifier: Identifier<R> = identifier.into().parse()?;
        let uid = resolve(&*client, Some(identifier)).await?;
        let list = client
            .identity(uid)
            .await?
            .into_iter()
            .map(|id| id.to_string())
            .collect();
        Ok(list)
    }

    pub async fn prove(&self, service: impl Into<&str>) -> Result<Vec<String>> {
        let service: Service = service.into().parse()?;
        let instructions = service.cli_instructions();
        let proof = self.client.read().await.prove_identity(service).await?;
        Ok(vec![instructions, proof])
    }

    pub async fn revoke(&self, service: impl Into<&str>) -> Result<bool> {
        let service: Service = service.into().parse()?;
        self.client.read().await.revoke_identity(service).await?;
        Ok(true)
    }
}

impl<'a, C, R> Wallet<'a, C, R>
where
    C: IdentityClient<R> + Send + Sync,
    R: Runtime + Balances,
    R: Identity<IdAccountData = AccountData<<R as Balances>::Balance>>,
    <R as System>::AccountId: Ss58Codec + Into<<R as System>::Address>,
    <<<R as Runtime>::Extra as SignedExtra<R>>::Extra as SignedExtension>::AdditionalSigned:
        Send + Sync,
{
    pub async fn balance(&self, identifier: impl Into<&str>) -> Result<R::Balance> {
        let client = self.client.read().await;
        let identifier: Identifier<R> = identifier.into().parse()?;
        let uid = resolve(&*client, Some(identifier)).await?;
        let account = client.fetch_account(uid).await?;
        Ok(account.free)
    }

    pub async fn transfer(
        &self,
        identifier: impl Into<&str>,
        amount: impl Into<R::Balance>,
    ) -> Result<R::Balance> {
        let client = self.client.read().await;
        let identifier: Identifier<R> = identifier.into().parse()?;
        let signer = client.chain_signer()?;
        let uid = resolve(&*client, Some(identifier)).await?;
        let keys = client.fetch_keys(uid, None).await?;
        client
            .chain_client()
            .transfer_and_watch(&signer, &keys[0].clone().into(), amount.into())
            .await?
            .transfer()?
            .ok_or(Error::TransferEventFind)?;

        self.balance(uid.to_string().as_str()).await
    }
}

#[cfg(feature = "faucet")]
make!(Faucet);

#[cfg(feature = "faucet")]
impl<'a, C, R> Faucet<'a, C, R>
where
    C: IdentityClient<R> + FaucetClient<R> + Send + Sync,
    R: Runtime + Identity + SunshineFaucet,
{
    pub async fn mint(&self) -> Result<R::Balance> {
        let event = self.client.read().await.mint().await?;
        if let Some(minted) = event {
            Ok(minted.amount)
        } else {
            Err(Error::FailedToMint.into())
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("password too short")]
    PasswordTooShort,
    #[error("transfer event not found")]
    TransferEventFind,
    #[cfg(feature = "faucet")]
    #[error("failed to mint")]
    FailedToMint,
}
