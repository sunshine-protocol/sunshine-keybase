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
use sunshine_client_utils::{Node, Result};
use sunshine_ffi_utils::async_std::sync::RwLock;
use sunshine_identity_client::{resolve, Identifier, Identity, IdentityClient, Service};
use thiserror::Error;

macro_rules! make {
    ($name: ident) => {
        #[derive(Clone, Debug)]
        pub struct $name<'a, C, N>
        where
            C: IdentityClient<N> + Send + Sync,
            N: Node,
            N::Runtime: Identity,
        {
            client: &'a RwLock<C>,
            _runtime: PhantomData<N>,
        }

        impl<'a, C, N> $name<'a, C, N>
        where
            C: IdentityClient<N> + Send + Sync,
            N: Node,
            N::Runtime: Identity,
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

impl<'a, C, N> Key<'a, C, N>
where
    N: Node,
    N::Runtime: Identity,
    C: IdentityClient<N> + Send + Sync,
{
    pub async fn exists(&self) -> Result<bool> {
        self.client.read().await.keystore().is_initialized().await
    }

    pub async fn set(
        &self,
        password: &str,
        suri: Option<&str>,
        paperkey: Option<&str>,
    ) -> Result<String> {
        let password = SecretString::new(password.to_string());
        if password.expose_secret().len() < 8 {
            return Err(Error::PasswordTooShort.into());
        }
        let dk = if let Some(paperkey) = paperkey {
            let mnemonic = Mnemonic::parse(paperkey)?;
            TypedPair::<C::KeyType>::from_mnemonic(&mnemonic)?
        } else if let Some(suri) = suri {
            TypedPair::<C::KeyType>::from_suri(suri)?
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

    pub async fn uid(&self) -> Result<String> {
        let client = self.client.read().await;
        let signer = client.signer()?;
        Ok(signer.account_id().to_string())
    }

    pub async fn lock(&self) -> Result<bool> {
        self.client.write().await.lock().await?;
        Ok(true)
    }

    pub async fn unlock(&self, password: &str) -> Result<bool> {
        let password = SecretString::new(password.to_string());
        self.client.write().await.unlock(&password).await?;
        Ok(true)
    }
}

impl<'a, C, N> Account<'a, C, N>
where
    N: Node,
    N::Runtime: Identity,
    C: IdentityClient<N> + Send + Sync,
    <N::Runtime as System>::AccountId: Ss58Codec,
{
    pub async fn create(&self, device: &str) -> Result<bool> {
        let device: Ss58<N::Runtime> = device.parse()?;
        self.client
            .read()
            .await
            .create_account_for(&device.0)
            .await?;
        Ok(true)
    }

    pub async fn change_password(&self, password: &str) -> Result<bool> {
        let password = SecretString::new(password.to_string());
        if password.expose_secret().len() < 8 {
            return Err(Error::PasswordTooShort.into());
        }
        self.client.read().await.change_password(&password).await?;
        Ok(true)
    }
}

impl<'a, C, N> Device<'a, C, N>
where
    N: Node,
    N::Runtime: Identity,
    C: IdentityClient<N> + Send + Sync,
    <N::Runtime as System>::AccountId: Ss58Codec,
{
    pub async fn current(&self) -> Result<String> {
        let client = self.client.read().await;
        let signer = client.signer()?;
        Ok(signer.account_id().to_string())
    }

    pub async fn has_device_key(&self) -> Result<bool> {
        Ok(self.client.read().await.keystore().is_initialized().await?)
    }

    pub async fn add(&self, device: &str) -> Result<bool> {
        let device: Ss58<N::Runtime> = device.parse()?;
        self.client.read().await.add_key(&device.0).await?;
        Ok(true)
    }

    pub async fn remove(&self, device: &str) -> Result<bool> {
        let device: Ss58<N::Runtime> = device.parse()?;
        self.client.read().await.remove_key(&device.0).await?;
        Ok(true)
    }

    pub async fn list(&self, identifier: &str) -> Result<Vec<String>> {
        let client = self.client.read().await;
        let identifier: Identifier<N::Runtime> = identifier.parse()?;
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

impl<'a, C, N> ID<'a, C, N>
where
    N: Node,
    N::Runtime: Identity,
    C: IdentityClient<N> + Send + Sync,
    <N::Runtime as System>::AccountId: Ss58Codec,
{
    pub async fn resolve(&self, identifier: &str) -> Result<String> {
        let identifier: Identifier<N::Runtime> = identifier.parse()?;
        let client = self.client.read().await;
        let uid = resolve(&*client, Some(identifier)).await?;
        Ok(uid.to_string())
    }

    pub async fn list(&self, identifier: &str) -> Result<Vec<String>> {
        let client = self.client.read().await;
        let identifier: Identifier<N::Runtime> = identifier.parse()?;
        let uid = resolve(&*client, Some(identifier)).await?;
        let list = client
            .identity(uid)
            .await?
            .into_iter()
            .map(|id| id.to_string())
            .collect();
        Ok(list)
    }

    pub async fn prove(&self, service: &str) -> Result<Vec<String>> {
        let service: Service = service.parse()?;
        let instructions = service.cli_instructions();
        let proof = self.client.read().await.prove_identity(service).await?;
        Ok(vec![instructions, proof])
    }

    pub async fn revoke(&self, service: &str) -> Result<bool> {
        let service: Service = service.parse()?;
        self.client.read().await.revoke_identity(service).await?;
        Ok(true)
    }
}

impl<'a, C, N> Wallet<'a, C, N>
where
    N: Node,
    N::Runtime: Identity + Balances,
    C: IdentityClient<N> + Send + Sync,
    N::Runtime: Identity<IdAccountData = AccountData<<N::Runtime as Balances>::Balance>>,
    <N::Runtime as System>::AccountId: Ss58Codec + Into<<N::Runtime as System>::Address>,
    <<<N::Runtime as Runtime>::Extra as SignedExtra<N::Runtime>>::Extra as SignedExtension>::AdditionalSigned:
        Send + Sync,
{
    pub async fn balance(&self, identifier: Option<&str>) -> Result<<N::Runtime as Balances>::Balance> {
        let client = self.client.read().await;
        let account_id: Identifier<N::Runtime> = if let Some(identifier) = identifier {
            identifier.parse()?
        } else {
            Identifier::Account(client.signer()?.account_id().clone())
        };
        let uid = resolve(&*client, Some(account_id)).await?;
        let account = client.fetch_account(uid).await?;
        Ok(account.free)
    }

    pub async fn transfer(
        &self,
        identifier: &str,
        amount: impl Into<<N::Runtime as Balances>::Balance>,
    ) -> Result<<N::Runtime as Balances>::Balance> {
        let client = self.client.read().await;
        let identifier: Identifier<N::Runtime> = identifier.parse()?;
        let signer = client.chain_signer()?;
        let uid = resolve(&*client, Some(identifier)).await?;
        let keys = client.fetch_keys(uid, None).await?;
        client
            .chain_client()
            .transfer_and_watch(&signer, &keys[0].clone().into(), amount.into())
            .await?
            .transfer()?
            .ok_or(Error::TransferEventFind)?;

        self.balance(None).await
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("password too short")]
    PasswordTooShort,
    #[error("transfer event not found")]
    TransferEventFind,
}
