use crate::error::{Error, Result};
use ffi_utils::async_std::sync::RwLock;
use std::marker::PhantomData;
use substrate_subxt::{
    balances::{AccountData, Balances, TransferCallExt, TransferEventExt},
    sp_core::crypto::Ss58Codec,
    system::System,
    Runtime, SignedExtension, SignedExtra,
};
use sunshine_core::bip39::{Language, Mnemonic};
use sunshine_core::{ExposeSecret, Keystore, SecretString, Ss58};
#[cfg(feature = "faucet")]
use sunshine_faucet_client::{Faucet as SunshineFaucet, FaucetClient};
use sunshine_identity_client::{
    resolve, Error as IdentityError, Identifier, Identity, IdentityClient, Service,
};

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
    C::Error: From<IdentityError>,
    R: Runtime + Identity,
{
    pub async fn set(
        &self,
        password: impl Into<&str>,
        suri: Option<impl Into<&str>>,
        paperkey: Option<impl Into<&str>>,
    ) -> Result<String, C::Error> {
        use sunshine_core::Key;

        let password = SecretString::new(password.into().to_string());
        if password.expose_secret().len() < 8 {
            return Err(Error::PasswordTooShort);
        }
        let dk = if let Some(paperkey) = paperkey {
            let mnemonic = Mnemonic::from_phrase(paperkey.into(), Language::English)
                .map_err(|_| Error::InvalidMnemonic)?;
            <C::Keystore as Keystore<R>>::Key::from_mnemonic(&mnemonic)
                .map_err(|_| Error::InvalidMnemonic)?
        } else if let Some(suri) = suri {
            <C::Keystore as Keystore<R>>::Key::from_suri(suri.into())?
        } else {
            <C::Keystore as Keystore<R>>::Key::generate().await
        };

        self.client
            .write()
            .await
            .keystore_mut()
            .set_device_key(&dk, &password, false)
            .await
            .map_err(|e| Error::Client(e.into()))?;
        Ok(dk.to_account_id().to_string())
    }

    pub async fn lock(&self) -> Result<bool, C::Error> {
        self.client
            .write()
            .await
            .keystore_mut()
            .lock()
            .await
            .map_err(|e| Error::Client(e.into()))?;
        Ok(true)
    }

    pub async fn unlock(&self, password: impl Into<&str>) -> Result<bool, C::Error> {
        let password = SecretString::new(password.into().to_string());
        self.client
            .write()
            .await
            .keystore_mut()
            .unlock(&password)
            .await
            .map_err(|e| Error::Client(e.into()))?;
        Ok(true)
    }
}

impl<'a, C, R> Account<'a, C, R>
where
    C: IdentityClient<R> + Send + Sync,
    C::Error: From<IdentityError>,
    R: Runtime + Identity,
    <R as System>::AccountId: Ss58Codec,
{
    pub async fn create(&self, device: impl Into<&str>) -> Result<bool, C::Error> {
        let device: Ss58<R> = device.into().parse()?;
        self.client
            .read()
            .await
            .create_account_for(&device.0)
            .await
            .map_err(Error::Client)?;
        Ok(true)
    }

    pub async fn change_password(&self, password: impl Into<&str>) -> Result<bool, C::Error> {
        let password = SecretString::new(password.into().to_string());
        if password.expose_secret().len() < 8 {
            return Err(Error::PasswordTooShort);
        }
        self.client
            .read()
            .await
            .change_password(&password)
            .await
            .map_err(Error::Client)?;
        Ok(true)
    }
}

impl<'a, C, R> Device<'a, C, R>
where
    C: IdentityClient<R> + Send + Sync,
    C::Error: From<IdentityError>,
    R: Runtime + Identity,
    <R as System>::AccountId: Ss58Codec,
{
    pub async fn current(&self) -> Result<String, C::Error> {
        let client = self.client.read().await;
        let signer = client.chain_signer().map_err(Error::Client)?;
        Ok(signer.account_id().to_string())
    }

    pub async fn has_device_key(&self) -> Result<bool, C::Error> {
        Ok(self.client.read().await.keystore().chain_signer().is_some())
    }

    pub async fn add(&self, device: impl Into<&str>) -> Result<bool, C::Error> {
        let device: Ss58<R> = device.into().parse()?;
        self.client
            .read()
            .await
            .add_key(&device.0)
            .await
            .map_err(Error::Client)?;
        Ok(true)
    }

    pub async fn remove(&self, device: impl Into<&str>) -> Result<bool, C::Error> {
        let device: Ss58<R> = device.into().parse()?;
        self.client
            .read()
            .await
            .remove_key(&device.0)
            .await
            .map_err(Error::Client)?;
        Ok(true)
    }

    pub async fn list(&self, identifier: impl Into<&str>) -> Result<Vec<String>, C::Error> {
        let client = self.client.read().await;
        let identifier: Identifier<R> = identifier.into().parse()?;
        let uid = resolve(&*client, Some(identifier))
            .await
            .map_err(Error::Client)?;
        let list = client
            .fetch_keys(uid, None)
            .await
            .map_err(Error::Client)?
            .into_iter()
            .map(|key| key.to_ss58check())
            .collect();
        Ok(list)
    }

    pub async fn paperkey(&self) -> Result<String, C::Error> {
        let mnemonic = self
            .client
            .read()
            .await
            .add_paperkey()
            .await
            .map_err(Error::Client)?;
        Ok(mnemonic.into_phrase())
    }
}

impl<'a, C, R> ID<'a, C, R>
where
    C: IdentityClient<R> + Send + Sync,
    C::Error: From<IdentityError>,
    R: Runtime + Identity,
    <R as System>::AccountId: Ss58Codec,
{
    pub async fn resolve(&self, identifier: impl Into<&str>) -> Result<String, C::Error> {
        let identifier: Identifier<R> = identifier.into().parse()?;
        let client = self.client.read().await;
        let uid = resolve(&*client, Some(identifier))
            .await
            .map_err(Error::Client)?;
        Ok(uid.to_string())
    }

    pub async fn list(&self, identifier: impl Into<&str>) -> Result<Vec<String>, C::Error> {
        let client = self.client.read().await;
        let identifier: Identifier<R> = identifier.into().parse()?;
        let uid = resolve(&*client, Some(identifier))
            .await
            .map_err(Error::Client)?;
        let list = client
            .identity(uid)
            .await
            .map_err(Error::Client)?
            .into_iter()
            .map(|id| id.to_string())
            .collect();
        Ok(list)
    }

    pub async fn prove(&self, service: impl Into<&str>) -> Result<Vec<String>, C::Error> {
        let service: Service = service.into().parse()?;
        let instructions = service.cli_instructions();
        let proof = self
            .client
            .read()
            .await
            .prove_identity(service)
            .await
            .map_err(Error::Client)?;
        Ok(vec![instructions, proof])
    }

    pub async fn revoke(&self, service: impl Into<&str>) -> Result<bool, C::Error> {
        let service: Service = service.into().parse()?;
        self.client
            .read()
            .await
            .revoke_identity(service)
            .await
            .map_err(Error::Client)?;
        Ok(true)
    }
}

impl<'a, C, R> Wallet<'a, C, R>
where
    C: IdentityClient<R> + Send + Sync,
    C::Error: From<IdentityError>,
    R: Runtime + Balances,
    R: Identity<IdAccountData = AccountData<<R as Balances>::Balance>>,
    <R as System>::AccountId: Ss58Codec + Into<<R as System>::Address>,
    <<<R as Runtime>::Extra as SignedExtra<R>>::Extra as SignedExtension>::AdditionalSigned:
        Send + Sync,
{
    pub async fn balance(&self, identifier: impl Into<&str>) -> Result<R::Balance, C::Error> {
        let client = self.client.read().await;
        let identifier: Identifier<R> = identifier.into().parse()?;
        let uid = resolve(&*client, Some(identifier))
            .await
            .map_err(Error::Client)?;
        let account = client.fetch_account(uid).await.map_err(Error::Client)?;
        Ok(account.free)
    }

    pub async fn transfer(
        &self,
        identifier: impl Into<&str>,
        amount: impl Into<R::Balance>,
    ) -> Result<R::Balance, C::Error> {
        let client = self.client.read().await;
        let identifier: Identifier<R> = identifier.into().parse()?;
        let signer = client.chain_signer().map_err(Error::Client)?;
        let uid = resolve(&*client, Some(identifier))
            .await
            .map_err(Error::Client)?;
        let keys = client.fetch_keys(uid, None).await.map_err(Error::Client)?;
        client
            .chain_client()
            .transfer_and_watch(&*signer, &keys[0].clone().into(), amount.into())
            .await
            .map_err(|e| Error::Client(e.into()))?
            .transfer()
            .map_err(|_| Error::TransferEventDecode)?
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
    pub async fn mint(&self) -> Result<R::Balance, C::Error> {
        let event = self
            .client
            .read()
            .await
            .mint()
            .await
            .map_err(Error::Client)?;
        if let Some(minted) = event {
            Ok(minted.amount)
        } else {
            Err(Error::FailedToMint)
        }
    }
}
