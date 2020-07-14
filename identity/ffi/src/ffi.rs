use crate::error::{Error, Result};
use client::AbstractClient;
use client::{Identifier, Identity, Service, Ss58, Suri};
use keystore::{
    bip39::{Language, Mnemonic},
    DeviceKey, Password,
};
use std::marker::PhantomData;
use substrate_subxt::{
    balances::{AccountData, Balances, TransferCallExt, TransferEventExt},
    sp_core::{crypto::Ss58Codec, Pair},
    system::System,
    Runtime, SignedExtension, SignedExtra,
};

macro_rules! make {
    ($name: ident) => {
        #[derive(Copy, Clone, Debug)]
        pub struct $name<'a, C, R, P>
        where
            C: AbstractClient<R, P> + Send + Sync,
            R: Runtime + Identity,
            P: Pair,
        {
            client: &'a C,
            _runtime: PhantomData<R>,
            _pair: PhantomData<P>,
        }

        impl<'a, C, R, P> $name<'a, C, R, P>
        where
            C: AbstractClient<R, P> + Send + Sync,
            R: Runtime + Identity,
            P: Pair,
        {
            pub fn new(client: &'a C) -> Self {
                Self {
                    client,
                    _runtime: PhantomData,
                    _pair: PhantomData,
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

impl<'a, C, R, P> Key<'a, C, R, P>
where
    C: AbstractClient<R, P> + Send + Sync,
    R: Runtime + Identity,
    P: Pair,
    P::Seed: Into<[u8; 32]>,
{
    pub async fn set(
        &self,
        password: impl Into<&str>,
        suri: Option<impl Into<&str>>,
        paperkey: Option<impl Into<&str>>,
    ) -> Result<String> {
        let suri = suri.and_then(|v| v.into().parse::<Suri<P>>().ok());
        let paperkey =
            paperkey.and_then(|p| Mnemonic::from_phrase(p.into(), Language::English).ok());
        let dk = if let Some(mnemonic) = paperkey {
            Some(DeviceKey::from_mnemonic(&mnemonic).map_err(|_| Error::InvalidMnemonic)?)
        } else if let Some(seed) = suri {
            Some(DeviceKey::from_seed(seed.0.into()))
        } else {
            None
        };
        let password = Password::from(password.into().to_owned());
        if password.expose_secret().len() < 8 {
            return Err(Error::PasswordTooShort);
        }
        let dk = if let Some(dk) = dk {
            dk
        } else {
            DeviceKey::generate().await
        };
        let device_id = self.client.set_device_key(&dk, &password, false).await?;
        Ok(device_id.to_string())
    }

    pub async fn lock(&self) -> Result<bool> {
        self.client.lock().await?;
        Ok(true)
    }

    pub async fn unlock(&self, password: impl Into<&str>) -> Result<bool> {
        let password = Password::from(password.into().to_owned());
        self.client.unlock(&password).await?;
        Ok(true)
    }
}

impl<'a, C, R, P> Account<'a, C, R, P>
where
    C: AbstractClient<R, P> + Send + Sync,
    R: Runtime + Identity,
    P: Pair,
    <R as System>::AccountId: Ss58Codec,
{
    pub async fn create(&self, device: impl Into<&str>) -> Result<bool> {
        let device: Ss58<R> = device.into().parse()?;
        self.client.create_account_for(&device.0).await?;
        Ok(true)
    }

    pub async fn change_password(&self, password: impl Into<&str>) -> Result<bool> {
        let password = Password::from(password.into().to_owned());
        if password.expose_secret().len() < 8 {
            return Err(Error::PasswordTooShort);
        }
        self.client.change_password(&password).await?;
        Ok(true)
    }
}

impl<'a, C, R, P> Device<'a, C, R, P>
where
    C: AbstractClient<R, P> + Send + Sync,
    R: Runtime + Identity,
    P: Pair,
    <R as System>::AccountId: Ss58Codec,
{
    pub async fn current(&self) -> Result<String> {
        let signer = self.client.signer().await?;
        Ok(signer.account_id().to_string())
    }

    pub async fn has_device_key(&self) -> Result<bool> {
        let v = self.client.has_device_key().await;
        Ok(v)
    }

    pub async fn add(&self, device: impl Into<&str>) -> Result<bool> {
        let device: Ss58<R> = device.into().parse()?;
        self.client.add_key(&device.0).await?;
        Ok(true)
    }

    pub async fn remove(&self, device: impl Into<&str>) -> Result<bool> {
        let device: Ss58<R> = device.into().parse()?;
        self.client.remove_key(&device.0).await?;
        Ok(true)
    }

    pub async fn list(&self, identifier: impl Into<&str>) -> Result<Vec<String>> {
        let identifier: Identifier<R> = identifier.into().parse()?;
        let uid = client::resolve(self.client, Some(identifier)).await?;
        let list = self
            .client
            .fetch_keys(uid, None)
            .await?
            .into_iter()
            .map(|key| key.to_ss58check())
            .collect();
        Ok(list)
    }

    pub async fn paperkey(&self) -> Result<String> {
        let mnemonic = self.client.add_paperkey().await?;
        Ok(mnemonic.into_phrase())
    }
}

impl<'a, C, R, P> ID<'a, C, R, P>
where
    C: AbstractClient<R, P> + Send + Sync,
    R: Runtime + Identity,
    P: Pair,
    <R as System>::AccountId: Ss58Codec,
{
    pub async fn resolve(&self, identifier: impl Into<&str>) -> Result<String> {
        let identifier: Identifier<R> = identifier.into().parse()?;
        let uid = client::resolve(self.client, Some(identifier)).await?;
        Ok(uid.to_string())
    }

    pub async fn list(&self, identifier: impl Into<&str>) -> Result<Vec<String>> {
        let identifier: Identifier<R> = identifier.into().parse()?;
        let uid = client::resolve(self.client, Some(identifier)).await?;
        let list = self
            .client
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
        let proof = self.client.prove_identity(service).await?;
        Ok(vec![instructions, proof])
    }

    pub async fn revoke(&self, service: impl Into<&str>) -> Result<bool> {
        let service: Service = service.into().parse()?;
        self.client.revoke_identity(service).await?;
        Ok(true)
    }
}

impl<'a, C, R, P> Wallet<'a, C, R, P>
where
    C: AbstractClient<R, P> + Send + Sync,
    R: Runtime + Balances,
    R: Identity<IdAccountData = AccountData<<R as Balances>::Balance>>,
    P: Pair,
    <R as System>::AccountId: Ss58Codec + Into<<R as System>::Address>,
    <<<R as Runtime>::Extra as SignedExtra<R>>::Extra as SignedExtension>::AdditionalSigned:
        Send + Sync,
{
    pub async fn balance(&self, identifier: impl Into<&str>) -> Result<R::Balance> {
        let identifier: Identifier<R> = identifier.into().parse()?;
        let uid = client::resolve(self.client, Some(identifier)).await?;
        let account = self.client.fetch_account(uid).await?;
        Ok(account.free)
    }

    pub async fn transfer(
        &self,
        identifier: impl Into<&str>,
        amount: impl Into<R::Balance>,
    ) -> Result<R::Balance> {
        let identifier: Identifier<R> = identifier.into().parse()?;
        let signer = self.client.signer().await?;
        let uid = client::resolve(self.client, Some(identifier)).await?;
        let keys = self.client.fetch_keys(uid, None).await?;
        self.client
            .subxt()
            .transfer_and_watch(&*signer, &keys[0].clone().into(), amount.into())
            .await?
            .transfer()
            .map_err(|_| Error::TransferEventDecode)?
            .ok_or(Error::TransferEventFind)?;

        self.balance(uid.to_string().as_str()).await
    }
}

#[cfg(feature = "faucet")]
make!(Faucet);

#[cfg(feature = "faucet")]
impl<'a, C, R, P> Faucet<'a, C, R, P>
where
    C: AbstractClient<R, P> + Send + Sync,
    R: Runtime + Balances + Identity + faucet_client::Faucet,
    P: Pair,
    <R as System>::AccountId: Ss58Codec + Into<<R as System>::Address>,
    <<<R as Runtime>::Extra as SignedExtra<R>>::Extra as SignedExtension>::AdditionalSigned:
        Send + Sync,
{
    pub async fn mint(&self, identifier: impl Into<&str>) -> Result<R::Balance> {
        let identifier: Ss58<R> = identifier.into().parse()?;
        let mint = faucet_client::mint(self.client.subxt(), &identifier.0).await?;
        if let Some(minted) = mint {
            Ok(minted.amount)
        } else {
            Err(Error::FailedToMint)
        }
    }
}
