use crate::{async_trait, ChainClient, Command, Error, Identity, IdentityClient, Result, Runtime};
use clap::Clap;
use identity_client::{resolve, Identifier};
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;
use sunshine_core::Ss58;

#[derive(Clone, Debug, Clap)]
pub struct DeviceAddCommand {
    pub device: String,
}

#[async_trait]
impl<T: Runtime + Identity, C: IdentityClient<T>> Command<T, C> for DeviceAddCommand
where
    <T as System>::AccountId: Ss58Codec,
{
    async fn exec(&self, client: &mut C) -> Result<(), C::Error> {
        let device: Ss58<T> = self.device.parse()?;
        client.add_key(&device.0).await.map_err(Error::Client)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct DeviceRemoveCommand {
    pub device: String,
}

#[async_trait]
impl<T: Runtime + Identity, C: IdentityClient<T>> Command<T, C> for DeviceRemoveCommand
where
    <T as System>::AccountId: Ss58Codec,
    <C as ChainClient<T>>::Error: From<identity_client::Error>,
{
    async fn exec(&self, client: &mut C) -> Result<(), C::Error> {
        let device: Ss58<T> = self.device.parse()?;
        client.remove_key(&device.0).await.map_err(Error::Client)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct DeviceListCommand {
    pub identifier: Option<String>,
}

#[async_trait]
impl<T: Runtime + Identity, C: IdentityClient<T>> Command<T, C> for DeviceListCommand
where
    <T as System>::AccountId: Ss58Codec,
    <C as ChainClient<T>>::Error: From<identity_client::Error>,
{
    async fn exec(&self, client: &mut C) -> Result<(), C::Error> {
        let identifier: Option<Identifier<T>> = if let Some(identifier) = &self.identifier {
            Some(identifier.parse()?)
        } else {
            None
        };
        let uid = resolve(client, identifier).await.map_err(Error::Client)?;
        for key in client.fetch_keys(uid, None).await.map_err(Error::Client)? {
            println!("{}", key.to_ss58check());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct DevicePaperkeyCommand;

#[async_trait]
impl<T: Runtime + Identity, C: IdentityClient<T>> Command<T, C> for DevicePaperkeyCommand
where
    <C as ChainClient<T>>::Error: From<identity_client::Error>,
{
    async fn exec(&self, client: &mut C) -> Result<(), C::Error> {
        println!("Generating a new paper key.");
        let mnemonic = client.add_paperkey().await.map_err(Error::Client)?;
        println!("Here is your secret paper key phrase:");
        let words: Vec<_> = mnemonic.phrase().split(' ').collect();
        println!();
        println!("{}", words[..12].join(" "));
        println!("{}", words[12..].join(" "));
        println!();
        println!("Write it down and keep somewhere safe.");
        Ok(())
    }
}
