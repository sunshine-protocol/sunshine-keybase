use crate::{async_trait, AbstractClient, Command, Identity, Pair, Result, Runtime};
use clap::Clap;
use identity_client::{resolve, Identifier, Ss58};
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;

#[derive(Clone, Debug, Clap)]
pub struct DeviceAddCommand {
    pub device: String,
}

#[async_trait]
impl<T: Runtime + Identity, P: Pair> Command<T, P> for DeviceAddCommand
where
    <T as System>::AccountId: Ss58Codec,
{
    async fn exec(&self, client: &dyn AbstractClient<T, P>) -> Result<()> {
        let device: Ss58<T> = self.device.parse()?;
        client.add_key(&device.0).await?;
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct DeviceRemoveCommand {
    pub device: String,
}

#[async_trait]
impl<T: Runtime + Identity, P: Pair> Command<T, P> for DeviceRemoveCommand
where
    <T as System>::AccountId: Ss58Codec,
{
    async fn exec(&self, client: &dyn AbstractClient<T, P>) -> Result<()> {
        let device: Ss58<T> = self.device.parse()?;
        client.remove_key(&device.0).await?;
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct DeviceListCommand {
    pub identifier: Option<String>,
}

#[async_trait]
impl<T: Runtime + Identity, P: Pair> Command<T, P> for DeviceListCommand
where
    <T as System>::AccountId: Ss58Codec,
{
    async fn exec(&self, client: &dyn AbstractClient<T, P>) -> Result<()> {
        let identifier: Option<Identifier<T>> = if let Some(identifier) = &self.identifier {
            Some(identifier.parse()?)
        } else {
            None
        };
        let uid = resolve(client, identifier).await?;
        for key in client.fetch_keys(uid, None).await? {
            println!("{}", key.to_ss58check());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct DevicePaperkeyCommand;

#[async_trait]
impl<T: Runtime + Identity, P: Pair> Command<T, P> for DevicePaperkeyCommand {
    async fn exec(&self, client: &dyn AbstractClient<T, P>) -> Result<()> {
        println!("Generating a new paper key.");
        let mnemonic = client.add_paperkey().await?;
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
