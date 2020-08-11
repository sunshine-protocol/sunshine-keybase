use clap::Clap;
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;
use substrate_subxt::Runtime;
use sunshine_client_utils::crypto::ss58::Ss58;
use sunshine_client_utils::Result;
use sunshine_identity_client::{resolve, Identifier, Identity, IdentityClient};

#[derive(Clone, Debug, Clap)]
pub struct DeviceAddCommand {
    pub device: String,
}

impl DeviceAddCommand {
    pub async fn exec<R: Runtime + Identity, C: IdentityClient<R>>(&self, client: &C) -> Result<()>
    where
        <R as System>::AccountId: Ss58Codec,
    {
        let device: Ss58<R> = self.device.parse()?;
        client.add_key(&device.0).await?;
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct DeviceRemoveCommand {
    pub device: String,
}

impl DeviceRemoveCommand {
    pub async fn exec<R: Runtime + Identity, C: IdentityClient<R>>(&self, client: &C) -> Result<()>
    where
        <R as System>::AccountId: Ss58Codec,
    {
        let device: Ss58<R> = self.device.parse()?;
        client.remove_key(&device.0).await?;
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct DeviceListCommand {
    pub identifier: Option<String>,
}

impl DeviceListCommand {
    pub async fn exec<R: Runtime + Identity, C: IdentityClient<R>>(&self, client: &C) -> Result<()>
    where
        <R as System>::AccountId: Ss58Codec,
    {
        let identifier: Option<Identifier<R>> = if let Some(identifier) = &self.identifier {
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

impl DevicePaperkeyCommand {
    pub async fn exec<R: Runtime + Identity, C: IdentityClient<R>>(
        &self,
        client: &C,
    ) -> Result<()> {
        println!("Generating a new paper key.");
        let mnemonic = client.add_paperkey().await?;
        println!("Here is your secret paper key phrase:");
        let words: Vec<_> = mnemonic.as_str().split(' ').collect();
        println!();
        println!("{}", words[..12].join(" "));
        println!("{}", words[12..].join(" "));
        println!();
        println!("Write it down and keep somewhere safe.");
        Ok(())
    }
}
