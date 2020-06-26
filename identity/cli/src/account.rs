use crate::{
    ask_for_new_password, async_trait, AbstractClient, Command, Identity, Pair, Result, Runtime,
};
use clap::Clap;
use client_identity::Ss58;
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;

#[derive(Clone, Debug, Clap)]
pub struct AccountCreateCommand {
    pub device: String,
}

#[async_trait]
impl<T: Runtime + Identity, P: Pair> Command<T, P> for AccountCreateCommand
where
    <T as System>::AccountId: Ss58Codec,
{
    async fn exec(&self, client: &dyn AbstractClient<T, P>) -> Result<()> {
        let device: Ss58<T> = self.device.parse()?;
        client.create_account_for(&device.0).await?;
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct AccountPasswordCommand;

#[async_trait]
impl<T: Runtime + Identity, P: Pair> Command<T, P> for AccountPasswordCommand {
    async fn exec(&self, client: &dyn AbstractClient<T, P>) -> Result<()> {
        let password = ask_for_new_password()?;
        client.change_password(&password).await?;
        Ok(())
    }
}
