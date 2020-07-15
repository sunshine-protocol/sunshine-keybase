use crate::{
    ask_for_new_password, async_trait, Command, Error, Identity, IdentityClient, Result, Runtime,
};
use clap::Clap;
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;
use sunshine_core::Ss58;

#[derive(Clone, Debug, Clap)]
pub struct AccountCreateCommand {
    pub device: String,
}

#[async_trait]
impl<T: Runtime + Identity, C: IdentityClient<T>> Command<T, C> for AccountCreateCommand
where
    <T as System>::AccountId: Ss58Codec,
{
    async fn exec(&self, client: &mut C) -> Result<(), C::Error> {
        let device: Ss58<T> = self.device.parse()?;
        client
            .create_account_for(&device.0)
            .await
            .map_err(Error::Client)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct AccountPasswordCommand;

#[async_trait]
impl<T: Runtime + Identity, C: IdentityClient<T>> Command<T, C> for AccountPasswordCommand {
    async fn exec(&self, client: &mut C) -> Result<(), C::Error> {
        let password = ask_for_new_password(8)?;
        client
            .change_password(&password)
            .await
            .map_err(Error::Client)?;
        Ok(())
    }
}
