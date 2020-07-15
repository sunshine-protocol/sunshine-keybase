use crate::{ask_for_new_password, Error, Result};
use clap::Clap;
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;
use substrate_subxt::Runtime;
use sunshine_core::Ss58;
use sunshine_identity_client::{Identity, IdentityClient};

#[derive(Clone, Debug, Clap)]
pub struct AccountCreateCommand {
    pub device: String,
}

impl AccountCreateCommand {
    pub async fn exec<R: Runtime + Identity, C: IdentityClient<R>>(
        &self,
        client: &C,
    ) -> Result<(), C::Error>
    where
        <R as System>::AccountId: Ss58Codec,
    {
        let device: Ss58<R> = self.device.parse()?;
        client
            .create_account_for(&device.0)
            .await
            .map_err(Error::Client)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct AccountPasswordCommand;

impl AccountPasswordCommand {
    pub async fn exec<R: Runtime + Identity, C: IdentityClient<R>>(
        &self,
        client: &C,
    ) -> Result<(), C::Error> {
        let password = ask_for_new_password(8)?;
        client
            .change_password(&password)
            .await
            .map_err(Error::Client)?;
        Ok(())
    }
}
