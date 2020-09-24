use clap::Clap;
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;
use sunshine_cli_utils::client::crypto::ss58::Ss58;
use sunshine_cli_utils::{ask_for_new_password, Node, Result};
use sunshine_identity_client::{Identity, IdentityClient};

#[derive(Clone, Debug, Clap)]
pub struct AccountCreateCommand {
    pub device: String,
}

impl AccountCreateCommand {
    pub async fn exec<N: Node, C: IdentityClient<N>>(&self, client: &C) -> Result<()>
    where
        N::Runtime: Identity,
        <N::Runtime as System>::AccountId: Ss58Codec,
    {
        let device: Ss58<N::Runtime> = self.device.parse()?;
        client.create_account_for(&device.0).await?;
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct AccountPasswordCommand;

impl AccountPasswordCommand {
    pub async fn exec<N: Node, C: IdentityClient<N>>(&self, client: &C) -> Result<()>
    where
        N::Runtime: Identity,
    {
        let password = ask_for_new_password(8)?;
        client.change_password(&password).await?;
        Ok(())
    }
}
