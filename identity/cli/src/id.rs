use crate::{async_trait, AbstractClient, Command, Identity, Pair, Result, Runtime};
use clap::Clap;
use client_identity::{resolve, Identifier, Service};
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;

#[derive(Clone, Debug, Clap)]
pub struct IdListCommand {
    pub identifier: Option<String>,
}

#[async_trait]
impl<T: Runtime + Identity, P: Pair> Command<T, P> for IdListCommand
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
        println!("Your user id is {}", uid);
        for id in client.identity(uid).await? {
            println!("{}", id);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct IdProveCommand {
    pub service: Service,
}

#[async_trait]
impl<T: Runtime + Identity, P: Pair> Command<T, P> for IdProveCommand {
    async fn exec(&self, client: &dyn AbstractClient<T, P>) -> Result<()> {
        println!("Claiming {}...", self.service);
        let instructions = self.service.cli_instructions();
        let proof = client.prove_identity(self.service.clone()).await?;
        println!("{}", instructions);
        print!("{}", proof);
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct IdRevokeCommand {
    pub service: Service,
}

#[async_trait]
impl<T: Runtime + Identity, P: Pair> Command<T, P> for IdRevokeCommand {
    async fn exec(&self, client: &dyn AbstractClient<T, P>) -> Result<()> {
        client.revoke_identity(self.service.clone()).await?;
        Ok(())
    }
}
