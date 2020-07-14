use crate::{async_trait, ChainClient, Command, Error, Identity, IdentityClient, Result, Runtime};
use clap::Clap;
use identity_client::{resolve, Identifier, Service};
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;

#[derive(Clone, Debug, Clap)]
pub struct IdListCommand {
    pub identifier: Option<String>,
}

#[async_trait]
impl<T: Runtime + Identity, C: IdentityClient<T>> Command<T, C> for IdListCommand
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
        println!("Your user id is {}", uid);
        for id in client.identity(uid).await.map_err(Error::Client)? {
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
impl<T: Runtime + Identity, C: IdentityClient<T>> Command<T, C> for IdProveCommand
where
    <C as ChainClient<T>>::Error: From<identity_client::Error>,
{
    async fn exec(&self, client: &mut C) -> Result<(), C::Error> {
        println!("Claiming {}...", self.service);
        let instructions = self.service.cli_instructions();
        let proof = client
            .prove_identity(self.service.clone())
            .await
            .map_err(Error::Client)?;
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
impl<T: Runtime + Identity, C: IdentityClient<T>> Command<T, C> for IdRevokeCommand
where
    <C as ChainClient<T>>::Error: From<identity_client::Error>,
{
    async fn exec(&self, client: &mut C) -> Result<(), C::Error> {
        client
            .revoke_identity(self.service.clone())
            .await
            .map_err(Error::Client)?;
        Ok(())
    }
}
