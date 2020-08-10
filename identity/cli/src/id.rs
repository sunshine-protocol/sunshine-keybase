use clap::Clap;
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;
use substrate_subxt::Runtime;
use sunshine_client_utils::Result;
use sunshine_identity_client::{resolve, Identifier, Identity, IdentityClient, Service};

#[derive(Clone, Debug, Clap)]
pub struct IdListCommand {
    pub identifier: Option<String>,
}

impl IdListCommand {
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

impl IdProveCommand {
    pub async fn exec<R: Runtime + Identity, C: IdentityClient<R>>(
        &self,
        client: &C,
    ) -> Result<()> {
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

impl IdRevokeCommand {
    pub async fn exec<R: Runtime + Identity, C: IdentityClient<R>>(
        &self,
        client: &C,
    ) -> Result<()> {
        client.revoke_identity(self.service.clone()).await?;
        Ok(())
    }
}
