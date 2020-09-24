use clap::Clap;
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;
use sunshine_cli_utils::{Node, Result};
use sunshine_identity_client::{resolve, Identifier, Identity, IdentityClient, Service};

#[derive(Clone, Debug, Clap)]
pub struct IdListCommand {
    pub identifier: Option<String>,
}

impl IdListCommand {
    pub async fn exec<N: Node, C: IdentityClient<N>>(&self, client: &C) -> Result<()>
    where
        N::Runtime: Identity,
        <N::Runtime as System>::AccountId: Ss58Codec,
    {
        let identifier: Option<Identifier<N::Runtime>> = if let Some(identifier) = &self.identifier
        {
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
    pub async fn exec<N: Node, C: IdentityClient<N>>(&self, client: &C) -> Result<()>
    where
        N::Runtime: Identity,
    {
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
    pub async fn exec<N: Node, C: IdentityClient<N>>(&self, client: &C) -> Result<()>
    where
        N::Runtime: Identity,
    {
        client.revoke_identity(self.service.clone()).await?;
        Ok(())
    }
}
