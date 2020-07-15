use crate::error::{Error, Result};
use clap::Clap;
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;
use substrate_subxt::Runtime;
use sunshine_core::ChainClient;
use sunshine_identity_client::{
    resolve, Error as IdentityError, Identifier, Identity, IdentityClient, Service,
};

#[derive(Clone, Debug, Clap)]
pub struct IdListCommand {
    pub identifier: Option<String>,
}

impl IdListCommand {
    pub async fn exec<R: Runtime + Identity, C: IdentityClient<R>>(
        &self,
        client: &C,
    ) -> Result<(), C::Error>
    where
        <R as System>::AccountId: Ss58Codec,
        <C as ChainClient<R>>::Error: From<IdentityError>,
    {
        let identifier: Option<Identifier<R>> = if let Some(identifier) = &self.identifier {
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

impl IdProveCommand {
    pub async fn exec<R: Runtime + Identity, C: IdentityClient<R>>(
        &self,
        client: &C,
    ) -> Result<(), C::Error>
    where
        <C as ChainClient<R>>::Error: From<IdentityError>,
    {
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

impl IdRevokeCommand {
    pub async fn exec<R: Runtime + Identity, C: IdentityClient<R>>(
        &self,
        client: &C,
    ) -> Result<(), C::Error>
    where
        <C as ChainClient<R>>::Error: From<IdentityError>,
    {
        client
            .revoke_identity(self.service.clone())
            .await
            .map_err(Error::Client)?;
        Ok(())
    }
}
