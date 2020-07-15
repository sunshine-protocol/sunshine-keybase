use crate::error::{Error, Result};
use clap::Clap;
use core::fmt::{Debug, Display};
use substrate_subxt::balances::{AccountData, Balances, TransferCallExt, TransferEventExt};
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;
use substrate_subxt::{Runtime, SignedExtension, SignedExtra};
use sunshine_core::ChainClient;
use sunshine_identity_client::{
    resolve, Error as IdentityError, Identifier, Identity, IdentityClient,
};

#[derive(Clone, Debug, Clap)]
pub struct WalletBalanceCommand {
    pub identifier: Option<String>,
}

impl WalletBalanceCommand {
    pub async fn exec<R: Runtime + Identity + Balances, C: IdentityClient<R>>(
        &self,
        client: &C,
    ) -> Result<(), C::Error>
    where
        <R as System>::AccountId: Ss58Codec,
        R: Identity<IdAccountData = AccountData<<R as Balances>::Balance>>,
        <C as ChainClient<R>>::Error: From<IdentityError>,
    {
        let identifier: Option<Identifier<R>> = if let Some(identifier) = &self.identifier {
            Some(identifier.parse()?)
        } else {
            None
        };
        let uid = resolve(client, identifier).await.map_err(Error::Client)?;
        let account = client.fetch_account(uid).await.map_err(Error::Client)?;
        println!("{:?}", account.free);
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct WalletTransferCommand {
    pub identifier: String,
    pub amount: u128,
}

impl WalletTransferCommand {
    pub async fn exec<R: Runtime + Identity + Balances, C: IdentityClient<R>>(
        &self,
        client: &C,
    ) -> Result<(), C::Error>
    where
        <R as System>::AccountId: Ss58Codec + Into<<R as System>::Address>,
        <<<R as Runtime>::Extra as SignedExtra<R>>::Extra as SignedExtension>::AdditionalSigned:
            Send + Sync,
        <R as Balances>::Balance: From<u128> + Display,
        <C as ChainClient<R>>::Error: From<IdentityError>,
    {
        let identifier: Identifier<R> = self.identifier.parse()?;
        let uid = resolve(client, Some(identifier))
            .await
            .map_err(Error::Client)?;
        let keys = client.fetch_keys(uid, None).await.map_err(Error::Client)?;
        let signer = client.chain_signer().map_err(Error::Client)?;
        let event = client
            .chain_client()
            .transfer_and_watch(signer, &keys[0].clone().into(), self.amount.into())
            .await
            .map_err(|e| Error::Client(e.into()))?
            .transfer()
            .map_err(|_| Error::TransferEventDecode)?
            .ok_or(Error::TransferEventFind)?;
        println!("transfered {} to {}", event.amount, event.to.to_string());
        Ok(())
    }
}
