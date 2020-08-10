use clap::Clap;
use core::fmt::{Debug, Display};
use substrate_subxt::balances::{AccountData, Balances, TransferCallExt, TransferEventExt};
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;
use substrate_subxt::{Runtime, SignedExtension, SignedExtra};
use sunshine_client_utils::Result;
use sunshine_identity_client::{resolve, Identifier, Identity, IdentityClient};
use thiserror::Error;

#[derive(Clone, Debug, Clap)]
pub struct WalletBalanceCommand {
    pub identifier: Option<String>,
}

impl WalletBalanceCommand {
    pub async fn exec<R: Runtime + Identity + Balances, C: IdentityClient<R>>(
        &self,
        client: &C,
    ) -> Result<()>
    where
        <R as System>::AccountId: Ss58Codec,
        R: Identity<IdAccountData = AccountData<<R as Balances>::Balance>>,
    {
        let identifier: Option<Identifier<R>> = if let Some(identifier) = &self.identifier {
            Some(identifier.parse()?)
        } else {
            None
        };
        let uid = resolve(client, identifier).await?;
        let account = client.fetch_account(uid).await?;
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
    ) -> Result<()>
    where
        <R as System>::AccountId: Ss58Codec + Into<<R as System>::Address>,
        <<<R as Runtime>::Extra as SignedExtra<R>>::Extra as SignedExtension>::AdditionalSigned:
            Send + Sync,
        <R as Balances>::Balance: From<u128> + Display,
    {
        let identifier: Identifier<R> = self.identifier.parse()?;
        let uid = resolve(client, Some(identifier)).await?;
        let keys = client.fetch_keys(uid, None).await?;
        let signer = client.chain_signer()?;
        let event = client
            .chain_client()
            .transfer_and_watch(&signer, &keys[0].clone().into(), self.amount.into())
            .await?
            .transfer()
            .map_err(|_| TransferEventDecode)?
            .ok_or(TransferEventFind)?;
        println!("transfered {} to {}", event.amount, event.to.to_string());
        Ok(())
    }
}

#[derive(Debug, Error)]
#[error("Failed to decode transfer event")]
pub struct TransferEventDecode;

#[derive(Debug, Error)]
#[error("Failed to find transfer event")]
pub struct TransferEventFind;
