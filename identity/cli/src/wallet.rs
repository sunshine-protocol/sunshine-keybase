use crate::{async_trait, AbstractClient, Command, Error, Identity, Pair, Result, Runtime};
use clap::Clap;
use core::fmt::{Debug, Display};
use identity_client::{resolve, Identifier};
use substrate_subxt::balances::{Balances, TransferCallExt, TransferEventExt};
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;
use substrate_subxt::{SignedExtension, SignedExtra};

#[derive(Clone, Debug, Clap)]
pub struct WalletBalanceCommand {
    pub identifier: Option<String>,
}

#[async_trait]
impl<T: Runtime + Identity + Balances, P: Pair> Command<T, P> for WalletBalanceCommand
where
    <T as System>::AccountId: Ss58Codec,
    <T as Identity>::IdAccountData: Debug,
{
    async fn exec(&self, client: &dyn AbstractClient<T, P>) -> Result<()> {
        let identifier: Option<Identifier<T>> = if let Some(identifier) = &self.identifier {
            Some(identifier.parse()?)
        } else {
            None
        };
        let uid = resolve(client, identifier).await?;
        let account = client.fetch_account(uid).await?;
        println!("{:?}", account);
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct WalletTransferCommand {
    pub identifier: String,
    pub amount: u128,
}

#[async_trait]
impl<T: Runtime + Identity + Balances, P: Pair> Command<T, P> for WalletTransferCommand
where
    <T as System>::AccountId: Ss58Codec + Into<<T as System>::Address>,
    <<<T as Runtime>::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned:
        Send + Sync,
    <T as Balances>::Balance: From<u128> + Display,
{
    async fn exec(&self, client: &dyn AbstractClient<T, P>) -> Result<()> {
        let identifier: Identifier<T> = self.identifier.parse()?;
        let signer = client.signer().await?;
        let uid = resolve(client, Some(identifier)).await?;
        let keys = client.fetch_keys(uid, None).await?;
        let event = client
            .subxt()
            .transfer_and_watch(&*signer, &keys[0].clone().into(), self.amount.into())
            .await?
            .transfer()
            .map_err(|_| Error::TransferEventDecode)?
            .ok_or(Error::TransferEventFind)?;
        println!("transfered {} to {}", event.amount, event.to.to_string());
        Ok(())
    }
}
