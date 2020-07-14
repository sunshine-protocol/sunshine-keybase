use crate::{async_trait, ChainClient, Command, Error, Identity, IdentityClient, Result, Runtime};
use clap::Clap;
use core::fmt::{Debug, Display};
use identity_client::{resolve, Identifier};
use substrate_subxt::balances::{AccountData, Balances, TransferCallExt, TransferEventExt};
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::system::System;
use substrate_subxt::{SignedExtension, SignedExtra};

#[derive(Clone, Debug, Clap)]
pub struct WalletBalanceCommand {
    pub identifier: Option<String>,
}

#[async_trait]
impl<T: Runtime + Balances, C: IdentityClient<T>> Command<T, C> for WalletBalanceCommand
where
    <T as System>::AccountId: Ss58Codec,
    T: Identity<IdAccountData = AccountData<<T as Balances>::Balance>>,
    <C as ChainClient<T>>::Error: From<identity_client::Error>,
{
    async fn exec(&self, client: &mut C) -> Result<(), C::Error> {
        let identifier: Option<Identifier<T>> = if let Some(identifier) = &self.identifier {
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

#[async_trait]
impl<T: Runtime + Identity + Balances, C: IdentityClient<T>> Command<T, C> for WalletTransferCommand
where
    <T as System>::AccountId: Ss58Codec + Into<<T as System>::Address>,
    <<<T as Runtime>::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned:
        Send + Sync,
    <T as Balances>::Balance: From<u128> + Display,
    <C as ChainClient<T>>::Error: From<identity_client::Error>,
{
    async fn exec(&self, client: &mut C) -> Result<(), C::Error> {
        let identifier: Identifier<T> = self.identifier.parse()?;
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
