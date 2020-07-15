use async_trait::async_trait;
use clap::Clap;
use substrate_subxt::{balances::Balances, Runtime};
use sunshine_faucet_client::{Faucet, FaucetClient};

#[async_trait]
pub trait Command<T: Runtime + Faucet, C: FaucetClient<T>>: Send + Sync {
    async fn exec(&self, client: &mut C) -> Result<(), C::Error>;
}

#[derive(Clone, Debug, Clap)]
pub struct MintCommand;

#[async_trait]
impl<T: Runtime + Faucet, C: FaucetClient<T>> Command<T, C> for MintCommand
where
    <T as Balances>::Balance: std::fmt::Display,
{
    async fn exec(&self, client: &mut C) -> Result<(), C::Error> {
        let amount = client.mint().await?.unwrap().amount;
        println!("minted {} tokens into your account", amount);
        Ok(())
    }
}
