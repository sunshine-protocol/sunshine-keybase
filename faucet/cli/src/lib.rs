use clap::Clap;
use substrate_subxt::{balances::Balances, Runtime};
use sunshine_client_utils::Result;
use sunshine_faucet_client::{Faucet, FaucetClient};

#[derive(Clone, Debug, Clap)]
pub struct MintCommand;

impl MintCommand {
    pub async fn exec<R: Runtime + Faucet, C: FaucetClient<R>>(&self, client: &C) -> Result<()>
    where
        <R as Balances>::Balance: std::fmt::Display,
    {
        let amount = client.mint().await?.unwrap().amount;
        println!("minted {} tokens into your account", amount);
        Ok(())
    }
}
