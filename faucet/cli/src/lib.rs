use clap::Clap;
use substrate_subxt::balances::Balances;
use sunshine_client_utils::{Node, Result};
use sunshine_faucet_client::{Faucet, FaucetClient};

#[derive(Clone, Debug, Clap)]
pub struct MintCommand;

impl MintCommand {
    pub async fn exec<N: Node, C: FaucetClient<N>>(&self, client: &C) -> Result<()>
    where
        N::Runtime: Faucet,
        <N::Runtime as Balances>::Balance: std::fmt::Display,
    {
        let amount = client.mint().await?.unwrap().amount;
        println!("minted {} tokens into your account", amount);
        Ok(())
    }
}
