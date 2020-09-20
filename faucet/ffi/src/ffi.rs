use crate::utils::async_std::sync::RwLock;
use std::marker::PhantomData;
use substrate_subxt::balances::Balances;
use sunshine_client_utils::{Node, Result};
use sunshine_faucet_client::{Faucet as SunshineFaucet, FaucetClient};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct Faucet<'a, C, N>
where
    N: Node,
    N::Runtime: SunshineFaucet,
    C: FaucetClient<N> + Send + Sync,
{
    client: &'a RwLock<C>,
    _runtime: PhantomData<N>,
}

impl<'a, C, N> Faucet<'a, C, N>
where
    N: Node,
    N::Runtime: SunshineFaucet,
    C: FaucetClient<N> + Send + Sync,
{
    pub fn new(client: &'a RwLock<C>) -> Self {
        Self {
            client,
            _runtime: PhantomData,
        }
    }

    pub async fn mint(&self) -> Result<<N::Runtime as Balances>::Balance> {
        let event = self.client.read().await.mint().await?;
        if let Some(minted) = event {
            Ok(minted.amount)
        } else {
            Err(Error::FailedToMint.into())
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to mint")]
    FailedToMint,
}
