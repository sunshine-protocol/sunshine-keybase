use crate::utils::async_std::sync::RwLock;
use std::marker::PhantomData;
use substrate_subxt::Runtime;
use sunshine_client_utils::Result;
use sunshine_faucet_client::{Faucet as SunshineFaucet, FaucetClient};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct Faucet<'a, C, R>
where
    C: FaucetClient<R> + Send + Sync,
    R: Runtime + SunshineFaucet,
{
    client: &'a RwLock<C>,
    _runtime: PhantomData<R>,
}

impl<'a, C, R> Faucet<'a, C, R>
where
    C: FaucetClient<R> + Send + Sync,
    R: Runtime + SunshineFaucet,
{
    pub fn new(client: &'a RwLock<C>) -> Self {
        Self {
            client,
            _runtime: PhantomData,
        }
    }

    pub async fn mint(&self) -> Result<R::Balance> {
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
