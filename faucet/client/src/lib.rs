use parity_scale_codec::{Decode, Encode};
use substrate_subxt::balances::{Balances, BalancesEventsDecoder};
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt::{module, Call, Event, Runtime, SignedExtension, SignedExtra};
use sunshine_client_utils::{async_trait, Client, Result};
use sunshine_identity_client::{Identity, IdentityEventsDecoder};

#[module]
pub trait Faucet: Identity + Balances + System {}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct MintCall<'a, T: Faucet> {
    pub account: &'a <T as System>::AccountId,
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct MintedEvent<T: Faucet> {
    pub account: <T as System>::AccountId,
    pub amount: <T as Balances>::Balance,
}

#[async_trait]
pub trait FaucetClient<T: Runtime + Faucet>: Client<T> {
    async fn mint(&self) -> Result<Option<MintedEvent<T>>>;
}

#[async_trait]
impl<T, C> FaucetClient<T> for C
where
    T: Runtime + Faucet,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<T>,
{
    async fn mint(&self) -> Result<Option<MintedEvent<T>>> {
        let account = self.signer()?.account_id();
        let call = MintCall { account };
        let unsigned = self.chain_client().create_unsigned(call)?;
        let decoder = self.chain_client().events_decoder::<MintCall<T>>();
        let event = self
            .chain_client()
            .submit_and_watch_extrinsic(unsigned, decoder)
            .await?
            .minted()?;
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use test_client::faucet::FaucetClient;
    use test_client::mock::{test_node, AccountKeyring, Client};

    #[async_std::test]
    async fn test_mint() {
        let (node, _node_tmp) = test_node();
        let client = Client::mock(&node, AccountKeyring::Eve).await;
        client.mint().await.unwrap();
    }
}
