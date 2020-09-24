use parity_scale_codec::{Decode, Encode};
use substrate_subxt::balances::{Balances, BalancesEventsDecoder};
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt::{module, Call, Event, Runtime, SignedExtension, SignedExtra};
use sunshine_client_utils::{async_trait, Client, Node, Result};
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
pub trait FaucetClient<N: Node>: Client<N>
where
    N::Runtime: Faucet,
{
    async fn mint(&self) -> Result<Option<MintedEvent<N::Runtime>>>;
}

#[async_trait]
impl<N, C> FaucetClient<N> for C
where
    N: Node,
    N::Runtime: Faucet,
    <<<N::Runtime as Runtime>::Extra as SignedExtra<N::Runtime>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<N>,
{
    async fn mint(&self) -> Result<Option<MintedEvent<N::Runtime>>> {
        let account = self.signer()?.account_id();
        let call = MintCall { account };
        let unsigned = self.chain_client().create_unsigned(call)?;
        let decoder = self.chain_client().events_decoder::<MintCall<N::Runtime>>();
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
    use test_client::client::{AccountKeyring, Node as _};
    use test_client::faucet::FaucetClient;
    use test_client::{Client, Node};

    #[async_std::test]
    async fn test_mint() {
        let node = Node::new_mock();
        let (client, _tmp) = Client::mock(&node, AccountKeyring::Eve).await;
        client.mint().await.unwrap();
    }
}
