use async_trait::async_trait;
use codec::{Decode, Encode};
use identity_client::{Identity, IdentityEventsDecoder};
use substrate_subxt::balances::{Balances, BalancesEventsDecoder};
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt::{module, Call, Event, Runtime, SignedExtension, SignedExtra};
use sunshine_core::ChainClient;

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
pub trait FaucetClient<T: Runtime + Faucet>: ChainClient<T> {
    async fn mint(&self) -> Result<Option<MintedEvent<T>>, Self::Error>;
}

#[async_trait]
impl<T, C> FaucetClient<T> for C
where
    T: Runtime + Faucet,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
{
    async fn mint(&self) -> Result<Option<MintedEvent<T>>, C::Error> {
        let account = self.chain_signer()?.account_id();
        let call = MintCall { account };
        let unsigned = self
            .chain_client()
            .create_unsigned(call, account, None)
            .await?;
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
    use sp_core::sr25519::Pair;
    use sp_core::Pair as _;
    use substrate_subxt::{sp_core, ClientBuilder, PairSigner, Signer};
    use test_client::faucet;
    use test_client::mock::test_node;
    use test_client::Runtime;

    #[async_std::test]
    async fn test_mint() {
        let (node, _) = test_node();
        let client = ClientBuilder::<Runtime>::new()
            .set_client(node)
            .build()
            .await
            .unwrap();
        let hans = PairSigner::<Runtime, _>::new(Pair::generate().0);
        faucet::mint(&client, hans.account_id()).await.unwrap();
    }
}
