use codec::{Decode, Encode};
use substrate_subxt::balances::{Balances, BalancesEventsDecoder};
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt::{module, Call, Event};

#[module]
pub trait Faucet: Balances + System {}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct MintCall<'a, T: Faucet> {
    pub account: &'a <T as System>::AccountId,
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct MintedEvent<T: Faucet> {
    pub account: <T as System>::AccountId,
    pub amount: <T as Balances>::Balance,
}

#[cfg(test)]
mod tests {
    use sp_core::sr25519::Pair;
    use sp_core::Pair as _;
    use substrate_subxt::{sp_core, ClientBuilder, PairSigner, Signer};
    use test_client::faucet::{MintCall, MintedEventExt};
    use test_client::identity::Identity;
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

        let call = MintCall {
            account: hans.account_id(),
        };
        let unsigned = client
            .create_unsigned(call, hans.account_id(), None)
            .await
            .unwrap();
        let mut decoder = client.events_decoder::<MintCall<Runtime>>();
        decoder.register_type_size::<<Runtime as Identity>::Uid>("Uid");

        client
            .submit_and_watch_extrinsic(unsigned, decoder)
            .await
            .unwrap()
            .minted()
            .unwrap();
    }
}
