use codec::Encode;
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt::{module, Call};

#[module]
pub trait Faucet: System {}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct MintCall<'a, T: Faucet> {
    account: &'a <T as System>::AccountId,
}

#[cfg(test)]
mod tests {
    use sp_core::sr25519::Pair;
    use sp_core::Pair as _;
    use substrate_subxt::{sp_core, ClientBuilder, PairSigner, Signer};
    use test_client::faucet::MintCallExt;
    use test_client::mock::test_node;
    use test_client::Runtime;

    #[async_std::test]
    #[ignore]
    async fn test_mint() {
        let (node, _) = test_node();
        let client = ClientBuilder::<Runtime>::new()
            .set_client(node)
            .build()
            .await
            .unwrap();
        //let hans = PairSigner::<Runtime, _>::new(Pair::generate().0);
        let hans = PairSigner::<Runtime, _>::new(test_client::mock::AccountKeyring::Alice.pair());

        client
            .mint_and_watch(&hans, hans.account_id())
            .await
            .unwrap();
    }
}
