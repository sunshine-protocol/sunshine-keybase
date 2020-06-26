use client_identity::{Identity, IdentityEventsDecoder};
use codec::{Decode, Encode};
use substrate_subxt::balances::{Balances, BalancesEventsDecoder};
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt::{module, Call, Error, Event, Runtime, SignedExtension, SignedExtra};

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

pub async fn mint<T: Runtime + Faucet>(
    client: &substrate_subxt::Client<T>,
    account: &<T as System>::AccountId,
) -> Result<Option<MintedEvent<T>>, Error>
where
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
{
    let call = MintCall { account };
    let unsigned = client.create_unsigned(call, account, None).await?;
    let decoder = client.events_decoder::<MintCall<T>>();
    let event = client
        .submit_and_watch_extrinsic(unsigned, decoder)
        .await?
        .minted()?;
    Ok(event)
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
