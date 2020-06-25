use codec::Encode;
use substrate_subxt::{module, Call};
use substrate_subxt::system::{System, SystemEventsDecoder};

#[module]
pub trait Faucet: System {}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct MintCall<'a, T: Faucet> {
    account: &'a <T as System>::AccountId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use substrate_subxt::{
        Error,
        PairSigner,
    };
    use sp_keyring::AccountKeyring;

    #[async_std::test]
    async fn test_timestamp_set() {
        env_logger::try_init().ok();
        let alice = PairSigner::<TestRuntime, _>::new(AccountKeyring::Alice.pair());
        let (client, _) = test_client().await;

        client
            .mint_and_watch(&alice, 1)
            .await
            .unwrap();

        /*assert!(
            if let Err(Error::BadOrigin) = res {
                true
            } else {
                false
            }
        );*/
    }
}
