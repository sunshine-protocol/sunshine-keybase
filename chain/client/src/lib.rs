mod subxt;

pub use subxt::*;

use async_trait::async_trait;
use parity_scale_codec::{Decode, Encode};
use substrate_subxt::{system::System, Runtime, SignedExtension, SignedExtra};
use sunshine_chain_utils::block::GenericBlock;
use sunshine_chain_utils::trie::TreeEncode;
use sunshine_core::ChainClient as Client;
use thiserror::Error;

/*pub struct BlockSubscription<T: Runtime + Chain, B: Decode> {
    _marker: PhantomData<B>,
    client: substrate_subxt::Client<T>,
    subscription: EventSubscription<T>,
    chain_id: T::ChainId,
    offchain_client:
}*/

#[async_trait]
pub trait ChainClient<T: Runtime + Chain>: Client<T> {
    async fn create_chain(&self) -> Result<T::ChainId, Self::Error>;
    async fn author_block<B: Encode + ?Sized + Send + Sync>(
        &self,
        chain_id: T::ChainId,
        block: &B,
    ) -> Result<T::Number, Self::Error>;
    async fn subscribe<B: Decode>(
        &self,
        chain_id: T::ChainId,
        number: T::Number,
    ) -> Result<GenericBlock<B>, Self::Error>;
    async fn authorities(&self, chain_id: T::ChainId) -> Result<Vec<T::AccountId>, Self::Error>;
    async fn add_authority(
        &self,
        chain_id: T::ChainId,
        authority: &T::AccountId,
    ) -> Result<T::Number, Self::Error>;
    async fn remove_authority(
        &self,
        chain_id: T::ChainId,
        authority: &<T as System>::AccountId,
    ) -> Result<T::Number, Self::Error>;
    async fn follow(&self, chain_id: T::ChainId) -> Result<(), Self::Error>;
    async fn unfollow(&self, chain_id: T::ChainId) -> Result<(), Self::Error>;
}

#[async_trait]
impl<T, C> ChainClient<T> for C
where
    T: Runtime + Chain<Number = u64>,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<T>,
    C::Error: From<Error>,
{
    async fn create_chain(&self) -> Result<T::ChainId, C::Error> {
        Ok(self
            .chain_client()
            .create_chain_and_watch(self.chain_signer()?)
            .await?
            .new_chain()?
            .ok_or(Error::CreateChain)?
            .chain_id)
    }

    async fn author_block<B: Encode + ?Sized + Send + Sync>(
        &self,
        chain_id: T::ChainId,
        block: &B,
    ) -> Result<T::Number, C::Error> {
        let signer = self.chain_signer()?;
        let number = self.chain_client().chain_number(chain_id, None).await?;
        let ancestor = self.chain_client().chain_root(chain_id, None).await?;
        let full_block = GenericBlock {
            number,
            ancestor,
            payload: block,
        };
        let sealed = full_block.seal().map_err(|e| Error::Trie(e))?;
        self.chain_client()
            .author_block(signer, chain_id, sealed.offchain.root, &sealed.proof)
            .await?;
        //self.offchain_client().insert(sealed
        Ok(number)
    }

    async fn subscribe<B: Decode>(
        &self,
        _chain_id: T::ChainId,
        _number: T::Number,
    ) -> Result<GenericBlock<B>, C::Error> {
        /*let sub = self.chain_client().subscribe_events().await?;
        let mut decoder = EventsDecoder::<T>::new(self.chain_client().metadata().clone());
        decoder.with_chain();
        let mut sub = EventSubscription::<T>::new(sub, decoder);
        sub.filter_event::<NewBlockEvent<T>>();*/

        unimplemented!()
    }

    async fn authorities(&self, chain_id: T::ChainId) -> Result<Vec<T::AccountId>, C::Error> {
        Ok(self.chain_client().authorities(chain_id, None).await?)
    }

    async fn add_authority(
        &self,
        chain_id: T::ChainId,
        authority: &T::AccountId,
    ) -> Result<T::Number, C::Error> {
        Ok(self
            .chain_client()
            .add_authority_and_watch(self.chain_signer()?, chain_id, authority)
            .await?
            .authority_added()?
            .ok_or(Error::AddAuthority)?
            .number)
    }

    async fn remove_authority(
        &self,
        chain_id: T::ChainId,
        authority: &<T as System>::AccountId,
    ) -> Result<T::Number, C::Error> {
        Ok(self
            .chain_client()
            .remove_authority_and_watch(self.chain_signer()?, chain_id, authority)
            .await?
            .authority_removed()?
            .ok_or(Error::RemoveAuthority)?
            .number)
    }

    async fn follow(&self, _chain_id: T::ChainId) -> Result<(), C::Error> {
        Ok(())
    }

    async fn unfollow(&self, _chain_id: T::ChainId) -> Result<(), C::Error> {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Couldn't create chain.")]
    CreateChain,
    #[error("Couldn't add authority.")]
    AddAuthority,
    #[error("Couldn't remove authority.")]
    RemoveAuthority,
    #[error(transparent)]
    Trie(#[from] sunshine_chain_utils::trie::Error),
}

#[cfg(test)]
mod tests {
    use parity_scale_codec::{Decode, Encode};
    use test_client::chain::ChainClient;
    use test_client::mock::{test_node, AccountKeyring};
    use test_client::Client;

    #[derive(Clone, Debug, Eq, PartialEq, Decode, Encode)]
    struct Block {
        description: String,
    }

    #[async_std::test]
    async fn test_chain() {
        let (node, _node_tmp) = test_node();
        let (client, _client_tmp) = Client::mock(&node, AccountKeyring::Alice).await;

        let chain_id = client.create_chain().await.unwrap();
        assert_eq!(chain_id, 0);

        assert_eq!(client.authorities(chain_id).await.unwrap().len(), 1);

        let number = client
            .add_authority(chain_id, &AccountKeyring::Eve.to_account_id())
            .await
            .unwrap();
        assert_eq!(number, 0);
        assert_eq!(client.authorities(chain_id).await.unwrap().len(), 2);

        let number = client
            .remove_authority(chain_id, &AccountKeyring::Eve.to_account_id())
            .await
            .unwrap();
        assert_eq!(number, 0);
        assert_eq!(client.authorities(chain_id).await.unwrap().len(), 1);

        let mut block = Block {
            description: "the genesis block".into(),
        };
        let number = client.author_block(chain_id, &block).await.unwrap();
        assert_eq!(number, 0);

        block.description = "first block".into();
        let number = client.author_block(chain_id, &block).await.unwrap();
        assert_eq!(number, 1);
    }
}
