mod subxt;

pub use subxt::*;

use async_trait::async_trait;
use parity_scale_codec::{Decode, Encode};
use substrate_subxt::{system::System, Runtime, SignedExtension, SignedExtra};
use sunshine_chain_utils::block::GenericBlock;
use sunshine_core::ChainClient as Client;
use thiserror::Error;

#[async_trait]
pub trait ChainClient<T: Runtime + Chain>: Client<T> {
    async fn create_chain(&self) -> Result<T::ChainId, Self::Error>;
    async fn author_block<B: Encode>(&self) -> Result<(), Self::Error>;
    async fn subscribe<B: Decode>(
        &self,
        chain_id: T::ChainId,
        number: T::Number,
    ) -> Result<GenericBlock<B>, Self::Error>;
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
    T: Runtime + Chain,
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

    async fn author_block<B: Encode>(&self) -> Result<(), C::Error> {
        Ok(())
    }

    async fn subscribe<B: Decode>(
        &self,
        _chain_id: T::ChainId,
        _number: T::Number,
    ) -> Result<GenericBlock<B>, C::Error> {
        unimplemented!()
    }

    async fn add_authority(
        &self,
        _chain_id: T::ChainId,
        _authority: &T::AccountId,
    ) -> Result<T::Number, C::Error> {
        Ok(0u8.into())
    }

    async fn remove_authority(
        &self,
        _chain_id: T::ChainId,
        _authority: &<T as System>::AccountId,
    ) -> Result<T::Number, C::Error> {
        Ok(0u8.into())
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
}

#[cfg(test)]
mod tests {
    use test_client::chain::ChainClient;
    use test_client::mock::{test_node, AccountKeyring};
    use test_client::Client;

    #[async_std::test]
    async fn test_create_chain() {
        let (node, _node_tmp) = test_node();
        let (client, _client_tmp) = Client::mock(&node, AccountKeyring::Alice).await;
        let chain_id = client.create_chain().await.unwrap();
        assert_eq!(chain_id, 0);
    }
}
