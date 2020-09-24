pub mod error;
mod subxt;

pub use subxt::*;

use crate::error::{AddAuthority, AuthorBlock, CreateChain, RemoveAuthority};
use core::marker::PhantomData;
use libipld::alias;
use libipld::block::Block;
use libipld::cid::Cid;
use libipld::store::{dyn_alias, Store, StoreParams};
use parity_scale_codec::{Decode, Encode};
use sp_runtime::traits::CheckedSub;
use std::ops::Deref;
use substrate_subxt::{
    sp_runtime, system::System, Event, EventSubscription, EventsDecoder, Runtime, SignedExtension,
    SignedExtra,
};
use sunshine_client_utils::codec::codec::TreeCodec;
use sunshine_client_utils::codec::hasher::BLAKE2B_256_TREE;
use sunshine_client_utils::codec::trie::{OffchainBlock, TreeDecode, TreeEncode};
use sunshine_client_utils::GenericBlock;
use sunshine_client_utils::{async_trait, Client, Node, OffchainStore, Result};

fn chain_alias<R: Chain>(chain_id: R::ChainId) -> String {
    dyn_alias(alias!(chain), chain_id.into())
}

struct ChainEventSubscription<R: Runtime, E: Event<R>> {
    _marker: PhantomData<E>,
    subscription: EventSubscription<R>,
}

impl<R: Runtime + Chain, E: Event<R>> ChainEventSubscription<R, E> {
    async fn subscribe(client: &substrate_subxt::Client<R>) -> Result<Self> {
        let sub = client.subscribe_events().await?;
        let mut decoder = EventsDecoder::<R>::new(client.metadata().clone());
        decoder.with_chain();
        let mut subscription = EventSubscription::<R>::new(sub, decoder);
        subscription.filter_event::<E>();
        Ok(Self {
            _marker: PhantomData,
            subscription,
        })
    }

    async fn next(&mut self) -> Option<Result<E>> {
        match self.subscription.next().await {
            Some(Ok(raw)) => Some(E::decode(&mut &raw.data[..]).map_err(Into::into)),
            Some(Err(err)) => Some(Err(err.into())),
            None => None,
        }
    }
}

struct NewBlockSubscription<R: Runtime + Chain> {
    sub: ChainEventSubscription<R, NewBlockEvent<R>>,
    chain_id: R::ChainId,
    next: R::Number,
}

impl<R: Runtime + Chain> NewBlockSubscription<R> {
    async fn subscribe(
        client: &substrate_subxt::Client<R>,
        chain_id: R::ChainId,
        start: R::Number,
    ) -> Result<Self> {
        let sub = ChainEventSubscription::subscribe(client).await?;
        Ok(Self {
            sub,
            chain_id,
            next: start,
        })
    }

    fn set_next(&mut self, next: R::Number) {
        self.next = next;
    }

    async fn next(&mut self) -> Option<Result<NewBlockEvent<R>>> {
        while let Some(res) = self.sub.next().await {
            if res.is_err() {
                return Some(res);
            }
            let event = res.unwrap();
            if event.chain_id != self.chain_id {
                continue;
            }
            if event.number < self.next {
                continue;
            }
            if event.number > self.next {
                unreachable!();
            }
            self.next = self.next + 1u8.into();
            return Some(Ok(event));
        }
        None
    }
}

pub struct BlockSubscription<R: Runtime + Chain, S: Store, B: Decode + Send + Sync> {
    _marker: PhantomData<B>,
    store: S,
    sub: NewBlockSubscription<R>,
    sync_buf: Vec<GenericBlock<B, R::Number, R::TrieHasher>>,
    alias: String,
}

impl<R: Runtime + Chain, S: Store, B: Decode + Send + Sync> BlockSubscription<R, S, B>
where
    <S::Params as StoreParams>::Codecs: Into<TreeCodec>,
{
    async fn subscribe(
        client: &substrate_subxt::Client<R>,
        store: &S,
        chain_id: R::ChainId,
        start: R::Number,
    ) -> Result<Self> {
        let alias = chain_alias::<R>(chain_id);
        let mut sub = NewBlockSubscription::subscribe(client, chain_id, start).await?;
        let height = client.chain_height(chain_id, None).await?;
        let mut sync_buf =
            Vec::with_capacity(height.checked_sub(&start).unwrap_or_default().into() as usize);
        if height > start {
            let root: Cid = client.chain_root(chain_id, None).await?.unwrap().into();
            let mut next = root;
            loop {
                let block = Self::fetch_block(&store, &next).await?;
                let ancestor = block.ancestor;
                let number = block.number;
                sync_buf.push(block);
                if number <= start {
                    break;
                }
                next = ancestor.unwrap().into();
            }
            store.alias(&alias, Some(&root)).await?;
        }
        sub.set_next(height);
        Ok(Self {
            _marker: PhantomData,
            store: store.clone(),
            sub,
            sync_buf,
            alias,
        })
    }

    async fn fetch_block(
        store: &S,
        cid: &Cid,
    ) -> Result<GenericBlock<B, R::Number, R::TrieHasher>> {
        let block: OffchainBlock<R::TrieHasher> = store.get(cid).await?.decode::<TreeCodec, _>()?;
        GenericBlock::decode(&block)
    }

    pub async fn next(&mut self) -> Option<Result<GenericBlock<B, R::Number, R::TrieHasher>>> {
        if let Some(next) = self.sync_buf.pop() {
            return Some(Ok(next));
        }
        if let Some(res) = self.sub.next().await {
            Some(
                async move {
                    let cid = res?.root.into();
                    let block = Self::fetch_block(&self.store, &cid).await?;
                    self.store.alias(&self.alias, Some(&cid)).await?;
                    Ok(block)
                }
                .await,
            )
        } else {
            None
        }
    }
}

#[async_trait]
pub trait ChainClient<N: Node>: Client<N> + Sized
where
    N::Runtime: Chain,
{
    async fn create_chain(&self) -> Result<<N::Runtime as Chain>::ChainId>;
    async fn author_block<B: Encode + ?Sized + Send + Sync>(
        &self,
        chain_id: <N::Runtime as Chain>::ChainId,
        block: &B,
    ) -> Result<<N::Runtime as Chain>::Number>;
    async fn subscribe<B: Decode + Send + Sync>(
        &self,
        chain_id: <N::Runtime as Chain>::ChainId,
        number: <N::Runtime as Chain>::Number,
    ) -> Result<BlockSubscription<N::Runtime, OffchainStore<N>, B>>;
    async fn authorities(
        &self,
        chain_id: <N::Runtime as Chain>::ChainId,
    ) -> Result<Vec<<N::Runtime as System>::AccountId>>;
    async fn add_authority(
        &self,
        chain_id: <N::Runtime as Chain>::ChainId,
        authority: &<N::Runtime as System>::AccountId,
    ) -> Result<<N::Runtime as Chain>::Number>;
    async fn remove_authority(
        &self,
        chain_id: <N::Runtime as Chain>::ChainId,
        authority: &<N::Runtime as System>::AccountId,
    ) -> Result<<N::Runtime as Chain>::Number>;
}

#[async_trait]
impl<N, C> ChainClient<N> for C
where
    N: Node,
    N::Runtime: Chain,
    <<<N::Runtime as Runtime>::Extra as SignedExtra<N::Runtime>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<N>,
{
    async fn create_chain(&self) -> Result<<N::Runtime as Chain>::ChainId> {
        Ok(self
            .chain_client()
            .create_chain_and_watch(&self.chain_signer()?)
            .await?
            .new_chain()?
            .ok_or(CreateChain)?
            .chain_id)
    }

    async fn author_block<B: Encode + ?Sized + Send + Sync>(
        &self,
        chain_id: <N::Runtime as Chain>::ChainId,
        block: &B,
    ) -> Result<<N::Runtime as Chain>::Number> {
        let signer = self.chain_signer()?;
        let mut number = self.chain_client().chain_height(chain_id, None).await?;
        loop {
            let ancestor = self.chain_client().chain_root(chain_id, None).await?;
            let full_block = GenericBlock::<_, <N::Runtime as Chain>::Number, <N::Runtime as Chain>::TrieHasher> {
                number,
                ancestor,
                payload: block,
            };
            let sealed = full_block.seal()?;
            let block = Block::encode(TreeCodec, BLAKE2B_256_TREE, &sealed.offchain)?;
            log::info!(
                "created block {:?} {:?} with ancestor {:?}",
                number,
                block.cid(),
                ancestor
            );
            self.offchain_client().insert(&block).await?;
            let result = self
                .chain_client()
                .author_block_and_watch(&signer, chain_id, *sealed.offchain.root(), &sealed.proof)
                .await;
            if let Err(err) = &result {
                let height = self.chain_client().chain_height(chain_id, None).await?;
                if height > number {
                    number = height;
                    log::info!("chain height changed {:?}, retrying.\n{:?}", height, err);
                    continue;
                }
            }
            result?.new_block()?.ok_or(AuthorBlock)?;
            return Ok(number);
        }
    }

    async fn subscribe<B: Decode + Send + Sync>(
        &self,
        chain_id: <N::Runtime as Chain>::ChainId,
        number: <N::Runtime as Chain>::Number,
    ) -> Result<BlockSubscription<N::Runtime, OffchainStore<N>, B>> {
        BlockSubscription::subscribe(
            self.chain_client(),
            self.offchain_client().deref(),
            chain_id,
            number,
        )
        .await
    }

    async fn authorities(&self, chain_id: <N::Runtime as Chain>::ChainId) -> Result<Vec<<N::Runtime as System>::AccountId>> {
        Ok(self.chain_client().authorities(chain_id, None).await?)
    }

    async fn add_authority(
        &self,
        chain_id: <N::Runtime as Chain>::ChainId,
        authority: &<N::Runtime as System>::AccountId,
    ) -> Result<<N::Runtime as Chain>::Number> {
        Ok(self
            .chain_client()
            .add_authority_and_watch(&self.chain_signer()?, chain_id, authority)
            .await?
            .authority_added()?
            .ok_or(AddAuthority)?
            .number)
    }

    async fn remove_authority(
        &self,
        chain_id: <N::Runtime as Chain>::ChainId,
        authority: &<N::Runtime as System>::AccountId,
    ) -> Result<<N::Runtime as Chain>::Number> {
        Ok(self
            .chain_client()
            .remove_authority_and_watch(&self.chain_signer()?, chain_id, authority)
            .await?
            .authority_removed()?
            .ok_or(RemoveAuthority)?
            .number)
    }
}

#[cfg(test)]
mod tests {
    use async_std::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use test_client::chain::{Chain, ChainClient, ChainRootStoreExt};
    use test_client::client::{AccountKeyring, Client as _, Node as _};
    use test_client::{Client, Node, Runtime};

    #[derive(Clone, Debug, Eq, PartialEq, Decode, Encode)]
    struct Block {
        description: String,
    }

    async fn assert_chain_pinned(client: &Client, chain_id: <Runtime as Chain>::Number) {
        let root = client
            .chain_client()
            .chain_root(chain_id, None)
            .await
            .unwrap()
            .unwrap()
            .into();
        assert_eq!(
            client.offchain_client().pinned(&root).await.unwrap(),
            Some(true)
        );
    }

    #[async_std::test]
    async fn test_chain() {
        env_logger::try_init().ok();
        let node = Node::new_mock();
        let (client, _tmp) = Client::mock(&node, AccountKeyring::Alice).await;

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

        let mut sub = client.subscribe(chain_id, 0).await.unwrap();

        let mut block = Block {
            description: "the genesis block".into(),
        };
        let number = client.author_block(chain_id, &block).await.unwrap();
        assert_eq!(number, 0);

        let block2 = sub.next().await.unwrap().unwrap();
        assert_eq!(block2.number, number);
        assert!(block2.ancestor.is_none());
        assert_eq!(block, block2.payload);

        block.description = "first block".into();
        let number = client.author_block(chain_id, &block).await.unwrap();
        assert_eq!(number, 1);

        let block2 = sub.next().await.unwrap().unwrap();
        assert_eq!(block2.number, number);
        assert!(block2.ancestor.is_some());
        assert_eq!(block, block2.payload);

        assert_chain_pinned(&client, chain_id).await;
    }

    #[async_std::test]
    async fn test_sync() {
        env_logger::try_init().ok();
        let node = Node::new_mock();
        let (client, _tmp) = Client::mock(&node, AccountKeyring::Alice).await;

        let chain_id = client.create_chain().await.unwrap();
        assert_eq!(chain_id, 0);

        client.author_block(chain_id, &0u64).await.unwrap();
        client.author_block(chain_id, &1u64).await.unwrap();
        client.author_block(chain_id, &2u64).await.unwrap();

        let mut sub = client.subscribe::<u64>(chain_id, 1).await.unwrap();
        let b1 = sub.next().await.unwrap().unwrap();
        assert_eq!(b1.payload, 1);
        let b2 = sub.next().await.unwrap().unwrap();
        assert_eq!(b2.payload, 2);

        assert_chain_pinned(&client, chain_id).await;
    }

    #[async_std::test]
    async fn test_concurrent() {
        env_logger::try_init().ok();
        let node = Node::new_mock();
        let (client1, _tmp) = Client::mock(&node, AccountKeyring::Alice).await;
        let (client2, _tmp) = Client::mock(&node, AccountKeyring::Bob).await;

        let chain_id = client1.create_chain().await.unwrap();
        assert_eq!(chain_id, 0);
        client1
            .add_authority(chain_id, &AccountKeyring::Bob.to_account_id())
            .await
            .unwrap();

        let a = client1.author_block(chain_id, &0u64);
        let b = client2.author_block(chain_id, &1u64);

        let (ra, rb) = a.join(b).await;
        ra.unwrap();
        rb.unwrap();
    }
}
