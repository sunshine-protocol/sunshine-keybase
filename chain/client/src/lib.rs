pub mod error;
mod subxt;

pub use subxt::*;

use crate::error::{AddAuthority, AuthorBlock, CreateChain, RemoveAuthority};
use core::marker::PhantomData;
use libipld::block::Block;
use libipld::codec::{Decode as IpldDecode};
use libipld::ipld::Ipld;
use libipld::store::{Store, StoreParams};
use parity_scale_codec::{Decode, Encode};
use sp_runtime::traits::CheckedSub;
use substrate_subxt::{
    sp_runtime, system::System, Event, EventSubscription, EventsDecoder, Runtime, SignedExtension,
    SignedExtra,
};
use sunshine_client_utils::block::GenericBlock;
use sunshine_client_utils::codec::codec::TreeCodec;
use sunshine_client_utils::codec::hasher::BLAKE2B_256_TREE;
use sunshine_client_utils::codec::trie::{OffchainBlock, TreeDecode, TreeEncode};
use sunshine_client_utils::{async_trait, Client, Node, OffchainClient, Result};

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
        let mut sub = NewBlockSubscription::subscribe(client, chain_id, start).await?;
        let height = client.chain_height(chain_id, None).await?;
        let mut sync_buf =
            Vec::with_capacity(height.checked_sub(&start).unwrap_or_default().into() as usize);
        if height > start {
            let mut root = client.chain_root(chain_id, None).await?.unwrap();
            loop {
                let block = Self::fetch_block(&store, root).await?;
                let ancestor = block.ancestor;
                let number = block.number;
                sync_buf.push(block);
                if number <= start {
                    break;
                }
                root = ancestor.unwrap();
            }
        }
        sub.set_next(height);
        Ok(Self {
            _marker: PhantomData,
            store: store.clone(),
            sub,
            sync_buf,
        })
    }

    async fn fetch_block(
        store: &S,
        hash: R::TrieHash,
    ) -> Result<GenericBlock<B, R::Number, R::TrieHasher>> {
        let block: OffchainBlock<R::TrieHasher> =
            store.get(&hash.into()).await?.decode::<TreeCodec, _>()?;
        GenericBlock::decode(&block)
    }

    pub async fn next(&mut self) -> Option<Result<GenericBlock<B, R::Number, R::TrieHasher>>> {
        if let Some(next) = self.sync_buf.pop() {
            return Some(Ok(next));
        }
        if let Some(res) = self.sub.next().await {
            Some(async move { Self::fetch_block(&self.store, res?.root).await }.await)
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
    ) -> Result<BlockSubscription<N::Runtime, <Self::OffchainClient as OffchainClient>::Store, B>>;
    async fn authorities(&self, chain_id: <N::Runtime as Chain>::ChainId) -> Result<Vec<<N::Runtime as System>::AccountId>>;
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
    <<<C::OffchainClient as OffchainClient>::Store as Store>::Params as StoreParams>::Codecs:
        From<TreeCodec> + Into<TreeCodec>,
    Ipld: IpldDecode<<<<C::OffchainClient as OffchainClient>::Store as Store>::Params as StoreParams>::Codecs>,
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
            self.offchain_client().store().insert(block).await?;
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
            /*self.offchain_client().store().update(
            if let Some(cid) = ancestor.map(Into::into) {
                self.offchain_client().store().update(&cid).await?;
            }*/
            return Ok(number);
        }
    }

    async fn subscribe<B: Decode + Send + Sync>(
        &self,
        chain_id: <N::Runtime as Chain>::ChainId,
        number: <N::Runtime as Chain>::Number,
    ) -> Result<BlockSubscription<N::Runtime, <C::OffchainClient as OffchainClient>::Store, B>> {
        BlockSubscription::subscribe(
            self.chain_client(),
            self.offchain_client().store(),
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
    use sunshine_client_utils::{Client as _, OffchainClient, codec::Cid};
    use test_client::chain::{ChainClient, ChainRootStoreExt};
    use test_client::mock::{test_node, AccountKeyring, Client};

    #[derive(Clone, Debug, Eq, PartialEq, Decode, Encode)]
    struct Block {
        description: String,
    }

    async fn pinned_blocks(client: &Client) -> Vec<(Cid, usize)> {
        let store = client.offchain_client().store();
        let mut pinned_blocks = vec![];
        for cid in store.blocks().await {
            let md = store.metadata(&cid).await;
            if md.pins > 0 {
                pinned_blocks.push((cid, md.pins));
            }
        }
        pinned_blocks
    }

    async fn assert_only_root_is_pinned_once(client: &Client, chain_id: u64) {
        let root = client.chain_client().chain_root(chain_id, None).await.unwrap();
        let pinned = pinned_blocks(client).await;
        assert_eq!(pinned.len(), 1);
        assert_eq!(Some(pinned[0].0.clone()), root.map(Cid::from));
        assert_eq!(pinned[0].1, 1);
    }

    #[async_std::test]
    async fn test_chain() {
        env_logger::try_init().ok();
        let (node, _node_tmp) = test_node();
        let client = Client::mock(&node, AccountKeyring::Alice).await;

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

        assert_only_root_is_pinned_once(&client, chain_id).await;
    }

    #[async_std::test]
    async fn test_sync() {
        env_logger::try_init().ok();
        let (node, _node_tmp) = test_node();
        let client = Client::mock(&node, AccountKeyring::Alice).await;

        let chain_id = client.create_chain().await.unwrap();
        assert_eq!(chain_id, 0);

        client.author_block(chain_id, &0u64).await.unwrap();
        client.author_block(chain_id, &1u64).await.unwrap();
        client.author_block(chain_id, &2u64).await.unwrap();

        assert_only_root_is_pinned_once(&client, chain_id).await;

        let mut sub = client.subscribe::<u64>(chain_id, 1).await.unwrap();
        let b1 = sub.next().await.unwrap().unwrap();
        assert_eq!(b1.payload, 1);
        let b2 = sub.next().await.unwrap().unwrap();
        assert_eq!(b2.payload, 2);

        assert_only_root_is_pinned_once(&client, chain_id).await;
    }

    #[async_std::test]
    async fn test_concurrent() {
        env_logger::try_init().ok();
        let (node, _node_tmp) = test_node();
        let client1 = Client::mock(&node, AccountKeyring::Alice).await;
        let client2 = Client::mock(&node, AccountKeyring::Bob).await;

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

        assert_only_root_is_pinned_once(&client1, chain_id).await;
        assert_only_root_is_pinned_once(&client2, chain_id).await;
    }
}
