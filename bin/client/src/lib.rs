use libipld::cache::IpldCache;
use libipld::cbor::DagCborCodec;
use libipld::derive_cache;
use libipld::store::Store;
use sc_service::{Configuration, RpcHandlers, TaskManager};
use std::ops::Deref;
use substrate_subxt::balances::{AccountData, Balances};
use substrate_subxt::sp_runtime::traits::{IdentifyAccount, Verify};
use substrate_subxt::system::System;
use substrate_subxt::{extrinsic, sp_core, sp_runtime};
use sunshine_chain_client::Chain;
use sunshine_client_utils::codec::hasher::{TreeHashBlake2b256, TreeHasherBlake2b256, BLAKE2B_256};
use sunshine_client_utils::codec::Cid;
use sunshine_client_utils::crypto::keychain::KeyType;
use sunshine_client_utils::crypto::sr25519;
use sunshine_client_utils::{
    sc_service, ChainSpecError, GenericClient, Network, Node as NodeT,
    OffchainClient as OffchainClientT, OffchainStore,
};
use sunshine_faucet_client::Faucet;
use sunshine_identity_client::{Claim, Identity};

pub use sunshine_chain_client as chain;
pub use sunshine_client_utils as client;
pub use sunshine_faucet_client as faucet;
pub use sunshine_identity_client as identity;

pub type AccountId = <<sp_runtime::MultiSignature as Verify>::Signer as IdentifyAccount>::AccountId;
pub type Uid = u32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Runtime;

impl System for Runtime {
    type Index = u32;
    type BlockNumber = u32;
    type Hash = sp_core::H256;
    type Hashing = sp_runtime::traits::BlakeTwo256;
    type AccountId = AccountId;
    type Address = AccountId;
    type Header = sp_runtime::generic::Header<Self::BlockNumber, Self::Hashing>;
    type Extrinsic = sp_runtime::OpaqueExtrinsic;
    type AccountData = ();
}

impl Balances for Runtime {
    type Balance = u128;
}

impl Chain for Runtime {
    type ChainId = u64;
    type Number = u64;
    type TrieHasher = TreeHasherBlake2b256;
    type TrieHash = TreeHashBlake2b256;
}

impl Faucet for Runtime {}

impl Identity for Runtime {
    type Uid = Uid;
    type Cid = Cid;
    type Mask = [u8; 32];
    type Gen = u16;
    type IdAccountData = AccountData<<Self as Balances>::Balance>;
}

impl substrate_subxt::Runtime for Runtime {
    type Signature = sp_runtime::MultiSignature;
    type Extra = extrinsic::DefaultExtra<Self>;
}

pub struct OffchainClient<S> {
    store: S,
    claims: IpldCache<S, DagCborCodec, Claim>,
}

impl<S> Deref for OffchainClient<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

derive_cache!(OffchainClient, claims, DagCborCodec, Claim);

impl<S: Store> OffchainClient<S> {
    pub fn new(store: S) -> Self {
        Self {
            claims: IpldCache::new(store.clone(), DagCborCodec, BLAKE2B_256, 64),
            store,
        }
    }
}

impl<S: Store> From<S> for OffchainClient<S> {
    fn from(store: S) -> Self {
        Self::new(store)
    }
}

impl<S: Store> OffchainClientT<S> for OffchainClient<S> {}

#[derive(Clone, Copy)]
pub struct Node;

impl NodeT for Node {
    type ChainSpec = test_node::ChainSpec;
    type Block = test_node::OpaqueBlock;
    type Runtime = Runtime;

    fn impl_name() -> &'static str {
        test_node::IMPL_NAME
    }

    fn impl_version() -> &'static str {
        test_node::IMPL_VERSION
    }

    fn author() -> &'static str {
        test_node::AUTHOR
    }

    fn copyright_start_year() -> i32 {
        test_node::COPYRIGHT_START_YEAR
    }

    fn chain_spec_dev() -> Self::ChainSpec {
        test_node::development_config()
    }

    fn chain_spec_from_json_bytes(json: Vec<u8>) -> Result<Self::ChainSpec, ChainSpecError> {
        Self::ChainSpec::from_json_bytes(json).map_err(ChainSpecError)
    }

    fn new_light(
        config: Configuration,
    ) -> Result<(TaskManager, RpcHandlers, Network<Self>), sc_service::Error> {
        Ok(test_node::new_light(config)?)
    }

    fn new_full(
        config: Configuration,
    ) -> Result<(TaskManager, RpcHandlers, Network<Self>), sc_service::Error> {
        Ok(test_node::new_full(config)?)
    }
}

pub struct UserDevice;

impl KeyType for UserDevice {
    const KEY_TYPE: u8 = 0;
    type Pair = sr25519::Pair;
}

pub type Client = GenericClient<Node, UserDevice, OffchainClient<OffchainStore<Node>>>;
