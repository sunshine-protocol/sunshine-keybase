use faucet_client::Faucet;
use identity_client::{Claim, Identity};
use identity_utils::cid::CidBytes;
use ipld_block_builder::{derive_cache, Codec, IpldCache};
use libipld::store::Store;
use ipfs_embed::{Config, Store as OffchainStore};
use substrate_subxt::balances::{AccountData, Balances};
use substrate_subxt::sp_runtime::traits::{IdentifyAccount, Verify};
use substrate_subxt::system::System;
use substrate_subxt::{sp_core, sp_runtime};
use substrate_keybase_keystore::Keystore;
use sunshine_core::{ChainClient, ChainSigner, OffchainSigner, Keystore as _};
use thiserror::Error;
use std::path::Path;

pub use faucet_client as faucet;
pub use identity_client as identity;
mod light;

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

impl Identity for Runtime {
    type Uid = Uid;
    type Cid = CidBytes;
    type Mask = [u8; 32];
    type Gen = u16;
    type IdAccountData = AccountData<<Self as Balances>::Balance>;
}

impl Faucet for Runtime {}

impl substrate_subxt::Runtime for Runtime {
    type Signature = sp_runtime::MultiSignature;
    type Extra = substrate_subxt::DefaultExtra<Self>;
}

pub struct Client {
    keystore: Keystore<Runtime, sp_core::sr25519::Pair>,
    chain: substrate_subxt::Client<Runtime>,
    offchain: OffchainClient<OffchainStore>,
}

impl Client {
    pub async fn new(root: &Path, chain_spec: Option<&Path>) -> Result<Self, Error> {
        let keystore = Keystore::open(root.join("keystore")).await?;
        let db = sled::open(root.join("db"))?;
        let db_ipfs = db.open_tree("ipfs")?;

        let chain = if let Some(chain_spec) = chain_spec {
            let db_light = db.open_tree("substrate")?;
            light::build_light_client(db_light, chain_spec).await?
        } else {
            substrate_subxt::ClientBuilder::new().build().await?
        };

        let config = Config::from_tree(db_ipfs);
        let store = OffchainStore::new(config)?;
        let offchain = OffchainClient::new(store);

        Ok(Self { keystore, chain, offchain })
    }
}

impl ChainClient<Runtime> for Client {
    type Keystore = Keystore<Runtime, sp_core::sr25519::Pair>;
    type OffchainClient = OffchainClient<OffchainStore>;
    type Error = Error;

    fn keystore(&self) -> &Self::Keystore {
        &self.keystore
    }

    fn keystore_mut(&mut self) -> &mut Self::Keystore {
        &mut self.keystore
    }

    fn chain_client(&self) -> &substrate_subxt::Client<Runtime> {
        &self.chain
    }

    fn chain_signer(&self) -> Result<&(dyn ChainSigner<Runtime> + Send + Sync), Self::Error> {
        self.keystore.chain_signer().ok_or(Error::Keystore(substrate_keybase_keystore::Error::Locked))
    }

    fn offchain_client(&self) -> &Self::OffchainClient {
        &self.offchain
    }

    fn offchain_signer(&self) -> Result<&dyn OffchainSigner<Runtime>, Self::Error> {
        self.keystore.offchain_signer().ok_or(Error::Keystore(substrate_keybase_keystore::Error::Locked))
    }
}

pub struct OffchainClient<S> {
    claims: IpldCache<S, Codec, Claim>,
}

impl<S: Store> OffchainClient<S> {
    pub fn new(store: S) -> Self {
        Self {
            claims: IpldCache::new(store, Codec::new(), 64),
        }
    }
}

derive_cache!(OffchainClient, claims, Codec, Claim);

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Keystore(#[from] substrate_keybase_keystore::Error),
    #[error(transparent)]
    Chain(#[from] substrate_subxt::Error),
    #[error(transparent)]
    Offchain(#[from] ipfs_embed::Error),
    #[error(transparent)]
    Ipld(#[from] libipld::error::Error),
    #[error(transparent)]
    Light(#[from] light::Error),
    #[error(transparent)]
    Db(#[from] sled::Error),
    #[error(transparent)]
    Identity(#[from] identity_client::Error),
}

impl From<codec::Error> for Error {
    fn from(error: codec::Error) -> Self {
        Self::Chain(error.into())
    }
}

#[cfg(feature = "mock")]
pub mod mock {
    pub use sp_keyring::AccountKeyring;
    use substrate_subxt::client::{DatabaseConfig, Role, SubxtClient, SubxtClientConfig};
    pub use tempdir::TempDir;

    pub type TestNode = jsonrpsee::Client;

    pub fn test_node() -> (TestNode, TempDir) {
        env_logger::try_init().ok();
        let tmp = TempDir::new("sunshine-identity-").expect("failed to create tempdir");
        let config = SubxtClientConfig {
            impl_name: "test-client",
            impl_version: "0.1.0",
            author: "sunshine",
            copyright_start_year: 2020,
            db: DatabaseConfig::RocksDb {
                path: tmp.path().into(),
                cache_size: 128,
            },
            builder: test_node::service::new_full,
            chain_spec: test_node::chain_spec::development_config(),
            role: Role::Authority(AccountKeyring::Alice),
        };
        let client = SubxtClient::new(config).unwrap().into();
        (client, tmp)
    }
}
