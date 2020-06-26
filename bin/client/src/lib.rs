use client_faucet::Faucet;
use client_identity::Identity;
use substrate_subxt::balances::{AccountData, Balances};
use substrate_subxt::sp_runtime::traits::{IdentifyAccount, Verify};
use substrate_subxt::system::System;
use substrate_subxt::{sp_core, sp_runtime};
use utils_identity::cid::CidBytes;

pub use client_faucet as faucet;
pub use client_identity as identity;
#[cfg(feature = "light")]
pub mod light;

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
