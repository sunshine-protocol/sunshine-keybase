use client_identity::Identity;
use substrate_subxt::balances::{AccountData, Balances};
use substrate_subxt::sp_runtime::traits::{IdentifyAccount, Verify};
use substrate_subxt::system::System;
use substrate_subxt::{sp_core, sp_runtime};
use utils_identity::cid::CidBytes;

pub type AccountId = <<sp_runtime::MultiSignature as Verify>::Signer as IdentifyAccount>::AccountId;
pub type Signature = sp_runtime::MultiSignature;
pub type Extra = substrate_subxt::DefaultExtra<Runtime>;

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
    type AccountData = AccountData<<Self as Balances>::Balance>;
}

impl Balances for Runtime {
    type Balance = u128;
}

impl Identity for Runtime {
    type Uid = u32;
    type Cid = CidBytes;
    type Mask = [u8; 32];
    type Gen = u16;
}
