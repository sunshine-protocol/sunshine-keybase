use clap::Clap;
use std::path::PathBuf;
use sunshine_faucet_cli::MintCommand;
use sunshine_identity_cli::{account, device, id, key, wallet};

#[derive(Clone, Debug, Clap)]
pub struct Opts {
    #[clap(subcommand)]
    pub cmd: SubCommand,
    #[clap(short = 'p', long = "path")]
    pub path: Option<PathBuf>,
    #[clap(short = 'c', long = "chain-spec")]
    pub chain_spec: Option<PathBuf>,
}

#[derive(Clone, Debug, Clap)]
pub enum SubCommand {
    Key(KeyCommand),
    Account(AccountCommand),
    Device(DeviceCommand),
    Id(IdCommand),
    Wallet(WalletCommand),
    Run,
}

#[derive(Clone, Debug, Clap)]
pub struct KeyCommand {
    #[clap(subcommand)]
    pub cmd: KeySubCommand,
}

#[derive(Clone, Debug, Clap)]
pub enum KeySubCommand {
    Set(key::KeySetCommand),
    Unlock(key::KeyUnlockCommand),
    Lock(key::KeyLockCommand),
}

#[derive(Clone, Debug, Clap)]
pub struct AccountCommand {
    #[clap(subcommand)]
    pub cmd: AccountSubCommand,
}

#[derive(Clone, Debug, Clap)]
pub enum AccountSubCommand {
    Create(account::AccountCreateCommand),
    Password(account::AccountPasswordCommand),
    Mint(MintCommand),
}

#[derive(Clone, Debug, Clap)]
pub struct DeviceCommand {
    #[clap(subcommand)]
    pub cmd: DeviceSubCommand,
}

#[derive(Clone, Debug, Clap)]
pub enum DeviceSubCommand {
    Add(device::DeviceAddCommand),
    Remove(device::DeviceRemoveCommand),
    List(device::DeviceListCommand),
    Paperkey(device::DevicePaperkeyCommand),
}

#[derive(Clone, Debug, Clap)]
pub struct IdCommand {
    #[clap(subcommand)]
    pub cmd: IdSubCommand,
}

#[derive(Clone, Debug, Clap)]
pub enum IdSubCommand {
    List(id::IdListCommand),
    Prove(id::IdProveCommand),
    Revoke(id::IdRevokeCommand),
}

#[derive(Clone, Debug, Clap)]
pub struct WalletCommand {
    #[clap(subcommand)]
    pub cmd: WalletSubCommand,
}

#[derive(Clone, Debug, Clap)]
pub enum WalletSubCommand {
    Balance(wallet::WalletBalanceCommand),
    Transfer(wallet::WalletTransferCommand),
}
