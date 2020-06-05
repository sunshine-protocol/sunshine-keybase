use crate::error::Error;
use crate::runtime::{AccountId, Uid};
use clap::Clap;
use client_identity::{Service, ServiceParseError};
use std::path::PathBuf;
use std::str::FromStr;
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::sp_core::{sr25519, Pair};

#[derive(Clone, Debug, Clap)]
pub struct Opts {
    #[clap(subcommand)]
    pub cmd: SubCommand,
    #[clap(short = "p", long = "path")]
    pub path: Option<PathBuf>,
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
    Init(KeyInitCommand),
    Unlock,
    Lock,
}

#[derive(Clone, Debug, Clap)]
pub struct AccountCommand {
    #[clap(subcommand)]
    pub cmd: AccountSubCommand,
}

#[derive(Clone, Debug, Clap)]
pub enum AccountSubCommand {
    Create(AccountCreateCommand),
    //Password(ChangePasswordCommand),
}

#[derive(Clone, Debug, Clap)]
pub struct DeviceCommand {
    #[clap(subcommand)]
    pub cmd: DeviceSubCommand,
}

#[derive(Clone, Debug, Clap)]
pub enum DeviceSubCommand {
    Add(DeviceAddCommand),
    Remove(DeviceRemoveCommand),
    List(DeviceListCommand),
}

#[derive(Clone, Debug, Clap)]
pub struct IdCommand {
    #[clap(subcommand)]
    pub cmd: IdSubCommand,
}

#[derive(Clone, Debug, Clap)]
pub enum IdSubCommand {
    List(IdListCommand),
    Prove(IdProveCommand),
    Revoke(IdRevokeCommand),
}

#[derive(Clone, Debug, Clap)]
pub struct WalletCommand {
    #[clap(subcommand)]
    pub cmd: WalletSubCommand,
}

#[derive(Clone, Debug, Clap)]
pub enum WalletSubCommand {
    Balance(WalletBalanceCommand),
    Transfer(WalletTransferCommand),
}

#[derive(Clone, Debug, Clap)]
pub struct KeyInitCommand {
    /// Overwrite existing keys.
    #[clap(short = "f", long = "force")]
    pub force: bool,

    /// Suri.
    #[clap(long = "suri")]
    pub suri: Option<Suri>,
}

#[derive(Clone, Debug, Clap)]
pub struct AccountCreateCommand {
    pub device: Ss58,
}

#[derive(Clone, Debug, Clap)]
pub struct DeviceAddCommand {
    pub device: Ss58,
}

#[derive(Clone, Debug, Clap)]
pub struct DeviceRemoveCommand {
    pub device: Ss58,
}

#[derive(Clone, Debug, Clap)]
pub struct DeviceListCommand {
    pub identifier: Option<Identifier>,
}

#[derive(Clone, Debug, Clap)]
pub struct IdListCommand {
    pub identifier: Option<Identifier>,
}

#[derive(Clone, Debug, Clap)]
pub struct IdProveCommand {
    pub service: Service,
}

#[derive(Clone, Debug, Clap)]
pub struct IdRevokeCommand {
    pub service: Service,
}

#[derive(Clone, Debug, Clap)]
pub struct WalletBalanceCommand {
    pub identifier: Option<Identifier>,
}

#[derive(Clone, Debug, Clap)]
pub struct WalletTransferCommand {
    pub identifier: Identifier,
    pub amount: u128,
}

#[derive(Clone)]
pub struct Suri(pub [u8; 32]);

impl core::fmt::Debug for Suri {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "*****")
    }
}

impl FromStr for Suri {
    type Err = Error;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let (_, seed) =
            sr25519::Pair::from_string_with_seed(string, None).map_err(|_| Error::InvalidSuri)?;
        Ok(Self(seed.unwrap()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ss58(pub AccountId);

impl FromStr for Ss58 {
    type Err = Error;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            AccountId::from_string(string).map_err(|_| Error::InvalidSs58)?,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Identifier {
    Uid(Uid),
    Account(AccountId),
    Service(Service),
}

impl core::fmt::Display for Identifier {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Uid(uid) => write!(f, "{}", uid),
            Self::Account(account_id) => write!(f, "{}", account_id.to_string()),
            Self::Service(service) => service.fmt(f),
        }
    }
}

impl FromStr for Identifier {
    type Err = ServiceParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        if let Ok(uid) = Uid::from_str(string) {
            Ok(Self::Uid(uid))
        } else if let Ok(Ss58(account_id)) = Ss58::from_str(string) {
            Ok(Self::Account(account_id))
        } else {
            Ok(Self::Service(Service::from_str(string)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_keyring::AccountKeyring;

    #[test]
    fn parse_identifer() {
        assert_eq!(
            Identifier::from_str("dvc94ch@github"),
            Ok(Identifier::Service(Service::Github("dvc94ch".into())))
        );
        assert_eq!(
            Identifier::from_str("dvc94ch@twitter"),
            Err(ServiceParseError::Unknown("twitter".into()))
        );
        assert_eq!(
            Identifier::from_str("@dvc94ch"),
            Err(ServiceParseError::Invalid)
        );
        let alice = AccountKeyring::Alice.to_account_id();
        assert_eq!(
            Identifier::from_str(&alice.to_string()),
            Ok(Identifier::Account(alice))
        );
    }
}
