use crate::error::Error;
use crate::runtime::AccountId;
use clap::Clap;
use client_identity::{Service, ServiceParseError};
use std::path::PathBuf;
use std::str::FromStr;
use substrate_subxt::sp_core::crypto::Ss58Codec;

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct Opts {
    #[clap(subcommand)]
    pub subcmd: SubCommand,
    #[clap(short = "p", long = "path")]
    pub path: Option<PathBuf>,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub enum SubCommand {
    Key(KeyCommand),
    Account(AccountCommand),
    Device(DeviceCommand),
    Id(IdCommand),
    Wallet(WalletCommand),
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub enum KeyCommand {
    Init(KeyInitCommand),
    Unlock,
    Lock,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub enum AccountCommand {
    Create(AccountCreateCommand),
    //Password(ChangePasswordCommand),
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub enum DeviceCommand {
    Add(DeviceAddCommand),
    Remove(DeviceRemoveCommand),
    List,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub enum IdCommand {
    List(IdListCommand),
    Prove(IdProveCommand),
    Revoke(IdRevokeCommand),
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub enum WalletCommand {
    Balance,
    Transfer(WalletTransferCommand),
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct KeyInitCommand {
    #[clap(short = "f", long = "force")]
    pub force: bool,

    #[clap(short = "s", long = "suri")]
    pub suri: bool,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct AccountCreateCommand {
    pub account: Account,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct DeviceAddCommand {
    pub device: Account,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct DeviceRemoveCommand {
    pub device: Account,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct IdListCommand {
    pub identifier: Option<Identifier>,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct IdProveCommand {
    pub service: Service,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct IdRevokeCommand {
    pub seqno: u32,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct WalletTransferCommand {
    pub identifier: Identifier,
    pub amount: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Identifier {
    Account(AccountId),
    Service(Service),
}

impl core::fmt::Display for Identifier {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Account(account_id) => write!(f, "{}", account_id.to_string()),
            Self::Service(service) => service.fmt(f),
        }
    }
}

impl FromStr for Identifier {
    type Err = ServiceParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        if let Ok(Account(account_id)) = Account::from_str(string) {
            Ok(Self::Account(account_id))
        } else {
            Ok(Self::Service(Service::from_str(string)?))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account(pub AccountId);

impl FromStr for Account {
    type Err = Error;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        Ok(Self(AccountId::from_string(string).map_err(|_| Error::InvalidAccountId)?))
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
