use crate::runtime::AccountId;
use clap::Clap;
use client_identity::{Service, ServiceParseError};
use std::path::PathBuf;
use std::str::FromStr;
use substrate_subxt::sp_core::crypto::{PublicError, Ss58Codec};

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct Opts {
    #[clap(subcommand)]
    pub subcmd: SubCommand,
    #[clap(short = "p", long = "path")]
    pub path: Option<PathBuf>,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub enum SubCommand {
    Init(InitCommand),
    Unlock,
    Lock,
    Id(IdCommand),
    Prove(ProveCommand),
    Revoke(RevokeCommand),
    Transfer(TransferCommand),
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct InitCommand {
    #[clap(short = "f", long = "force")]
    pub force: bool,
    #[clap(short = "s", long = "suri")]
    pub suri: bool,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct IdCommand {
    pub identifier: Option<Identifier>,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct ProveCommand {
    pub service: Service,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct RevokeCommand {
    pub seqno: u32,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct TransferCommand {
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

pub struct Account(pub AccountId);

impl FromStr for Account {
    type Err = PublicError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        Ok(Self(AccountId::from_string(string)?))
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
