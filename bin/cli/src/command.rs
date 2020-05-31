use crate::runtime::AccountId;
use clap::Clap;
use std::path::PathBuf;
use std::str::FromStr;
use substrate_subxt::sp_core::crypto::{PublicError, Ss58Codec};
use thiserror::Error;

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct Opts {
    #[clap(subcommand)]
    pub subcmd: SubCommand,
    #[clap(short = "p", long = "path")]
    pub path: Option<PathBuf>,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub enum SubCommand {
    Id(IdCommand),
    Prove(ProveCommand),
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct IdCommand {
    pub identifier: Option<Identifier>,
}

#[derive(Clone, Debug, Clap, Eq, PartialEq)]
pub struct ProveCommand {
    pub identifier: Identifier,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Identifier {
    Ss58(AccountId),
    Github(String),
}

impl FromStr for Identifier {
    type Err = IdentifierError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let mut parts = string.split("@");
        let username = parts.next().ok_or(IdentifierError::InvalidIdentifier)?;
        if username.is_empty() {
            return Err(IdentifierError::InvalidIdentifier);
        }
        let result = if let Some(service) = parts.next() {
            match service {
                "github" => Ok(Identifier::Github(username.into())),
                _ => Err(IdentifierError::UnknownService(service.into())),
            }
        } else {
            Ok(Identifier::Ss58(AccountId::from_string(username)?))
        };
        if parts.next().is_some() {
            return Err(IdentifierError::InvalidIdentifier);
        }
        result
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum IdentifierError {
    #[error("unknown service {0}")]
    UnknownService(String),
    #[error("invalid identifier")]
    InvalidIdentifier,
    #[error("invalid ss58: {0}")]
    InvalidSs58(InvalidSs58),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{0:?}")]
pub struct InvalidSs58(PublicError);

impl From<PublicError> for IdentifierError {
    fn from(error: PublicError) -> Self {
        Self::InvalidSs58(InvalidSs58(error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_keyring::AccountKeyring;

    #[test]
    fn parse_identifer() {
        if let Err(IdentifierError::InvalidSs58(_)) = Identifier::from_str("dvc94ch") {
        } else {
            panic!()
        }
        assert_eq!(
            Identifier::from_str("dvc94ch@github"),
            Ok(Identifier::Github("dvc94ch".into()))
        );
        assert_eq!(
            Identifier::from_str("dvc94ch@twitter"),
            Err(IdentifierError::UnknownService("twitter".into()))
        );
        assert_eq!(
            Identifier::from_str("@dvc94ch"),
            Err(IdentifierError::InvalidIdentifier)
        );
        let alice = AccountKeyring::Alice.to_account_id();
        assert_eq!(
            Identifier::from_str(&alice.to_string()),
            Ok(Identifier::Ss58(alice))
        );
    }
}
