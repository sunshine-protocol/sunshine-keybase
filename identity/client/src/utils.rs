use crate::{AbstractClient, Identity};
use crate::error::Error;
use crate::service::{Service, ServiceParseError};
use core::fmt::{self, Debug};
use sp_core::crypto::{Pair, PublicError, SecretStringError, Ss58Codec};
use std::str::FromStr;
use substrate_subxt::{sp_core, system::System, Runtime};
use thiserror::Error;

#[derive(Clone)]
pub struct Suri<P: Pair>(pub P::Seed);

impl<P: Pair> Debug for Suri<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "*****")
    }
}

#[derive(Debug, Error)]
#[error("Invalid suri encoded key pair: {0:?}")]
pub struct InvalidSuri(SecretStringError);

impl<P: Pair> FromStr for Suri<P> {
    type Err = InvalidSuri;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let (_, seed) = P::from_string_with_seed(string, None)
            .map_err(|err| InvalidSuri(err))?;
        Ok(Self(seed.unwrap()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ss58<T: System>(pub T::AccountId);

#[derive(Debug, Error)]
#[error("Invalid ss58 encoded public key: {0:?}")]
pub struct InvalidSs58(PublicError);

impl<T: System> FromStr for Ss58<T>
where
    T::AccountId: Ss58Codec,
{
    type Err = InvalidSs58;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            <T::AccountId as Ss58Codec>::from_string(string).map_err(|err| InvalidSs58(err))?,
        ))
    }
}

pub async fn resolve<T: Runtime + Identity, P: Pair>(
    client: &dyn AbstractClient<T, P>,
    identifier: Option<Identifier<T>>,
) -> Result<T::Uid, Error> {
    let identifier = if let Some(identifier) = identifier {
        identifier
    } else {
        Identifier::Account(client.signer().await?.account_id().clone())
    };
    let uid = match identifier {
        Identifier::Uid(uid) => uid,
        Identifier::Account(account_id) => client
            .fetch_uid(&account_id)
            .await?
            .ok_or(Error::NoAccount)?,
        Identifier::Service(service) => client.resolve(&service).await?,
    };
    Ok(uid)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Identifier<T: Identity> {
    Uid(T::Uid),
    Account(T::AccountId),
    Service(Service),
}

impl<T: Identity> core::fmt::Display for Identifier<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Uid(uid) => write!(f, "{}", uid),
            Self::Account(account_id) => write!(f, "{}", account_id.to_string()),
            Self::Service(service) => write!(f, "{}", service),
        }
    }
}

impl<T: Identity> FromStr for Identifier<T>
where
    <T as System>::AccountId: Ss58Codec,
{
    type Err = ServiceParseError;

    fn from_str(string: &str) -> core::result::Result<Self, Self::Err> {
        if let Ok(uid) = T::Uid::from_str(string) {
            Ok(Self::Uid(uid))
        } else if let Ok(Ss58(account_id)) = Ss58::<T>::from_str(string) {
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
