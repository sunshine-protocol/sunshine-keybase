use crate::error::NoAccount;
use crate::service::{Service, ServiceParseError};
use crate::{Identity, IdentityClient};
use sp_core::crypto::Ss58Codec;
use std::str::FromStr;
use substrate_subxt::{sp_core, system::System};
use sunshine_client_utils::{crypto::ss58::Ss58, Node, Result};

pub async fn resolve<N, C>(
    client: &C,
    identifier: Option<Identifier<N::Runtime>>,
) -> Result<<N::Runtime as Identity>::Uid>
where
    N: Node,
    N::Runtime: Identity,
    C: IdentityClient<N>,
{
    let identifier = if let Some(identifier) = identifier {
        identifier
    } else {
        Identifier::Account(client.signer()?.account_id().clone())
    };
    let uid = match identifier {
        Identifier::Uid(uid) => uid,
        Identifier::Account(account_id) => client.fetch_uid(&account_id).await?.ok_or(NoAccount)?,
        Identifier::Service(service) => client.resolve(&service).await?,
    };
    Ok(uid)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Identifier<R: Identity> {
    Uid(R::Uid),
    Account(R::AccountId),
    Service(Service),
}

impl<R: Identity> core::fmt::Display for Identifier<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Uid(uid) => write!(f, "{}", uid),
            Self::Account(account_id) => write!(f, "{}", account_id.to_string()),
            Self::Service(service) => write!(f, "{}", service),
        }
    }
}

impl<R: Identity> FromStr for Identifier<R>
where
    <R as System>::AccountId: Ss58Codec,
{
    type Err = ServiceParseError;

    fn from_str(string: &str) -> core::result::Result<Self, Self::Err> {
        if let Ok(uid) = R::Uid::from_str(string) {
            Ok(Self::Uid(uid))
        } else if let Ok(Ss58(account_id)) = Ss58::<R>::from_str(string) {
            Ok(Self::Account(account_id))
        } else {
            Ok(Self::Service(Service::from_str(string)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;
    use test_client::client::AccountKeyring;
    use test_client::identity::{Identifier, Service, ServiceParseError};
    use test_client::Runtime;

    #[test]
    fn parse_identifer() {
        assert_eq!(
            Identifier::from_str("dvc94ch@github"),
            Ok(Identifier::<Runtime>::Service(Service::Github(
                "dvc94ch".into()
            )))
        );
        assert_eq!(
            Identifier::<Runtime>::from_str("dvc94ch@twitter"),
            Err(ServiceParseError::Unknown("twitter".into()))
        );
        assert_eq!(
            Identifier::<Runtime>::from_str("@dvc94ch"),
            Err(ServiceParseError::Invalid)
        );
        let alice = AccountKeyring::Alice.to_account_id();
        assert_eq!(
            Identifier::<Runtime>::from_str(&alice.to_string()),
            Ok(Identifier::Account(alice))
        );
    }
}
