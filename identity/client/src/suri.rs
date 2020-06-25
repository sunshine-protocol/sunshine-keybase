use core::fmt::{self, Debug};
use sp_core::crypto::{Pair, SecretStringError};
use std::str::FromStr;
use substrate_subxt::sp_core::{self, sr25519};
use thiserror::Error;

#[derive(Clone)]
pub struct Suri(pub [u8; 32]);

impl Debug for Suri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "*****")
    }
}

#[derive(Debug, Error)]
#[error("Invalid suri encoded key pair: {0:?}")]
pub struct InvalidSuri(SecretStringError);

impl FromStr for Suri {
    type Err = InvalidSuri;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let (_, seed) = sr25519::Pair::from_string_with_seed(string, None)
            .map_err(|err| InvalidSuri(err))?;
        Ok(Self(seed.unwrap()))
    }
}
