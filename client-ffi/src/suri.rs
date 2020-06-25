use core::fmt::{self, Debug};
use std::str::FromStr;
use substrate_subxt::sp_core::{sr25519, Pair};

#[derive(Clone)]
pub struct Suri(pub [u8; 32]);

impl Debug for Suri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "*****")
    }
}

impl FromStr for Suri {
    type Err = String;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let (_, seed) = sr25519::Pair::from_string_with_seed(string, None)
            .map_err(|_| "InvalidSuri".to_owned())?;
        Ok(Self(seed.unwrap()))
    }
}
