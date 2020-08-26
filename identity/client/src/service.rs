use crate::claim::Claim;
use crate::github;
use core::str::FromStr;
use libipld::cbor::DagCborCodec;
use libipld::codec::Codec;
use libipld::json::DagJsonCodec;
use libipld::multibase::{encode, Base};
use libipld::{DagCbor, Ipld};
use sunshine_client_utils::Result;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Hash, DagCbor)]
pub enum Service {
    Github(String),
}

impl Service {
    pub fn username(&self) -> &str {
        match self {
            Self::Github(username) => &username,
        }
    }

    pub fn service(&self) -> &str {
        match self {
            Self::Github(_) => "github",
        }
    }

    pub async fn verify(&self, signature: &[u8]) -> Result<String> {
        let signature = encode(Base::Base64, signature);
        match self {
            Self::Github(user) => github::verify(&user, &signature).await,
        }
    }

    pub async fn resolve(&self) -> Result<Vec<String>> {
        match self {
            Self::Github(user) => github::resolve(&user).await,
        }
    }

    pub fn proof(&self, claim: &Claim) -> Result<String> {
        let genesis = encode(Base::Base64, &claim.claim().genesis);
        let block = encode(Base::Base64, &claim.claim().block);
        let uid = claim.claim().uid.to_string();
        let public = &claim.claim().public;
        let signature = encode(Base::Base64, claim.signature());

        let bytes = DagCborCodec.encode(claim.claim())?;
        let ipld: Ipld = DagCborCodec.decode(&bytes)?;
        let bytes = DagJsonCodec.encode(&ipld)?;
        let object = std::str::from_utf8(&bytes).expect("json codec returns valid utf8");

        Ok(match self {
            Self::Github(user) => {
                github::proof(&genesis, &block, &uid, &user, &public, &object, &signature)
            }
        })
    }

    pub fn cli_instructions(&self) -> String {
        match self {
            Self::Github(_) => github::cli_instructions(),
        }
    }
}

impl core::fmt::Display for Service {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}@{}", self.username(), self.service())
    }
}

impl FromStr for Service {
    type Err = ServiceParseError;

    fn from_str(string: &str) -> core::result::Result<Self, Self::Err> {
        let mut parts = string.split('@');
        let username = parts.next().ok_or(ServiceParseError::Invalid)?;
        if username.is_empty() {
            return Err(ServiceParseError::Invalid);
        }
        let service = parts.next().ok_or(ServiceParseError::Invalid)?;
        if service.is_empty() {
            return Err(ServiceParseError::Invalid);
        }
        if parts.next().is_some() {
            return Err(ServiceParseError::Invalid);
        }
        match service {
            "github" => Ok(Self::Github(username.into())),
            _ => Err(ServiceParseError::Unknown(service.into())),
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ServiceParseError {
    #[error("Expected a service description of the form username@service.")]
    Invalid,
    #[error("Unknown service '{0}'")]
    Unknown(String),
}
