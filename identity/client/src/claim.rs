use crate::service::Service;
use libipld::cbor::DagCborCodec;
use libipld::cid::Cid;
use libipld::codec::Codec as _;
use libipld::DagCbor;
use std::time::{Duration, UNIX_EPOCH};
use sunshine_client_utils::Result;

#[derive(Clone, Debug, Eq, PartialEq, DagCbor)]
pub struct Claim {
    claim: UnsignedClaim,
    signature: Vec<u8>,
}

impl Claim {
    pub fn new(claim: UnsignedClaim, signature: Vec<u8>) -> Self {
        Self { claim, signature }
    }

    pub fn claim(&self) -> &UnsignedClaim {
        &self.claim
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

impl core::fmt::Display for Claim {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self.claim().body)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, DagCbor)]
pub struct UnsignedClaim {
    /// The chain that this claim is valid for.
    pub genesis: Vec<u8>,
    /// The block at which the signing key was valid.
    pub block: Vec<u8>,
    /// The user that is making the claim.
    pub uid: u64,
    /// The public key used for signing the claim.
    pub public: String,
    /// The previous claim that the user made.
    pub prev: Option<Cid>,
    /// The sequence number of the claim.
    pub seqno: u32,
    /// The time this claim was made at.
    pub ctime: u64,
    /// The time at which the claim becomes invalid.
    pub expire_in: u64,
    /// The claim.
    pub body: ClaimBody,
}

impl UnsignedClaim {
    pub fn expired(&self) -> bool {
        let expires_at = Duration::from_millis(self.ctime.saturating_add(self.expire_in));
        UNIX_EPOCH.elapsed().unwrap() > expires_at
    }

    pub fn to_bytes(&self) -> Result<Box<[u8]>> {
        Ok(DagCborCodec.encode(self)?.into_boxed_slice())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, DagCbor)]
pub enum ClaimBody {
    Ownership(Service),
    Revoke(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityStatus {
    Expired,
    Revoked,
    ProofNotFound,
    Active(String),
}

impl core::fmt::Display for IdentityStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Expired => write!(f, "expired"),
            Self::Revoked => write!(f, "revoked"),
            Self::ProofNotFound => write!(f, "proof not found"),
            Self::Active(proof) => write!(f, "{}", proof),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityInfo {
    pub service: Service,
    pub claims: Vec<Claim>,
    pub status: IdentityStatus,
}

impl core::fmt::Display for IdentityInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{} {}", self.service, self.status)
    }
}
