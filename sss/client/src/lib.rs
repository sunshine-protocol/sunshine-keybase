//! Safe Secret Sharing Client
//! 1. encrypt secret with dealer's key
//! 2. split (encrypted) secret into n shares s.t. t<=n can reconstruct
//! 3. commit to hash of shares using substrate (start round)
//! 4. encrypt each share with public key for recipient and send to each member (strobe)
//! 5. holders decrypt their shares and report the decrypted value to verify if it is the preimage of the hash on-chain
pub mod error;
mod subxt;

pub use subxt::*;

use substrate_subxt::system::System;
use sunshine_client_utils::{async_trait, Client, Node, Result};

// TODO: chain event subscriptions

#[async_trait]
pub trait SecretClient<N: Node>: Client<N> + Sized
where
    N::Runtime: Secret,
{
    async fn create_group(
        &self,
        set: Vec<<N::Runtime as System>::AccountId>,
    ) -> Result<<N::Runtime as Secret>::SecretId>;
    async fn split_secret<'a>(
        &self,
        secret_id: <N::Runtime as Secret>::SecretId,
        commit: &'a [<N::Runtime as System>::Hash],
    ) -> Result<<N::Runtime as Secret>::RoundId>;
    async fn group_members(
        &self,
        secret_id: <N::Runtime as Secret>::SecretId,
    ) -> Result<Vec<<N::Runtime as System>::AccountId>>;
    async fn add_member(
        &self,
        secret_id: <N::Runtime as Secret>::SecretId,
        member: &<N::Runtime as System>::AccountId,
    ) -> Result<()>;
    async fn remove_member(
        &self,
        secret_id: <N::Runtime as Secret>::SecretId,
        member: &<N::Runtime as System>::AccountId,
    ) -> Result<()>;
}
