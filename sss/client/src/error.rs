use thiserror::Error;

#[derive(Debug, Error)]
#[error("Couldn't create secret group")]
pub struct CreateGroup;

#[derive(Debug, Error)]
#[error("Couldn't split secret.")]
pub struct SplitSecret;

#[derive(Debug, Error)]
#[error("Couldn't add member.")]
pub struct AddMember;

#[derive(Debug, Error)]
#[error("Couldn't remove member.")]
pub struct RemoveMember;
