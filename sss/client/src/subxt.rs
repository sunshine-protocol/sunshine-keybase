use frame_support::Parameter;
use parity_scale_codec::{Decode, Encode};
use sp_runtime::traits::{CheckedAdd, CheckedSub, Member};
use substrate_subxt::sp_runtime;
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt::{module, Call, Event, Store};

#[module]
pub trait Secret: System {
    /// Secret group ID type.
    type SecretId: Parameter + Member + Copy + Default + CheckedAdd + From<u8> + Into<u64>;

    /// Round identifier.
    type RoundId: Parameter
        + Member
        + Copy
        + Default
        + CheckedAdd
        + CheckedSub
        + From<u8>
        + Encode
        + Ord
        + Into<u64>;
}

use sunshine_split::{Group, RecoverySt, Threshold};
pub type Gov<T> = Group<<T as Secret>::SecretId, <T as System>::AccountId>;
pub type RecSt<T> =
    RecoverySt<(<T as Secret>::SecretId, <T as Secret>::RoundId), <T as System>::Hash>;

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct GroupsStore<T: Secret> {
    #[store(returns = Option<Gov<T>>)]
    pub secret_id: T::SecretId,
}

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct CommitsStore<T: Secret> {
    #[store(returns = Option<RecSt<T>>)]
    pub secret_id: T::SecretId,
    pub round_id: T::RoundId,
}

#[derive(Clone, Debug, Eq, Encode, PartialEq, Store)]
pub struct RoundStore<T: Secret> {
    #[store(returns = T::RoundId)]
    pub secret_id: T::SecretId,
}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct CreateGroupCall<T: Secret> {
    pub set: Vec<T::AccountId>,
}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct AddMemberCall<'a, T: Secret> {
    pub secret_id: T::SecretId,
    pub member: &'a <T as System>::AccountId,
}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct RemoveMemberCall<'a, T: Secret> {
    pub secret_id: T::SecretId,
    pub member: &'a <T as System>::AccountId,
}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct SplitSecretCall<'a, T: Secret> {
    pub secret_id: T::SecretId,
    pub commit: &'a [<T as System>::Hash],
    threshold: Threshold,
}

#[derive(Call, Clone, Debug, Eq, Encode, PartialEq)]
pub struct PublishProofCall<'a, T: Secret> {
    pub secret_id: T::SecretId,
    pub proof: &'a [u8],
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct NewGroupEvent<T: Secret> {
    pub secret_id: T::SecretId,
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct SplitSecretEvent<T: Secret> {
    pub secret_id: T::SecretId,
    pub round: T::RoundId,
    pub thresh: Threshold,
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct MemberAddedEvent<T: Secret> {
    pub secret_id: T::SecretId,
    pub who: <T as System>::AccountId,
}

#[derive(Clone, Debug, Decode, Eq, Event, PartialEq)]
pub struct MemberRemovedEvent<T: Secret> {
    pub secret_id: T::SecretId,
    pub who: <T as System>::AccountId,
}
