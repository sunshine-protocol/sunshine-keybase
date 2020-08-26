use crate::claim::{Claim, ClaimBody, IdentityInfo, IdentityStatus, UnsignedClaim};
use crate::error::{InvalidClaim, NoAccount, NoBlockHash, ResolveFailure, RuntimeInvalid};
use crate::keystore::{Keystore, Mask};
use crate::service::Service;
use crate::subxt::*;
use codec::{Decode, Encode};
use core::convert::TryInto;
use libipld::cache::{Cache, ReadonlyCache};
use libipld::cbor::DagCborCodec;
use libipld::cid::Cid;
use libipld::store::ReadonlyStore;
use std::collections::HashMap;
use std::time::Duration;
use std::time::UNIX_EPOCH;
use substrate_subxt::sp_core::crypto::{Pair, Ss58Codec};
use substrate_subxt::sp_runtime::traits::{IdentifyAccount, SignedExtension, Verify};
use substrate_subxt::system::System;
use substrate_subxt::{EventSubscription, EventsDecoder, Runtime, SignedExtra};
use sunshine_client_utils::crypto::{
    bip39::Mnemonic,
    keychain::{KeyType, TypedPair},
    secrecy::SecretString,
    signer::GenericSigner,
};
use sunshine_client_utils::{Client, OffchainClient, Result, Signer};

async fn set_identity<R, C>(client: &C, claim: Claim) -> Result<()>
where
    R: Runtime + Identity,
    <<R::Extra as SignedExtra<R>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<R>,
    C::OffchainClient: Cache<<C::OffchainClient as OffchainClient>::Store, DagCborCodec, Claim>,
    <<C::OffchainClient as OffchainClient>::Store as ReadonlyStore>::Codec:
        From<DagCborCodec> + Into<DagCborCodec>,
{
    let prev = claim.claim().prev.clone();
    let root = client.offchain_client().insert(claim).await?;
    let prev_cid = prev.clone().map(Into::into);
    let root_cid = root.clone().into();
    client.offchain_client().flush().await?;
    client
        .chain_client()
        .set_identity_and_watch(&client.chain_signer()?, &prev_cid, &root_cid)
        .await?
        .identity_changed()?;
    if let Some(prev) = prev {
        client.offchain_client().unpin(&prev).await?;
    }
    Ok(())
}

async fn fetch_identity<T, C>(client: &C, uid: T::Uid) -> Result<Option<Cid>>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<T>,
{
    Ok(client
        .chain_client()
        .identity(uid, None)
        .await?
        .map(Into::into))
}

async fn create_claim<R, C>(
    client: &C,
    body: ClaimBody,
    expire_in: Option<Duration>,
    uid: R::Uid,
) -> Result<Claim>
where
    R: Runtime + Identity,
    <<R::Extra as SignedExtra<R>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<R>,
    C::OffchainClient: Cache<<C::OffchainClient as OffchainClient>::Store, DagCborCodec, Claim>,
    <<C::OffchainClient as OffchainClient>::Store as ReadonlyStore>::Codec:
        From<DagCborCodec> + Into<DagCborCodec>,
    R::AccountId: Ss58Codec,
{
    let genesis = client.chain_client().genesis().as_ref().to_vec();
    let block = client
        .chain_client()
        .block_hash(None)
        .await?
        .ok_or(NoBlockHash)?
        .as_ref()
        .to_vec();
    let prev = fetch_identity(client, uid).await?;
    let prev_seqno = if let Some(prev) = prev.as_ref() {
        client.offchain_client().get(prev).await?.claim().seqno
    } else {
        0
    };
    let public = client.signer()?.account_id().to_ss58check();
    let expire_in = expire_in
        .unwrap_or_else(|| Duration::from_millis(u64::MAX))
        .as_millis() as u64;
    let ctime = UNIX_EPOCH.elapsed().unwrap().as_millis() as u64;
    let claim = UnsignedClaim {
        genesis,
        block,
        uid: uid.into(),
        public,
        prev,
        seqno: prev_seqno + 1,
        ctime,
        expire_in,
        body,
    };
    let signature = client.signer()?.sign(&claim.to_bytes()?);
    let signature = Encode::encode(&signature);
    Ok(Claim::new(claim, signature))
}

async fn verify_claim<R, C>(client: &C, uid: R::Uid, claim: &Claim) -> Result<()>
where
    R: Runtime + Identity,
    <<R::Extra as SignedExtra<R>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<R>,
    C::OffchainClient: Cache<<C::OffchainClient as OffchainClient>::Store, DagCborCodec, Claim>,
    <<C::OffchainClient as OffchainClient>::Store as ReadonlyStore>::Codec:
        From<DagCborCodec> + Into<DagCborCodec>,
    R::Signature: Decode,
    <R::Signature as Verify>::Signer: IdentifyAccount<AccountId = R::AccountId>,
    R::AccountId: Ss58Codec,
{
    if claim.claim().uid != uid.into() {
        return Err(InvalidClaim("uid").into());
    }
    if &claim.claim().genesis[..] != client.chain_client().genesis().as_ref() {
        return Err(InvalidClaim("genesis").into());
    }
    let prev_seqno = if let Some(prev) = claim.claim().prev.as_ref() {
        client.offchain_client().get(prev).await?.claim().seqno
    } else {
        0
    };
    if claim.claim().seqno != prev_seqno + 1 {
        return Err(InvalidClaim("seqno").into());
    }
    let block = Decode::decode(&mut &claim.claim().block[..])?;
    let keys = client.chain_client().keys(uid, Some(block)).await?;
    let key = keys
        .iter()
        .find(|k| k.to_ss58check() == claim.claim().public)
        .ok_or(InvalidClaim("key"))?;
    let bytes = claim.claim().to_bytes()?;
    let signature: R::Signature = Decode::decode(&mut claim.signature())?;
    if !signature.verify(&bytes[..], key) {
        return Err(InvalidClaim("signature").into());
    }
    Ok(())
}

pub async fn create_account_for<T, C>(client: &C, key: &<T as System>::AccountId) -> Result<()>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<T>,
{
    client
        .chain_client()
        .create_account_for_and_watch(&client.chain_signer()?, key)
        .await?
        .account_created()?;
    Ok(())
}

pub async fn add_paperkey<T, C, K>(client: &C) -> Result<Mnemonic>
where
    T: Runtime + Identity,
    T::AccountId: Into<T::Address>,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    <T::Signature as Verify>::Signer: From<<K::Pair as Pair>::Public>
        + TryInto<<K::Pair as Pair>::Public>
        + IdentifyAccount<AccountId = T::AccountId>
        + Clone
        + Send
        + Sync,
    C: Client<T>,
    K: KeyType,
    <K::Pair as Pair>::Signature: Into<T::Signature>,
{
    let mnemonic = Mnemonic::generate(24).expect("word count is a multiple of six; qed");
    let key = TypedPair::<K>::from_mnemonic(&mnemonic).expect("have enough entropy bits; qed");
    let signer = GenericSigner::<T, K>::new(key);
    add_key(client, signer.account_id()).await?;
    Ok(mnemonic)
}

pub async fn add_key<T, C>(client: &C, key: &<T as System>::AccountId) -> Result<()>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<T>,
{
    client
        .chain_client()
        .add_key_and_watch(&client.chain_signer()?, key)
        .await?
        .key_added()?;
    Ok(())
}

pub async fn remove_key<T, C>(client: &C, key: &<T as System>::AccountId) -> Result<()>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<T>,
{
    client
        .chain_client()
        .remove_key_and_watch(&client.chain_signer()?, key)
        .await?
        .key_removed()?;
    Ok(())
}

pub async fn change_password<T, C, K>(client: &C, password: &SecretString) -> Result<()>
where
    T: Runtime + Identity<Gen = u16, Mask = [u8; 32]>,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<T, KeyType = K, Keystore = Keystore<K>>,
    K: KeyType,
{
    let (mask, gen) = client.keystore().change_password_mask(password).await?;
    client
        .chain_client()
        .change_password_and_watch(&client.chain_signer()?, mask.as_ref(), gen)
        .await?;
    Ok(())
}

pub async fn update_password<T, C, K>(client: &mut C) -> Result<()>
where
    T: Runtime + Identity<Gen = u16, Mask = [u8; 32]>,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<T, KeyType = K, Keystore = Keystore<K>>,
    K: KeyType,
{
    let uid = fetch_uid(client, &client.signer()?.account_id())
        .await?
        .ok_or(NoAccount)?;
    let pgen = client.chain_client().password_gen(uid, None).await?;
    let gen = client.keystore().gen().await?;
    for g in gen..pgen {
        log::info!("Password change detected: reencrypting keystore");
        let mask = client
            .chain_client()
            .password_mask(uid, g + 1, None)
            .await?
            .ok_or(RuntimeInvalid)?;
        client
            .keystore_mut()
            .apply_mask(&Mask::new(mask), g + 1)
            .await?;
    }
    Ok(())
}

pub async fn subscribe_password_changes<T, C>(client: &C) -> Result<EventSubscription<T>>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<T>,
{
    let subscription = client.chain_client().subscribe_events().await.unwrap();
    let mut decoder = EventsDecoder::<T>::new(client.chain_client().metadata().clone());
    decoder.with_identity();
    let mut subscription = EventSubscription::<T>::new(subscription, decoder);
    subscription.filter_event::<PasswordChangedEvent<_>>();
    Ok(subscription)
}

pub async fn fetch_uid<T, C>(client: &C, key: &<T as System>::AccountId) -> Result<Option<T::Uid>>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<T>,
{
    Ok(client.chain_client().uid_lookup(key, None).await?)
}

pub async fn fetch_keys<T, C>(
    client: &C,
    uid: T::Uid,
    hash: Option<T::Hash>,
) -> Result<Vec<<T as System>::AccountId>>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<T>,
{
    let keys = client.chain_client().keys(uid, hash).await?;
    if keys.is_empty() {
        return Err(ResolveFailure.into());
    }
    Ok(keys)
}

pub async fn fetch_account<T, C>(client: &C, uid: T::Uid) -> Result<T::IdAccountData>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<T>,
{
    Ok(client.chain_client().account(uid, None).await?)
}

pub async fn prove_identity<R, C>(client: &C, service: Service) -> Result<String>
where
    R: Runtime + Identity,
    <<R::Extra as SignedExtra<R>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<R>,
    C::OffchainClient: Cache<<C::OffchainClient as OffchainClient>::Store, DagCborCodec, Claim>,
    <<C::OffchainClient as OffchainClient>::Store as ReadonlyStore>::Codec:
        From<DagCborCodec> + Into<DagCborCodec>,
    R::AccountId: Ss58Codec,
{
    let uid = fetch_uid(client, client.signer()?.account_id())
        .await?
        .ok_or(NoAccount)?;
    let claim = create_claim(client, ClaimBody::Ownership(service.clone()), None, uid).await?;
    let proof = service.proof(&claim)?;
    set_identity(client, claim).await?;
    Ok(proof)
}

pub async fn revoke_identity<R, C>(client: &C, service: Service) -> Result<()>
where
    R: Runtime + Identity,
    <<R::Extra as SignedExtra<R>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<R>,
    C::OffchainClient: Cache<<C::OffchainClient as OffchainClient>::Store, DagCborCodec, Claim>,
    <<C::OffchainClient as OffchainClient>::Store as ReadonlyStore>::Codec:
        From<DagCborCodec> + Into<DagCborCodec>,
    R::AccountId: Ss58Codec,
    R::Signature: Decode,
    <R::Signature as Verify>::Signer: IdentifyAccount<AccountId = R::AccountId>,
{
    let uid = fetch_uid(client, client.signer()?.account_id())
        .await?
        .ok_or(NoAccount)?;
    let id = identity(client, uid)
        .await?
        .into_iter()
        .find(|id| id.service == service && id.status != IdentityStatus::Revoked);
    if let Some(id) = id {
        let seqno = id.claims.last().unwrap().claim().seqno;
        let claim = create_claim(client, ClaimBody::Revoke(seqno), None, uid).await?;
        set_identity(client, claim).await?;
    }
    Ok(())
}

pub async fn identity<R, C>(client: &C, uid: R::Uid) -> Result<Vec<IdentityInfo>>
where
    R: Runtime + Identity,
    <<R::Extra as SignedExtra<R>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<R>,
    C::OffchainClient: Cache<<C::OffchainClient as OffchainClient>::Store, DagCborCodec, Claim>,
    <<C::OffchainClient as OffchainClient>::Store as ReadonlyStore>::Codec:
        From<DagCborCodec> + Into<DagCborCodec>,
    R::AccountId: Ss58Codec,
    R::Signature: Decode,
    <R::Signature as Verify>::Signer: IdentifyAccount<AccountId = R::AccountId>,
{
    let mut claims = vec![];
    let mut next = fetch_identity(client, uid).await?;
    while let Some(cid) = next {
        let claim = client.offchain_client().get(&cid).await?;
        next = claim.claim().prev.clone();
        verify_claim(client, uid, &claim).await?;
        claims.push(claim);
    }
    let mut ids = HashMap::<Service, Vec<Claim>>::new();
    for claim in claims.iter().rev() {
        match claim.claim().body.clone() {
            ClaimBody::Ownership(service) => {
                ids.entry(service.clone()).or_default().push(claim.clone());
            }
            ClaimBody::Revoke(seqno) => {
                let index = claims.len() - seqno as usize;
                if let Some(claim2) = claims.get(index) {
                    if let ClaimBody::Ownership(service) = &claim2.claim().body {
                        ids.entry(service.clone()).or_default().push(claim.clone());
                    } else {
                        return Err(InvalidClaim("cannot revoke: claim is not revokable").into());
                    }
                } else {
                    return Err(InvalidClaim("cannot revoke: claim not found").into());
                }
            }
        }
    }

    let mut info = vec![];
    for (service, claims) in ids.into_iter() {
        let mut status = IdentityStatus::ProofNotFound;
        let mut proof = None;
        for claim in &claims {
            match &claim.claim().body {
                ClaimBody::Ownership(_) => {
                    if claim.claim().expired() {
                        status = IdentityStatus::Expired;
                    } else {
                        status = IdentityStatus::ProofNotFound;
                        proof = Some(claim);
                    }
                }
                ClaimBody::Revoke(seqno) => {
                    if let Some(p) = proof {
                        if p.claim().seqno == *seqno {
                            status = IdentityStatus::Revoked;
                            proof = None;
                        }
                    }
                }
            }
        }
        if status == IdentityStatus::ProofNotFound {
            if let Some(proof) = proof {
                if let Ok(proof_url) = service.verify(proof.signature()).await {
                    status = IdentityStatus::Active(proof_url);
                }
            }
        }
        info.push(IdentityInfo {
            service,
            claims,
            status,
        });
    }
    Ok(info)
}

pub async fn resolve<R, C>(client: &C, service: &Service) -> Result<R::Uid>
where
    R: Runtime + Identity,
    <<R::Extra as SignedExtra<R>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: Client<R>,
    C::OffchainClient: Cache<<C::OffchainClient as OffchainClient>::Store, DagCborCodec, Claim>,
    <<C::OffchainClient as OffchainClient>::Store as ReadonlyStore>::Codec:
        From<DagCborCodec> + Into<DagCborCodec>,
    R::AccountId: Ss58Codec,
    R::Signature: Decode,
    <R::Signature as Verify>::Signer: IdentifyAccount<AccountId = R::AccountId>,
{
    let uids = service.resolve().await?;
    for uid in uids {
        let uid = if let Ok(uid) = uid.parse() {
            uid
        } else {
            continue;
        };
        for id in identity(client, uid).await? {
            if &id.service == service {
                if let IdentityStatus::Active(_) = &id.status {
                    return Ok(uid);
                }
            }
        }
    }
    Err(ResolveFailure.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_client::client::Client as _;
    use test_client::identity::{IdentityClient, IdentityStatus, Service};
    use test_client::mock::{test_node, AccountKeyring, ClientWithKeystore as Client};

    #[async_std::test]
    async fn prove_identity() {
        let (node, _node_tmp) = test_node();
        let (client, _tmp) = Client::mock_with_keystore(&node, AccountKeyring::Alice).await;
        let account_id = AccountKeyring::Alice.to_account_id();
        let uid = client.fetch_uid(&account_id).await.unwrap().unwrap();
        let service = Service::Github("dvc94ch".into());

        let ids = client.identity(uid).await.unwrap();
        assert_eq!(ids.len(), 0);

        client.prove_identity(service.clone()).await.unwrap();
        let ids = client.identity(uid).await.unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(&ids[0].service, &service);
        assert_eq!(ids[0].status, IdentityStatus::ProofNotFound);

        client.revoke_identity(service.clone()).await.unwrap();
        let ids = client.identity(uid).await.unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(&ids[0].service, &service);
        assert_eq!(ids[0].status, IdentityStatus::Revoked);

        client.prove_identity(service.clone()).await.unwrap();
        let ids = client.identity(uid).await.unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(&ids[0].service, &service);
        assert_eq!(ids[0].status, IdentityStatus::ProofNotFound);
    }

    #[async_std::test]
    async fn change_password() {
        let (node, _node_tmp) = test_node();
        let (mut client1, _tmp) = Client::mock_with_keystore(&node, AccountKeyring::Alice).await;
        let (client2, _tmp) = Client::mock_with_keystore(&node, AccountKeyring::Eve).await;

        let signer2 = client2.signer().unwrap();
        client1.add_key(signer2.account_id()).await.unwrap();
        let mut sub = client1.subscribe_password_changes().await.unwrap();

        let password = SecretString::new("password2".to_string());
        client2.change_password(&password).await.unwrap();

        let event = sub.next().await;
        assert!(event.is_some());
        client1.update_password().await.unwrap();
        client1.lock().await.unwrap();
        client1.unlock(&password).await.unwrap();
    }

    #[async_std::test]
    async fn provision_device() {
        let (node, _node_tmp) = test_node();
        let (mut client1, _tmp) = Client::mock_with_keystore(&node, AccountKeyring::Alice).await;
        let (mut client2, _tmp) = Client::mock_with_keystore(&node, AccountKeyring::Eve).await;

        let password = SecretString::new("abcdefgh".to_string());
        let (mask, gen) = client1
            .keystore_mut()
            .change_password_mask(&password)
            .await
            .unwrap();
        client1.keystore_mut().apply_mask(&mask, gen).await.unwrap();

        let (pass, gen) = client1.keystore().password().await.unwrap();
        client2
            .keystore_mut()
            .provision_device(&pass, gen)
            .await
            .unwrap();

        client2.lock().await.unwrap();
        client2.unlock(&password).await.unwrap();
    }
}
