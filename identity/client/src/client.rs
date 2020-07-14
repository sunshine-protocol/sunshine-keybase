use crate::claim::{Claim, ClaimBody, IdentityInfo, IdentityStatus, UnsignedClaim};
use crate::error::Error;
use crate::service::Service;
use crate::subxt::*;
use codec::{Decode, Encode};
use core::convert::TryInto;
use ipld_block_builder::{Cache, Codec, ReadonlyCache};
use keystore::bip39::{Language, Mnemonic, MnemonicType};
use libipld::cid::Cid;
use std::collections::HashMap;
use std::time::Duration;
use std::time::UNIX_EPOCH;
use substrate_subxt::sp_core::crypto::Ss58Codec;
use substrate_subxt::sp_runtime::traits::{IdentifyAccount, SignedExtension, Verify};
use substrate_subxt::system::System;
use substrate_subxt::{EventSubscription, EventsDecoder, Runtime, SignedExtra};
use sunshine_core::{ChainClient, Key, Keystore, SecretString};

async fn set_identity<T, C>(client: &C, claim: Claim) -> Result<(), C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
    C::OffchainClient: Cache<Codec, Claim>,
    C::Error: From<Error>,
{
    let prev = claim.claim().prev.clone();
    let root = client.offchain_client().insert(claim).await?;
    let prev_cid = prev.clone().map(T::Cid::from);
    let root_cid = T::Cid::from(root);
    client
        .chain_client()
        .set_identity_and_watch(client.chain_signer()?, &prev_cid, &root_cid)
        .await?
        .identity_changed()?;
    if let Some(prev) = prev {
        client.offchain_client().unpin(&prev).await?;
    }
    Ok(())
}

async fn fetch_identity<T, C>(client: &C, uid: T::Uid) -> Result<Option<Cid>, C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
    C::Error: From<Error>,
{
    if let Some(bytes) = client.chain_client().identity(uid, None).await? {
        Ok(Some(bytes.try_into().map_err(Error::from)?))
    } else {
        Ok(None)
    }
}

async fn create_claim<T, C>(
    client: &C,
    body: ClaimBody,
    expire_in: Option<Duration>,
    uid: T::Uid,
) -> Result<Claim, C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
    C::OffchainClient: Cache<Codec, Claim>,
    C::Error: From<Error>,
    T::AccountId: Ss58Codec,
{
    let genesis = client.chain_client().genesis().as_ref().to_vec();
    let block = client
        .chain_client()
        .block_hash(None)
        .await?
        .ok_or(Error::NoBlockHash)?
        .as_ref()
        .to_vec();
    let prev = fetch_identity(client, uid).await?;
    let prev_seqno = if let Some(prev) = prev.as_ref() {
        client.offchain_client().get(prev).await?.claim().seqno
    } else {
        0
    };
    let public = client.chain_signer()?.account_id().to_ss58check();
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
    let signature = client.offchain_signer()?.sign(&claim.to_bytes()?);
    let signature = Encode::encode(&signature);
    Ok(Claim::new(claim, signature))
}

async fn verify_claim<T, C>(client: &C, uid: T::Uid, claim: &Claim) -> Result<(), C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
    C::OffchainClient: Cache<Codec, Claim>,
    C::Error: From<Error>,
    T::Signature: Decode,
    <T::Signature as Verify>::Signer: IdentifyAccount<AccountId = T::AccountId>,
    T::AccountId: Ss58Codec,
{
    if claim.claim().uid != uid.into() {
        return Err(Error::InvalidClaim("uid").into());
    }
    if &claim.claim().genesis[..] != client.chain_client().genesis().as_ref() {
        return Err(Error::InvalidClaim("genesis").into());
    }
    let prev_seqno = if let Some(prev) = claim.claim().prev.as_ref() {
        client.offchain_client().get(prev).await?.claim().seqno
    } else {
        0
    };
    if claim.claim().seqno != prev_seqno + 1 {
        return Err(Error::InvalidClaim("seqno").into());
    }
    let block = Decode::decode(&mut &claim.claim().block[..])?;
    let keys = client.chain_client().keys(uid, Some(block)).await?;
    let key = keys
        .iter()
        .find(|k| k.to_ss58check() == claim.claim().public)
        .ok_or(Error::InvalidClaim("key"))?;
    let bytes = claim.claim().to_bytes()?;
    let signature: T::Signature = Decode::decode(&mut claim.signature())?;
    if !signature.verify(&bytes[..], key) {
        return Err(Error::InvalidClaim("signature").into());
    }
    Ok(())
}

pub async fn create_account_for<T, C>(
    client: &C,
    key: &<T as System>::AccountId,
) -> Result<(), C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
{
    client
        .chain_client()
        .create_account_for_and_watch(client.chain_signer()?, key)
        .await?
        .account_created()?;
    Ok(())
}

pub async fn add_paperkey<T, C>(client: &C) -> Result<Mnemonic, C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
{
    let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
    let key = <C::Keystore as Keystore<T>>::Key::from_mnemonic(&mnemonic).unwrap();
    add_key(client, &key.to_account_id()).await?;
    Ok(mnemonic)
}

pub async fn add_key<T, C>(client: &C, key: &<T as System>::AccountId) -> Result<(), C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
{
    client
        .chain_client()
        .add_key_and_watch(client.chain_signer()?, key)
        .await?
        .key_added()?;
    Ok(())
}

pub async fn remove_key<T, C>(client: &C, key: &<T as System>::AccountId) -> Result<(), C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
{
    client
        .chain_client()
        .remove_key_and_watch(client.chain_signer()?, key)
        .await?
        .key_removed()?;
    Ok(())
}

pub async fn change_password<T, C>(client: &C, password: &SecretString) -> Result<(), C::Error>
where
    T: Runtime + Identity<Gen = u16, Mask = [u8; 32]>,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
{
    let mask = client.keystore().change_password_mask(password).await?;
    let gen = client.keystore().gen().await + 1;
    client
        .chain_client()
        .change_password_and_watch(client.chain_signer()?, &mask, gen)
        .await?;
    Ok(())
}

pub async fn update_password<T, C>(client: &C) -> Result<(), C::Error>
where
    T: Runtime + Identity<Gen = u16, Mask = [u8; 32]>,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
    C::Error: From<Error>,
{
    let uid = fetch_uid(client, client.chain_signer()?.account_id())
        .await?
        .ok_or(Error::NoAccount)?;
    let pgen = client.chain_client().password_gen(uid, None).await?.into();
    let gen = client.keystore().gen().await;
    for g in gen..pgen {
        log::info!("Password change detected: reencrypting keystore");
        let mask = client
            .chain_client()
            .password_mask(uid, g + 1, None)
            .await?
            .ok_or(Error::RuntimeInvalid)?;
        client.keystore().apply_mask(&mask, g + 1).await?;
    }
    Ok(())
}

pub async fn subscribe_password_changes<T, C>(client: &C) -> Result<EventSubscription<T>, C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
{
    let subscription = client.chain_client().subscribe_events().await.unwrap();
    let mut decoder = EventsDecoder::<T>::new(client.chain_client().metadata().clone());
    decoder.with_identity();
    let mut subscription = EventSubscription::<T>::new(subscription, decoder);
    subscription.filter_event::<PasswordChangedEvent<_>>();
    Ok(subscription)
}

pub async fn fetch_uid<T, C>(
    client: &C,
    key: &<T as System>::AccountId,
) -> Result<Option<T::Uid>, C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
{
    Ok(client.chain_client().uid_lookup(key, None).await?)
}

pub async fn fetch_keys<T, C>(
    client: &C,
    uid: T::Uid,
    hash: Option<T::Hash>,
) -> Result<Vec<<T as System>::AccountId>, C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
{
    Ok(client.chain_client().keys(uid, hash).await?)
}

pub async fn fetch_account<T, C>(client: &C, uid: T::Uid) -> Result<T::IdAccountData, C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
{
    Ok(client.chain_client().account(uid, None).await?)
}

pub async fn prove_identity<T, C>(client: &C, service: Service) -> Result<String, C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
    C::OffchainClient: Cache<Codec, Claim>,
    C::Error: From<Error>,
    T::AccountId: Ss58Codec,
{
    let uid = fetch_uid(client, client.chain_signer()?.account_id())
        .await?
        .ok_or(Error::NoAccount)?;
    let claim = create_claim(client, ClaimBody::Ownership(service.clone()), None, uid).await?;
    let proof = service.proof(&claim)?;
    set_identity(client, claim).await?;
    Ok(proof)
}

pub async fn revoke_identity<T, C>(client: &C, service: Service) -> Result<(), C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
    C::OffchainClient: Cache<Codec, Claim>,
    C::Error: From<Error>,
    T::AccountId: Ss58Codec,
    T::Signature: Decode,
    <T::Signature as Verify>::Signer: IdentifyAccount<AccountId = T::AccountId>,
{
    let uid = fetch_uid(client, client.chain_signer()?.account_id())
        .await?
        .ok_or(Error::NoAccount)?;
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

pub async fn identity<T, C>(client: &C, uid: T::Uid) -> Result<Vec<IdentityInfo>, C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
    C::OffchainClient: Cache<Codec, Claim>,
    C::Error: From<Error>,
    T::AccountId: Ss58Codec,
    T::Signature: Decode,
    <T::Signature as Verify>::Signer: IdentifyAccount<AccountId = T::AccountId>,
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
                if let Some(claim2) = claims.get(seqno as usize - 1) {
                    if let ClaimBody::Ownership(service) = &claim2.claim().body {
                        ids.entry(service.clone()).or_default().push(claim.clone());
                    }
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

pub async fn resolve<T, C>(client: &C, service: &Service) -> Result<T::Uid, C::Error>
where
    T: Runtime + Identity,
    <<T::Extra as SignedExtra<T>>::Extra as SignedExtension>::AdditionalSigned: Send + Sync,
    C: ChainClient<T>,
    C::OffchainClient: Cache<Codec, Claim>,
    C::Error: From<Error>,
    T::AccountId: Ss58Codec,
    T::Signature: Decode,
    <T::Signature as Verify>::Signer: IdentifyAccount<AccountId = T::AccountId>,
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
    Err(Error::ResolveFailure.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libipld::mem::MemStore;
    use sp_core::sr25519::Pair;
    use sp_core::Pair as _;
    use substrate_subxt::{sp_core, ClientBuilder};
    use test_client::identity::{Client, Service};
    use test_client::mock::{test_node, AccountKeyring, TempDir, TestNode};
    use test_client::Runtime;

    async fn build_client(node: TestNode) -> (Client<Runtime, Pair, MemStore>, TempDir) {
        let tmp = TempDir::new("sunshine-identity-").expect("failed to create tempdir");
        let subxt = ClientBuilder::new().set_client(node).build().await.unwrap();
        let store = MemStore::default();
        let keystore = KeyStore::open(tmp.path()).await.unwrap();
        let client = Client::new(keystore, subxt, store);
        (client, tmp)
    }

    async fn test_client() -> (Client<Runtime, Pair, MemStore>, TestNode, TempDir, TempDir) {
        let (node, tmp1) = test_node();
        let (client, tmp2) = build_client(node.clone()).await;
        let seed = Pair::from_string_with_seed("//Alice", None)
            .unwrap()
            .1
            .unwrap();
        client
            .set_device_key(
                &DeviceKey::from_seed(seed),
                &Password::from("password".to_string()),
                true,
            )
            .await
            .unwrap();
        (client, node, tmp1, tmp2)
    }

    #[async_std::test]
    async fn prove_identity() {
        let (client, _, _tmp1, _tmp2) = test_client().await;
        let account_id = AccountKeyring::Alice.to_account_id();
        let uid = client.fetch_uid(&account_id).await.unwrap().unwrap();
        assert_eq!(client.identity(uid).await.unwrap().len(), 0);
        client
            .prove_identity(Service::Github("dvc94ch".into()))
            .await
            .unwrap();
        assert_eq!(client.identity(uid).await.unwrap().len(), 1);
    }

    #[async_std::test]
    async fn change_password() {
        let (client1, subxt, _tmp1, _tmp2) = test_client().await;
        let (client2, _tmp3) = build_client(subxt).await;
        client2
            .set_device_key(
                &DeviceKey::generate().await,
                &Password::from("password".to_string()),
                true,
            )
            .await
            .unwrap();
        let signer2 = client2.signer().await.unwrap();
        client1.add_key(signer2.account_id()).await.unwrap();
        let mut sub = client1.subscribe_password_changes().await.unwrap();

        let password = Password::from("password2".to_string());
        client2.change_password(&password).await.unwrap();

        let event = sub.next().await;
        assert!(event.is_some());
        client1.update_password().await.unwrap();
        client1.lock().await.unwrap();
        client1.unlock(&password).await.unwrap();
        client1.signer().await.unwrap();
    }
}
