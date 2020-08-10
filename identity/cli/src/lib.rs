pub mod account;
pub mod device;
pub mod id;
pub mod key;
pub mod wallet;

use substrate_subxt::system::System;
use substrate_subxt::Runtime;
use sunshine_client_utils::crypto::bip39::Mnemonic;
use sunshine_client_utils::crypto::keychain::TypedPair;
use sunshine_client_utils::crypto::keystore::{Keystore, KeystoreInitialized};
use sunshine_client_utils::crypto::secrecy::{ExposeSecret, SecretString};
use sunshine_client_utils::{Client, Result};

pub fn ask_for_new_password(length: u8) -> std::result::Result<SecretString, std::io::Error> {
    loop {
        let password = ask_for_password("Please enter a new password (8+ characters):\n", length)?;
        let password2 = ask_for_password("Please confirm your new password:\n", length)?;
        if password.expose_secret() == password2.expose_secret() {
            return Ok(password);
        }
        println!("Passwords don't match.");
    }
}

pub fn ask_for_password(
    prompt: &str,
    length: u8,
) -> std::result::Result<SecretString, std::io::Error> {
    loop {
        let password = SecretString::new(rpassword::prompt_password_stdout(prompt)?);
        if password.expose_secret().len() >= length as usize {
            return Ok(password);
        }
        println!(
            "Password too short, needs to be at least {} characters.",
            length
        );
    }
}

pub async fn ask_for_phrase(prompt: &str) -> std::result::Result<Mnemonic, std::io::Error> {
    loop {
        println!("{}", prompt);
        let mut words = Vec::with_capacity(24);
        while words.len() < 24 {
            let mut line = String::new();
            async_std::io::stdin().read_line(&mut line).await?;
            for word in line.split(' ') {
                words.push(word.trim().to_string());
            }
        }
        println!();
        if let Ok(mnemonic) = Mnemonic::parse(&words.join(" ")) {
            return Ok(mnemonic);
        }
        println!("Invalid mnemonic");
    }
}

pub async fn set_device_key<T, C>(
    client: &mut C,
    paperkey: bool,
    suri: Option<&str>,
    force: bool,
) -> Result<<T as System>::AccountId>
where
    T: Runtime,
    C: Client<T>,
{
    if client.keystore().is_initialized().await? && !force {
        return Err(KeystoreInitialized.into());
    }
    let password = ask_for_new_password(8)?;

    let dk = if paperkey {
        let mnemonic = ask_for_phrase("Please enter your backup phrase:").await?;
        TypedPair::<C::KeyType>::from_mnemonic(&mnemonic)?
    } else if let Some(suri) = &suri {
        TypedPair::<C::KeyType>::from_suri(&suri)?
    } else {
        TypedPair::<C::KeyType>::generate().await
    };
    client.set_key(dk, &password, force).await?;
    Ok(client.signer()?.account_id().clone())
}
