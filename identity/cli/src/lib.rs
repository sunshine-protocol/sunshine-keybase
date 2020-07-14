pub mod account;
pub mod device;
mod error;
pub mod id;
pub mod key;
pub mod wallet;

pub use crate::error::{Error, Result};

use keystore::bip39::{Language, Mnemonic};
use substrate_subxt::system::System;
use sunshine_core::{ExposeSecret, Key, Keystore, SecretString};

pub(crate) use async_trait::async_trait;
pub(crate) use identity_client::{Identity, IdentityClient};
pub(crate) use substrate_subxt::Runtime;
pub(crate) use sunshine_core::ChainClient;

#[async_trait]
pub trait Command<T: Runtime + Identity, C: IdentityClient<T>>: Send + Sync {
    async fn exec(&self, client: &mut C) -> Result<(), C::Error>;
}

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
        if let Ok(mnemonic) = Mnemonic::from_phrase(&words.join(" "), Language::English) {
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
) -> Result<<T as System>::AccountId, C::Error>
where
    T: Runtime + Identity,
    C: IdentityClient<T>,
{
    if client.keystore().chain_signer().is_some() && !force {
        return Err(Error::HasDeviceKey);
    }
    let password = ask_for_new_password(8)?;

    let dk = if paperkey {
        let mnemonic = ask_for_phrase("Please enter your backup phrase:").await?;
        <C::Keystore as Keystore<T>>::Key::from_mnemonic(&mnemonic)?
    } else if let Some(suri) = &suri {
        <C::Keystore as Keystore<T>>::Key::from_suri(&suri)?
    } else {
        <C::Keystore as Keystore<T>>::Key::generate().await
    };
    client
        .keystore_mut()
        .set_device_key(&dk, &password, force)
        .await
        .map_err(|e| Error::Client(e.into()))?;
    Ok(dk.to_account_id())
}
