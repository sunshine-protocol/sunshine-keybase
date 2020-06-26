pub mod account;
pub mod device;
mod error;
pub mod id;
pub mod key;
pub mod run;
pub mod wallet;

pub use crate::error::*;

use client_identity::Suri;
use keystore::bip39::{Language, Mnemonic};
use keystore::{DeviceKey, Password};
use substrate_subxt::system::System;


pub(crate) use async_trait::async_trait;
pub(crate) use client_identity::{AbstractClient, Identity};
pub(crate) use substrate_subxt::sp_core::Pair;
pub(crate) use substrate_subxt::Runtime;

#[async_trait]
pub trait Command<T: Runtime + Identity, P: Pair>: Send + Sync {
    async fn exec(&self, client: &dyn AbstractClient<T, P>) -> Result<()>;
}

pub fn ask_for_new_password() -> Result<Password> {
    let password = ask_for_password("Please enter a new password (8+ characters):\n")?;
    let password2 = ask_for_password("Please confirm your new password:\n")?;
    if password != password2 {
        return Err(Error::PasswordMissmatch);
    }
    Ok(password)
}

pub fn ask_for_password(prompt: &str) -> Result<Password> {
    Ok(Password::from(rpassword::prompt_password_stdout(prompt)?))
}

pub async fn ask_for_phrase(prompt: &str) -> Result<Mnemonic> {
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
    Ok(Mnemonic::from_phrase(&words.join(" "), Language::English)
        .map_err(|_| Error::InvalidMnemonic)?)
}

pub async fn set_device_key<T: Runtime + Identity, P: Pair>(
    client: &dyn AbstractClient<T, P>,
    paperkey: bool,
    suri: Option<&str>,
    force: bool,
) -> Result<<T as System>::AccountId>
where
    P::Seed: Into<[u8; 32]> + Copy + Send + Sync,
{
    if client.has_device_key().await && !force {
        return Err(Error::HasDeviceKey);
    }
    let password = ask_for_new_password()?;
    if password.expose_secret().len() < 8 {
        return Err(Error::PasswordTooShort);
    }
    let dk = if paperkey {
        let mnemonic = ask_for_phrase("Please enter your backup phrase:").await?;
        DeviceKey::from_mnemonic(&mnemonic).map_err(|_| Error::InvalidMnemonic)?
    } else if let Some(suri) = &suri {
        let suri: Suri<P> = suri.parse()?;
        DeviceKey::from_seed(suri.0.into())
    } else {
        DeviceKey::generate().await
    };
    Ok(client.set_device_key(&dk, &password, force).await?)
}
