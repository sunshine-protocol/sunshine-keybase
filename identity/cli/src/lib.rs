pub mod account;
pub mod device;
mod error;
pub mod id;
pub mod key;
pub mod run;
pub mod wallet;

pub use crate::error::*;

use keystore::bip39::{Language, Mnemonic};
use keystore::Password;

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
    println!("");
    Ok(Mnemonic::from_phrase(&words.join(" "), Language::English)
        .map_err(|_| Error::InvalidMnemonic)?)
}
