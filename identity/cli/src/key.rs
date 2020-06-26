use crate::{
    ask_for_new_password, ask_for_password, ask_for_phrase, async_trait, AbstractClient, Command,
    Error, Identity, Pair, Result, Runtime,
};
use clap::Clap;
use client_identity::Suri;
use keystore::DeviceKey;
use textwrap::Wrapper;

#[derive(Clone, Debug, Clap)]
pub struct KeySetCommand {
    /// Overwrite existing keys.
    #[clap(short = "f", long = "force")]
    pub force: bool,

    /// Suri.
    #[clap(long = "suri")]
    pub suri: Option<String>,

    /// Paperkey.
    #[clap(long = "paperkey")]
    pub paperkey: bool,
}

#[async_trait]
impl<T: Runtime + Identity, P: Pair> Command<T, P> for KeySetCommand
where
    P::Seed: Into<[u8; 32]> + Copy + Send + Sync,
{
    async fn exec(&self, client: &dyn AbstractClient<T, P>) -> Result<()> {
        if client.has_device_key().await && !self.force {
            return Err(Error::HasDeviceKey);
        }
        let password = ask_for_new_password()?;
        if password.expose_secret().len() < 8 {
            return Err(Error::PasswordTooShort);
        }
        let dk = if self.paperkey {
            let mnemonic = ask_for_phrase("Please enter your backup phrase:").await?;
            DeviceKey::from_mnemonic(&mnemonic).map_err(|_| Error::InvalidMnemonic)?
        } else if let Some(suri) = &self.suri {
            let suri: Suri<P> = suri.parse()?;
            DeviceKey::from_seed(suri.0.into())
        } else {
            DeviceKey::generate().await
        };
        let account_id = client.set_device_key(&dk, &password, self.force).await?;
        let account_id_str = account_id.to_string();
        println!("Your device id is {}", &account_id_str);
        if let Some(uid) = client.fetch_uid(&account_id).await? {
            println!("Your user id is {}", uid);
        } else {
            let p = "Creating an account requires making a `create_account_for` \
                             transaction. Your wallet contains insufficient funds for paying \
                             the transaction fee. Ask someone to scan the qr code with your \
                             device id to create an account for you.";
            println!("{}\n", Wrapper::with_termwidth().fill(p));
            qr2term::print_qr(&account_id_str)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct KeyLockCommand;

#[async_trait]
impl<T: Runtime + Identity, P: Pair> Command<T, P> for KeyLockCommand {
    async fn exec(&self, client: &dyn AbstractClient<T, P>) -> Result<()> {
        client.lock().await?;
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct KeyUnlockCommand;

#[async_trait]
impl<T: Runtime + Identity, P: Pair> Command<T, P> for KeyUnlockCommand {
    async fn exec(&self, client: &dyn AbstractClient<T, P>) -> Result<()> {
        let password = ask_for_password("Please enter your password (8+ characters):\n")?;
        client.unlock(&password).await?;
        Ok(())
    }
}
