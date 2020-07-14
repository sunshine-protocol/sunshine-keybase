use crate::{
    ask_for_password, async_trait, set_device_key, ChainClient, Command, Error, Identity,
    IdentityClient, Result, Runtime,
};
use clap::Clap;
use sunshine_core::Keystore;
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
impl<T: Runtime + Identity, C: IdentityClient<T>> Command<T, C> for KeySetCommand
where
    <C as ChainClient<T>>::Error: From<identity_client::Error>,
{
    async fn exec(&self, client: &mut C) -> Result<(), C::Error> {
        let account_id =
            set_device_key(client, self.paperkey, self.suri.as_deref(), self.force).await?;
        let account_id_str = account_id.to_string();
        println!("Your device id is {}", &account_id_str);
        if let Some(uid) = client.fetch_uid(&account_id).await.map_err(Error::Client)? {
            println!("Your user id is {}", uid);
        } else {
            let p = "Creating an account requires making a `create_account_for` \
                     transaction. Or transfering funds to your address. Your wallet \
                     contains insufficient funds for paying the transaction fee. Ask \
                     someone to scan the qr code with your device id to create an \
                     account for you.";
            println!("{}\n", Wrapper::with_termwidth().fill(p));
            qr2term::print_qr(&account_id_str)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct KeyLockCommand;

#[async_trait]
impl<T: Runtime + Identity, C: IdentityClient<T>> Command<T, C> for KeyLockCommand
where
    <C as ChainClient<T>>::Error: From<identity_client::Error>,
{
    async fn exec(&self, client: &mut C) -> Result<(), C::Error> {
        client
            .keystore_mut()
            .lock()
            .await
            .map_err(|e| Error::Client(e.into()))?;
        Ok(())
    }
}

#[derive(Clone, Debug, Clap)]
pub struct KeyUnlockCommand;

#[async_trait]
impl<T: Runtime + Identity, C: IdentityClient<T>> Command<T, C> for KeyUnlockCommand
where
    <C as ChainClient<T>>::Error: From<identity_client::Error>,
{
    async fn exec(&self, client: &mut C) -> Result<(), C::Error> {
        let password = ask_for_password("Please enter your password (8+ characters):\n", 8)?;
        client
            .keystore_mut()
            .unlock(&password)
            .await
            .map_err(|e| Error::Client(e.into()))?;
        Ok(())
    }
}
