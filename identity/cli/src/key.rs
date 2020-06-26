use crate::{
    ask_for_password, async_trait, set_device_key, AbstractClient, Command, Identity, Pair, Result,
    Runtime,
};
use clap::Clap;
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
        let account_id =
            set_device_key(client, self.paperkey, self.suri.as_deref(), self.force).await?;
        let account_id_str = account_id.to_string();
        println!("Your device id is {}", &account_id_str);
        if let Some(uid) = client.fetch_uid(&account_id).await? {
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
