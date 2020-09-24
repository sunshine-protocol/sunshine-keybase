use clap::Clap;
pub use sunshine_cli_utils::key::{KeyLockCommand, KeyUnlockCommand};
use sunshine_cli_utils::{set_key, Node, Result};
use sunshine_identity_client::{Identity, IdentityClient};
use textwrap::Wrapper;

#[derive(Clone, Debug, Clap)]
pub struct KeySetCommand {
    /// Overwrite existing keys.
    #[clap(short = 'f', long = "force")]
    pub force: bool,

    /// Suri.
    #[clap(long = "suri")]
    pub suri: Option<String>,

    /// Paperkey.
    #[clap(long = "paperkey")]
    pub paperkey: bool,
}

impl KeySetCommand {
    pub async fn exec<N: Node, C: IdentityClient<N>>(&self, client: &mut C) -> Result<()>
    where
        N::Runtime: Identity,
    {
        let account_id = set_key(client, self.paperkey, self.suri.as_deref(), self.force).await?;
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
