use crate::command::*;
use async_std::task;
use clap::Clap;
use cli_identity::{key::KeySetCommand, set_device_key, Command, Error};
use exitfailure::ExitDisplay;
use ipfs_embed::{Config, Store};
use keybase_keystore::KeyStore;
use std::time::Duration;
use substrate_subxt::sp_core::sr25519;
use test_client::faucet;
use test_client::Runtime;

mod command;

#[async_std::main]
async fn main() -> Result<(), ExitDisplay<Error>> {
    Ok(run().await?)
}

type Client = test_client::identity::Client<Runtime, sr25519::Pair, Store>;

async fn run() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();
    let root = if let Some(root) = opts.path {
        root
    } else {
        dirs2::config_dir()
            .ok_or(Error::ConfigDirNotFound)?
            .join("sunshine-identity")
    };
    let keystore = KeyStore::open(root.join("keystore")).await?;
    let db = sled::open(root.join("db")).unwrap();
    let db_ipfs = db.open_tree("ipfs").unwrap();

    #[cfg(not(feature = "light"))]
    let subxt = substrate_subxt::ClientBuilder::new().build().await?;
    #[cfg(feature = "light")]
    let subxt = {
        let db_light = db.open_tree("substrate").unwrap();
        test_client::light::build_light_client(db_light, include_bytes!("../chain-spec.json"))
            .await
            .unwrap()
    };

    let config = Config::from_tree(db_ipfs);
    let store = Store::new(config).unwrap();
    let client = Client::new(keystore, subxt, store);

    let mut password_changes = if client.has_device_key().await && client.signer().await.is_ok() {
        let sub = client.subscribe_password_changes().await?;
        client.update_password().await?;
        Some(sub)
    } else {
        None
    };

    match opts.cmd {
        SubCommand::Key(KeyCommand { cmd }) => match cmd {
            KeySubCommand::Set(KeySetCommand {
                paperkey,
                suri,
                force,
            }) => {
                let account_id = set_device_key(&client, paperkey, suri.as_deref(), force).await?;
                println!("your device key is {}", account_id.to_string());
                let amount = faucet::mint(client.subxt(), &account_id)
                    .await?
                    .unwrap()
                    .amount;
                println!("minted {} tokens into your account", amount);
                let uid = client.fetch_uid(&account_id).await?.unwrap();
                println!("your user id is {}", uid);
                Ok(())
            }
            KeySubCommand::Unlock(cmd) => cmd.exec(&client).await,
            KeySubCommand::Lock(cmd) => cmd.exec(&client).await,
        },
        SubCommand::Account(AccountCommand { cmd }) => match cmd {
            AccountSubCommand::Create(cmd) => cmd.exec(&client).await,
            AccountSubCommand::Password(cmd) => cmd.exec(&client).await,
        },
        SubCommand::Device(DeviceCommand { cmd }) => match cmd {
            DeviceSubCommand::Add(cmd) => cmd.exec(&client).await,
            DeviceSubCommand::Remove(cmd) => cmd.exec(&client).await,
            DeviceSubCommand::List(cmd) => cmd.exec(&client).await,
            DeviceSubCommand::Paperkey(cmd) => cmd.exec(&client).await,
        },
        SubCommand::Id(IdCommand { cmd }) => match cmd {
            IdSubCommand::List(cmd) => cmd.exec(&client).await,
            IdSubCommand::Prove(cmd) => cmd.exec(&client).await,
            IdSubCommand::Revoke(cmd) => cmd.exec(&client).await,
        },
        SubCommand::Wallet(WalletCommand { cmd }) => match cmd {
            WalletSubCommand::Balance(cmd) => cmd.exec(&client).await,
            WalletSubCommand::Transfer(cmd) => cmd.exec(&client).await,
        },
        SubCommand::Run => loop {
            if let Some(sub) = password_changes.as_mut() {
                if sub.next().await.is_some() {
                    client.update_password().await?;
                }
            } else {
                task::sleep(Duration::from_millis(100)).await
            }
        },
    }
}
