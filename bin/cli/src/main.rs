use crate::command::*;
use crate::error::Error;
use crate::runtime::{Runtime, Uid};
use clap::Clap;
use exitfailure::ExitDisplay;
use ipfs_embed::{Config, Store};
use keybase_keystore::bip39::{Language, Mnemonic};
use keybase_keystore::{DeviceKey, KeyStore, Password};
use std::path::PathBuf;
use substrate_subxt::balances::{TransferCallExt, TransferEventExt};
use substrate_subxt::sp_core::{crypto::Ss58Codec, sr25519};
use substrate_subxt::{ClientBuilder, Signer};
use textwrap::Wrapper;

mod command;
mod error;
mod runtime;

#[async_std::main]
async fn main() -> Result<(), ExitDisplay<Error>> {
    Ok(run().await?)
}

struct Paths {
    _root: PathBuf,
    keystore: PathBuf,
    db: PathBuf,
}

impl Paths {
    fn new(root: Option<PathBuf>) -> Result<Self, Error> {
        let root = if let Some(root) = root {
            root
        } else {
            dirs2::config_dir()
                .ok_or(Error::ConfigDirNotFound)?
                .join("cli-identity")
        };
        let keystore = root.join("keystore");
        let db = root.join("db");
        Ok(Paths {
            _root: root,
            keystore,
            db,
        })
    }
}

type Client = client_identity::Client<Runtime, sr25519::Pair, Store>;

async fn run() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();
    let paths = Paths::new(opts.path)?;

    let keystore = KeyStore::open(&paths.keystore).await?;
    let subxt = ClientBuilder::new().build().await?;
    let config = Config::from_path(&paths.db).map_err(ipfs_embed::Error::Sled)?;
    let store = Store::new(config)?;

    let mut client = Client::new(keystore, subxt.clone(), store);

    match opts.cmd {
        SubCommand::Key(KeyCommand { cmd }) => match cmd {
            KeySubCommand::Set(KeySetCommand {
                force,
                suri,
                paperkey,
            }) => {
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
                } else {
                    if let Some(suri) = &suri {
                        DeviceKey::from_seed(suri.0)
                    } else {
                        DeviceKey::generate()
                    }
                };
                let account_id = client.set_device_key(&dk, &password, force).await?;
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
            }
            KeySubCommand::Unlock => {
                let password = ask_for_password("Please enter your password (8+ characters):\n")?;
                client.unlock(&password).await?;
            }
            KeySubCommand::Lock => client.lock().await?,
        },
        SubCommand::Account(AccountCommand { cmd }) => match cmd {
            AccountSubCommand::Create(AccountCreateCommand { device }) => {
                client.create_account_for(&device.0).await?;
            }
            AccountSubCommand::Password => {
                let password = ask_for_new_password()?;
                client.change_password(&password).await?;
                client.update_password().await?;
            }
        },
        SubCommand::Device(DeviceCommand { cmd }) => match cmd {
            DeviceSubCommand::Paperkey => {
                println!("Generating a new paper key.");
                let mnemonic = client.add_paperkey().await?;
                println!("Here is your secret paper key phrase:");
                let words: Vec<_> = mnemonic.phrase().split(' ').collect();
                println!("");
                println!("{}", words[..12].join(" "));
                println!("{}", words[12..].join(" "));
                println!("");
                println!("Write it down and keep somewhere safe.");
            }
            DeviceSubCommand::Add(DeviceAddCommand { device }) => {
                client.add_key(&device.0).await?;
            }
            DeviceSubCommand::Remove(DeviceRemoveCommand { device }) => {
                client.remove_key(&device.0).await?;
            }
            DeviceSubCommand::List(DeviceListCommand { identifier }) => {
                let uid = resolve(&mut client, identifier).await?;
                for key in client.fetch_keys(uid, None).await? {
                    println!("{}", key.to_ss58check());
                }
            }
        },
        SubCommand::Id(IdCommand { cmd }) => match cmd {
            IdSubCommand::List(IdListCommand { identifier }) => {
                let uid = resolve(&mut client, identifier).await?;
                println!("Your user id is {}", uid);
                for id in client.identity(uid).await? {
                    println!("{}", id);
                }
            }
            IdSubCommand::Prove(IdProveCommand { service }) => {
                println!("Claiming {}...", service);
                let instructions = service.cli_instructions();
                let proof = client.prove_identity(service).await?;
                println!("{}", instructions);
                print!("{}", proof);
            }
            IdSubCommand::Revoke(IdRevokeCommand { service }) => {
                client.revoke_identity(service).await?;
            }
        },
        SubCommand::Wallet(WalletCommand { cmd }) => match cmd {
            WalletSubCommand::Balance(WalletBalanceCommand { identifier }) => {
                let uid = resolve(&mut client, identifier).await?;
                let balance = client.fetch_account(uid).await?.free;
                println!("{} of free balance", balance);
            }
            WalletSubCommand::Transfer(WalletTransferCommand { identifier, amount }) => {
                let signer = client.signer().await?;
                let uid = resolve(&mut client, Some(identifier)).await?;
                let keys = client.fetch_keys(uid, None).await?;
                let event = subxt
                    .transfer_and_watch(&signer, &keys[0], amount)
                    .await?
                    .transfer()
                    .map_err(|_| Error::TransferEventDecode)?
                    .ok_or(Error::TransferEventFind)?;
                println!("transfered {} to {}", event.amount, event.to.to_string());
            }
        },
        SubCommand::Run => loop {
            async_std::task::sleep(std::time::Duration::from_millis(100)).await
        },
    }
    Ok(())
}

fn ask_for_new_password() -> Result<Password, Error> {
    let password = ask_for_password("Please enter a new password (8+ characters):\n")?;
    let password2 = ask_for_password("Please confirm your new password:\n")?;
    if password != password2 {
        return Err(Error::PasswordMissmatch);
    }
    Ok(password)
}

fn ask_for_password(prompt: &str) -> Result<Password, Error> {
    Ok(Password::from(rpassword::prompt_password_stdout(prompt)?))
}

async fn ask_for_phrase(prompt: &str) -> Result<Mnemonic, Error> {
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

async fn resolve(client: &mut Client, identifier: Option<Identifier>) -> Result<Uid, Error> {
    let identifier = if let Some(identifier) = identifier {
        identifier
    } else {
        Identifier::Account(client.signer().await?.account_id().clone())
    };
    let uid = match identifier {
        Identifier::Uid(uid) => uid,
        Identifier::Account(account_id) => client
            .fetch_uid(&account_id)
            .await?
            .ok_or(Error::NoAccount)?,
        Identifier::Service(service) => client.resolve(&service).await?,
    };
    Ok(uid)
}
