use crate::command::*;
use crate::error::Error;
use crate::runtime::{Extra, Runtime, Signature, Uid};
use clap::Clap;
use exitfailure::ExitDisplay;
use ipfs_embed::{Config, Store};
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
            dirs::config_dir()
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

type Client = client_identity::Client<Runtime, Signature, Extra, sr25519::Pair, Store>;

async fn run() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();
    let paths = Paths::new(opts.path)?;

    let keystore = KeyStore::new(&paths.keystore);
    let subxt = ClientBuilder::new().build().await?;
    let config = Config::from_path(&paths.db).map_err(ipfs_embed::Error::Sled)?;
    let store = Store::new(config)?;

    let mut client = Client::new(keystore, subxt.clone(), store);

    match opts.cmd {
        SubCommand::Key(KeyCommand { cmd }) => match cmd {
            KeySubCommand::Init(KeyInitCommand { force, suri }) => {
                let dk = if let Some(suri) = &suri {
                    DeviceKey::from_seed(suri.0)
                } else {
                    DeviceKey::generate()
                };
                let account_id = client.set_device_key(&dk, &ask_for_password()?, force)?;
                let account_id = account_id.to_string();
                println!("Your device id is {}", &account_id);
                let p = "Creating an account requires making a `create_account_for` \
                         transaction. Your wallet contains insufficient funds for paying \
                         the transaction fee. Ask someone to scan the qr code with your \
                         device id to create an account for you.";
                println!("{}\n", Wrapper::with_termwidth().fill(p));
                qr2term::print_qr(&account_id)?;
            }
            KeySubCommand::Unlock => {
                client.unlock(&ask_for_password()?)?;
            }
            KeySubCommand::Lock => client.lock()?,
        },
        SubCommand::Account(AccountCommand { cmd }) => match cmd {
            AccountSubCommand::Create(AccountCreateCommand { device }) => {
                client.create_account_for(&device.0).await?;
            }
        },
        SubCommand::Device(DeviceCommand { cmd }) => match cmd {
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
                println!("{}", uid);
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
                let signer = client.signer()?;
                let uid = resolve(&mut client, Some(identifier)).await?;
                let keys = client.fetch_keys(uid, None).await?;
                // TODO: there is a race here, a key may be revoked before
                // the transfer completes.
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

fn ask_for_password() -> Result<Password, Error> {
    Ok(Password::from(rpassword::prompt_password_stdout(
        "Enter your password:\n",
    )?))
}

async fn resolve(client: &mut Client, identifier: Option<Identifier>) -> Result<Uid, Error> {
    let identifier = if let Some(identifier) = identifier {
        identifier
    } else {
        Identifier::Account(client.signer()?.account_id().clone())
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
