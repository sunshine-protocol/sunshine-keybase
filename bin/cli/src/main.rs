use crate::command::*;
use crate::error::Error;
use crate::runtime::{Extra, Runtime, Signature};
use clap::Clap;
use client_identity::{Client, IdentityStatus, Service};
use exitfailure::ExitDisplay;
use ipfs_embed::{Config, Store};
use keybase_keystore::{DeviceKey, KeyStore, Password};
use std::path::PathBuf;
use substrate_subxt::balances::{TransferCallExt, TransferEventExt};
use substrate_subxt::sp_core::sr25519;
use substrate_subxt::system::AccountStoreExt;
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

async fn run() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();
    let paths = Paths::new(opts.path)?;

    let keystore = KeyStore::new(&paths.keystore);
    let subxt = ClientBuilder::new().build().await?;
    let config = Config::from_path(&paths.db).map_err(|err| ipfs_embed::Error::Sled(err))?;
    let store = Store::new(config)?;

    let mut client = Client::<Runtime, Signature, Extra, sr25519::Pair, Store>::new(
        keystore,
        subxt.clone(),
        store,
    );

    match opts.cmd {
        SubCommand::Key(KeyCommand { cmd }) => match cmd {
            KeySubCommand::Init(KeyInitCommand { force, suri }) => {
                let dk = if let Some(suri) = &suri {
                    DeviceKey::from_seed(suri.0)
                } else {
                    DeviceKey::generate()
                };
                let account_id = client.set_device_key(&dk, &ask_for_password()?, force)?;
                if suri.is_some() {
                    client.create_account_for(&account_id).await?;
                } else {
                    let account_id = account_id.to_string();
                    println!("Your device id is {}", &account_id);
                    let p = "Creating an account requires making a `create_account_for` \
                             transaction. Your wallet contains insufficient funds for paying \
                             the transaction fee. Ask someone to scan the qr code with your \
                             device id to create an account for you.";
                    println!("{}\n", Wrapper::with_termwidth().fill(p));
                    qr2term::print_qr(&account_id)?;
                }
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
                client.add_device(&device.0).await?;
            }
            DeviceSubCommand::Remove(DeviceRemoveCommand { device }) => {
                client.remove_device(&device.0).await?;
            }
            DeviceSubCommand::List => todo!(),
        },
        SubCommand::Id(IdCommand { cmd }) => match cmd {
            IdSubCommand::List(IdListCommand { identifier }) => {
                let account_id = match identifier {
                    Some(Identifier::Account(account_id)) => account_id,
                    Some(Identifier::Service(service)) => client.resolve(&service).await?,
                    None => client.signer()?.account_id().clone(),
                };
                println!("{}", account_id.to_string());
                for id in client.identity(&account_id).await? {
                    println!("{}", id);
                }
            }
            IdSubCommand::Prove(IdProveCommand { service }) => {
                println!("Claiming {}...", service);
                let instructions = match service {
                    Service::Github(_) => {
                        "Please *publicly* post the following Gist, and name it \
                         'substrate-identity-proof.md'.\n"
                    }
                };
                let proof = client.prove_ownership(service).await?;
                println!("{}", instructions);
                print!("{}", proof);
            }
            IdSubCommand::Revoke(IdRevokeCommand { seqno }) => {
                let signer = client.signer()?;
                let id = client
                    .identity(signer.account_id())
                    .await?
                    .into_iter()
                    .find(|id| id.seqno == seqno && id.status != IdentityStatus::Revoked)
                    .ok_or(Error::SeqNoInvalid)?;
                println!("Do you really want to revoke {}? [y/n]", id.service);
                if ask_for_confirmation().await? {
                    client.revoke_claim(seqno).await?;
                }
            }
        },
        SubCommand::Wallet(WalletCommand { cmd }) => match cmd {
            WalletSubCommand::Balance => {
                let signer = client.signer()?;
                let balance = subxt.account(signer.account_id(), None).await?.data.free;
                println!("{} of free balance", balance);
            }
            WalletSubCommand::Transfer(WalletTransferCommand { identifier, amount }) => {
                let signer = client.signer()?;
                let account_id = match identifier {
                    Identifier::Account(account_id) => account_id,
                    Identifier::Service(service) => client.resolve(&service).await?,
                };
                let event = subxt
                    .transfer_and_watch(&signer, &account_id, amount)
                    .await?
                    .transfer()
                    .map_err(|_| Error::TransferEventDecode)?
                    .ok_or(Error::TransferEventFind)?;
                println!("transfered {} to {}", event.amount, event.to.to_string());
            }
        },
        SubCommand::Run => loop {},
    }
    Ok(())
}

async fn ask_for_confirmation() -> Result<bool, Error> {
    let mut line = String::new();
    async_std::io::stdin().read_line(&mut line).await?;
    Ok(&line == "y\n")
}

fn ask_for_password() -> Result<Password, Error> {
    Ok(Password::from(rpassword::prompt_password_stdout(
        "Enter your password:\n",
    )?))
}
