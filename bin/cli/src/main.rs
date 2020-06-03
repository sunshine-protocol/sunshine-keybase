use crate::command::*;
use crate::error::Error;
use crate::runtime::{AccountId, Extra, Runtime, Signature};
use clap::Clap;
use client_identity::{Client, IdentityStatus, Service};
use exitfailure::ExitDisplay;
use ipfs_embed::{Config, Store};
use keybase_keystore::{KeyStore, Password};
use std::path::{Path, PathBuf};
use substrate_subxt::balances::{TransferCallExt, TransferEventExt};
use substrate_subxt::sp_core::{crypto::Ss58Codec, sr25519};
use substrate_subxt::ClientBuilder;

mod command;
mod error;
mod runtime;

#[async_std::main]
async fn main() -> Result<(), ExitDisplay<Error>> {
    Ok(run().await?)
}

struct Paths {
    _root: PathBuf,
    account_id: PathBuf,
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
        let account_id = root.join("account_id");
        let keystore = root.join("keystore");
        let db = root.join("db");
        Ok(Paths {
            _root: root,
            account_id,
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

    match opts.subcmd {
        SubCommand::Init(InitCommand { force, suri: _ }) => {
            let account_id = client.create_account(ask_for_password()?, force).await?;
            write_account_id(&paths.account_id, &account_id).await?;
        }
        SubCommand::Unlock => {
            client
                .unlock(
                    &read_account_id(&paths.account_id).await?,
                    ask_for_password()?,
                )
                .await?;
        }
        SubCommand::Lock => {
            client.lock()?;
        }
        SubCommand::Id(IdCommand { identifier }) => {
            let account_id = match identifier {
                Some(Identifier::Account(account_id)) => account_id,
                Some(Identifier::Service(service)) => client.resolve(&service).await?,
                None => read_account_id(&paths.account_id).await?,
            };
            println!("{}", account_id.to_string());
            for id in client.identity(&account_id).await? {
                println!("{}", id);
            }
        }
        SubCommand::Prove(ProveCommand { service }) => {
            println!("Claiming {}...", service);
            let instructions = match service {
                Service::Github(_) => {
                    "Please *publicly* post the following Gist, and name it 'substrate-identity-proof.md'.\n"
                }
            };
            let proof = client.prove_ownership(service).await?;
            println!("{}", instructions);
            print!("{}", proof);
        }
        SubCommand::Revoke(RevokeCommand { seqno }) => {
            let account_id = read_account_id(&paths.account_id).await?;
            let id = client
                .identity(&account_id)
                .await?
                .into_iter()
                .find(|id| id.seqno == seqno && id.status != IdentityStatus::Revoked)
                .ok_or(Error::SeqNoInvalid)?;
            println!("Do you really want to revoke {}? [y/n]", id.service);
            if ask_for_confirmation().await? {
                client.revoke_claim(seqno).await?;
            }
        }
        SubCommand::Transfer(TransferCommand { identifier, amount }) => {
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
        "Enter your password",
    )?))
}

async fn write_account_id(path: &Path, account_id: &AccountId) -> Result<(), Error> {
    async_std::fs::write(&path, account_id.to_string()).await?;
    Ok(())
}

async fn read_account_id(path: &Path) -> Result<AccountId, Error> {
    let account_id = async_std::fs::read_to_string(path).await?;
    let account_id = AccountId::from_string(&account_id).map_err(|_| Error::InvalidAccountId)?;
    Ok(account_id)
}
