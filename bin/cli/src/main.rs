use crate::command::*;
use crate::error::Error;
use crate::runtime::Runtime;
use clap::Clap;
use client_identity::{Client, IdentityStatus, Service};
use exitfailure::ExitDisplay;
use ipfs_embed::{Config, Store};
use substrate_subxt::sp_core::Pair;
use substrate_subxt::ClientBuilder;

mod command;
mod error;
mod runtime;

#[async_std::main]
async fn main() -> Result<(), ExitDisplay<Error>> {
    Ok(run().await?)
}

async fn run() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();
    let path = if let Some(path) = opts.path {
        path
    } else {
        dirs::config_dir().unwrap().join("cli-identity")
    };
    let config = Config::from_path(path).map_err(|err| ipfs_embed::Error::Sled(err))?;
    let store = Store::new(config)?;
    // TODO get from fs
    let pair = sp_keyring::AccountKeyring::Alice.pair();
    let account_id = pair.public().into();
    let subxt = ClientBuilder::<Runtime>::new().build().await?;
    let mut client = Client::new(subxt, store, pair).await?;
    match opts.subcmd {
        SubCommand::Id(IdCommand { identifier }) => {
            let account_id = match identifier {
                Some(Identifier::Account(account_id)) => account_id,
                Some(Identifier::Service(_)) => unimplemented!(),
                None => account_id,
            };
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
            let id = client
                .identity(&account_id)
                .await?
                .into_iter()
                .find(|id| id.seqno == seqno && id.status != IdentityStatus::Revoked)
                .ok_or(Error::InvalidSeqNo)?;
            println!("Do you really want to revoke {}? [y/n]", id.service);
            if ask_for_confirmation().await? {
                client.revoke_claim(seqno).await?;
            }
        }
    }
    Ok(())
}

async fn ask_for_confirmation() -> Result<bool, Error> {
    let mut line = String::new();
    async_std::io::stdin().read_line(&mut line).await?;
    Ok(&line == "y\n")
}
