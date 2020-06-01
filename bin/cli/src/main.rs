use crate::command::*;
use crate::error::Error;
use crate::runtime::Runtime;
use clap::Clap;
use client_identity::{claim::Service, Client};
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
            let identifier = identifier.unwrap_or_else(|| Identifier::Ss58(account_id));
            if let Identifier::Ss58(account_id) = identifier {
                for id in client.identity(&account_id).await? {
                    println!("{}", id);
                }
            }
        }
        SubCommand::Prove(ProveCommand {
            identifier: Identifier::Github(username),
        }) => {
            println!("Claiming {}@github...", username);
            let proof = client.prove_ownership(Service::Github(username)).await?;
            println!("Please *publicly* post the following Gist, and name it 'substrate-identity-proof.md'.\n");
            print!("{}", proof);
        }
        _ => {
            eprintln!("unsupported identifier");
        }
    }
    Ok(())
}
