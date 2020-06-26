//! Substrate Node Template CLI library.

use sc_cli::{RunCmd, Subcommand, SubstrateCli};
use structopt::StructOpt;
use test_node::{chain_spec, new_full_start, service};

#[derive(Debug, StructOpt)]
pub struct Cli {
    #[structopt(subcommand)]
    pub subcommand: Option<Subcommand>,

    #[structopt(flatten)]
    pub run: RunCmd,
}

impl SubstrateCli for Cli {
    fn impl_name() -> &'static str {
        test_node::IMPL_NAME
    }

    fn impl_version() -> &'static str {
        test_node::IMPL_VERSION
    }

    fn description() -> &'static str {
        test_node::DESCRIPTION
    }

    fn author() -> &'static str {
        test_node::AUTHOR
    }

    fn support_url() -> &'static str {
        test_node::SUPPORT_URL
    }

    fn copyright_start_year() -> i32 {
        test_node::COPYRIGHT_START_YEAR
    }

    fn executable_name() -> &'static str {
        test_node::EXECUTABLE_NAME
    }

    fn load_spec(&self, id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
        Ok(match id {
            "dev" => Box::new(chain_spec::development_config()),
            "" | "local" => Box::new(chain_spec::local_testnet_config()),
            path => Box::new(chain_spec::ChainSpec::from_json_file(
                std::path::PathBuf::from(path),
            )?),
        })
    }
}

fn main() -> sc_cli::Result<()> {
    let cli = <Cli as SubstrateCli>::from_args();

    match &cli.subcommand {
        Some(subcommand) => {
            let runner = cli.create_runner(subcommand)?;
            runner.run_subcommand(subcommand, |config| Ok(new_full_start!(config).0))
        }
        None => {
            let runner = cli.create_runner(&cli.run)?;
            runner.run_node(service::new_light, service::new_full, test_runtime::VERSION)
        }
    }
}
