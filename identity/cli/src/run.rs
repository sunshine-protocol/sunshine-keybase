use crate::{async_trait, AbstractClient, Command, Identity, Pair, Result, Runtime};
use async_std::task;
use clap::Clap;
use std::time::Duration;

#[derive(Clone, Debug, Clap)]
pub struct RunCommand;

#[async_trait]
impl<T: Runtime + Identity, P: Pair> Command<T, P> for RunCommand {
    async fn exec(&self, _client: &dyn AbstractClient<T, P>) -> Result<()> {
        loop {
            task::sleep(Duration::from_millis(100)).await
        }
    }
}
