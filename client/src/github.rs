use serde::Deserialize;
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("network error: {0}")]
    NetworkError(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("proof not found")]
    ProofNotFound,
}

#[derive(Deserialize)]
struct Gist {
    files: BTreeMap<String, GistFile>,
}

#[derive(Deserialize)]
struct GistFile {
    raw_url: String,
}

pub async fn verify_identity(
    user: &str,
    gist_name: &str,
    gist_content: &str,
) -> Result<String, Error> {
    let uri = format!("https://api.github.com/users/{}/gists", user);
    let gists: Vec<Gist> = surf::get(&uri).recv_json().await?;
    let filtered = gists
        .into_iter()
        .filter_map(|mut g| g.files.remove(gist_name));
    for gist in filtered {
        let mut res = surf::get(&gist.raw_url).await?;
        let content = res.body_string().await?;
        if content == gist_content {
            return Ok(gist.raw_url);
        }
    }
    Err(Error::ProofNotFound)
}
