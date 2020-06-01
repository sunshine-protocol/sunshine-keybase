use serde::Deserialize;
use std::collections::BTreeMap;
use thiserror::Error;

pub const GIST_NAME: &'static str = "substrate-identity-proof.md";

#[derive(Debug, Error)]
pub enum Error {
    #[error("network error: {0}")]
    NetworkError(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("proof not found")]
    ProofNotFound,
}

#[derive(Deserialize)]
struct Gist {
    html_url: String,
    files: BTreeMap<String, GistFile>,
}

#[derive(Deserialize)]
struct GistFile {
    raw_url: String,
}

struct Proof {
    html_url: String,
    content: String,
}

async fn find_proofs(user: &str) -> Result<Vec<Proof>, Error> {
    let uri = format!("https://api.github.com/users/{}/gists", user);
    let gists: Vec<Gist> = surf::get(&uri).recv_json().await?;
    let mut proofs = Vec::with_capacity(gists.len());
    let urls = gists.into_iter().filter_map(|mut g| {
        g.files
            .remove(GIST_NAME)
            .map(|file| (g.html_url, file.raw_url))
    });
    for (html_url, raw_url) in urls {
        let mut res = surf::get(&raw_url).await?;
        let content = res.body_string().await?;
        proofs.push(Proof { html_url, content });
    }
    Ok(proofs)
}

pub async fn verify_identity(user: &str, proof: &str) -> Result<String, Error> {
    for proof2 in find_proofs(user).await? {
        if proof2.content == proof {
            return Ok(proof2.html_url);
        }
    }
    Err(Error::ProofNotFound)
}

pub async fn resolve_identity(user: &str) -> Result<Vec<String>, Error> {
    Ok(find_proofs(user)
        .await?
        .into_iter()
        .filter_map(|proof| {
            if let Some(line) = proof.content.lines().nth(5) {
                line.split_whitespace().nth(3).map(|s| s.to_string())
            } else {
                None
            }
        })
        .collect())
}
