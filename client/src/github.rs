use crate::error::{Error, Result};
use serde::Deserialize;
use std::collections::BTreeMap;

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

const GIST_NAME: &'static str = "substrate-identity-proof.md";

async fn find_proofs(user: &str) -> Result<Vec<Proof>> {
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

pub async fn verify(user: &str, signature: &str) -> Result<String> {
    find_proofs(user)
        .await?
        .into_iter()
        .filter_map(|proof| {
            if let Some(signature2) = proof.content.lines().nth(17) {
                if signature == signature2 {
                    return Some(proof.html_url);
                }
            }
            None
        })
        .next()
        .ok_or(Error::ProofNotFound)
}

pub async fn resolve(user: &str) -> Result<Vec<String>> {
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

pub fn proof(
    genesis: &str,
    block: &str,
    uid: &str,
    username: &str,
    public: &str,
    object: &str,
    signature: &str,
) -> String {
    format!(
        include_str!("../github-proof-template.md"),
        genesis = genesis,
        block = block,
        uid = uid,
        username = username,
        public = public,
        object = object,
        signature = signature,
    )
}

pub fn cli_instructions() -> String {
    format!(
        include_str!("../github-proof-instructions.md"),
        gist_name = GIST_NAME,
    )
}
