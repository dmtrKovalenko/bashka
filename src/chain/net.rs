use anyhow::{Context, Result, bail};
use std::time::Duration;

const MAX_BYTES: u64 = 8 * 1024 * 1024;

pub fn fetch(url: &str) -> Result<String> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        bail!("refusing to fetch non-HTTP URL `{url}`");
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(concat!("bashka/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let mut response = agent
        .get(url)
        .call()
        .with_context(|| format!("fetching {url}"))?;
    response
        .body_mut()
        .with_config()
        .limit(MAX_BYTES)
        .read_to_string()
        .with_context(|| format!("reading body of {url}"))
}
