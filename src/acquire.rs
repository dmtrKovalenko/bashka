use anyhow::{Context, Result, bail};
use std::io::{IsTerminal, Read};

pub fn stdin_script() -> Result<String> {
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        bail!(
            "bashka expects a script on stdin, e.g. `curl -fsSL https://example.com/install.sh | bashka`"
        );
    }
    let mut bytes = Vec::new();
    stdin
        .read_to_end(&mut bytes)
        .context("reading script from stdin")?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Whether stdin is a terminal rather than a pipe (nothing to analyze).
pub fn stdin_is_terminal() -> bool {
    std::io::stdin().is_terminal()
}
