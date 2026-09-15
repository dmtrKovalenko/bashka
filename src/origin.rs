use crate::url;
use std::io::IsTerminal;
use std::process::Command;

/// Commands that fetch a URL to stdout/stdin of a pipe.
const FETCHERS: &[&str] = &["curl", "wget", "fetch", "http", "https", "aria2c", "wget2"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub url: String,
    /// `curl -fsSL https://…` as seen in the process table.
    pub command: String,
}

pub fn source() -> Option<Source> {
    if std::io::stdin().is_terminal() {
        return None; // not a pipe; nothing to discover
    }
    let table = ps_table()?;
    sibling(std::process::id(), &table)
}

/// `(pid, ppid, command)` for every process, via `ps`.
fn ps_table() -> Option<Vec<(u32, u32, String)>> {
    let out = Command::new("ps")
        .args(["-axo", "pid=,ppid=,command="])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_ps(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_ps(text: &str) -> Vec<(u32, u32, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid, rest) = line.split_once(char::is_whitespace)?;
            let rest = rest.trim_start();
            let (ppid, cmd) = rest.split_once(char::is_whitespace)?;
            Some((
                pid.parse().ok()?,
                ppid.parse().ok()?,
                cmd.trim().to_string(),
            ))
        })
        .collect()
}

/// The fetcher process that shares our parent (a pipeline sibling), with its URL. When the
/// fetcher already exited (small scripts), the parent's own command line (`sh -c "curl … | …"`)
/// is the fallback.
fn sibling(me: u32, table: &[(u32, u32, String)]) -> Option<Source> {
    let (my_ppid, _) = table
        .iter()
        .find(|(pid, ..)| *pid == me)
        .map(|(_, ppid, cmd)| (*ppid, cmd))?;
    let from_sibling = table
        .iter()
        .filter(|(pid, ppid, _)| *pid != me && *ppid == my_ppid)
        .filter(|(.., cmd)| is_fetcher(cmd))
        .find_map(|(.., cmd)| fetcher_source(cmd));
    from_sibling.or_else(|| {
        let (.., parent_cmd) = table.iter().find(|(pid, ..)| *pid == my_ppid)?;
        let script = ["sh -c ", "bash -c ", "zsh -c ", "dash -c "]
            .iter()
            .find_map(|p| parent_cmd.strip_prefix(p))?;
        script
            .trim_matches(|c: char| c == '"' || c == '\'')
            .split('|')
            .map(str::trim)
            .filter(|stage| is_fetcher(stage))
            .find_map(fetcher_source)
    })
}

fn fetcher_source(cmd: &str) -> Option<Source> {
    let url = url::urls_in(cmd).find(|u| url::host(u).is_some())?;
    Some(Source {
        url: url.to_string(),
        command: cmd.to_string(),
    })
}

fn is_fetcher(command: &str) -> bool {
    let first = command.split_whitespace().next().unwrap_or_default();
    let name = first.rsplit('/').next().unwrap_or(first);
    FETCHERS.contains(&name)
}
