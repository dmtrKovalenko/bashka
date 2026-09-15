mod toggle;

pub use toggle::{NoConfig, Recommended, Toggle};

use crate::analysis::driver::BuiltFlag;
use crate::analysis::registry;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULTS: &str = include_str!("../../data/defaults.toml");

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Shared {
    /// Commands that download from the network.
    pub network_commands: Vec<String>,
    /// Commands that execute a script fed to them.
    pub shells: Vec<String>,
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            network_commands: ["curl", "wget", "fetch"].map(String::from).to_vec(),
            shells: ["bash", "sh", "zsh", "dash", "ksh"]
                .map(String::from)
                .to_vec(),
        }
    }
}

impl Shared {
    pub fn is_network(&self, cmd: &str) -> bool {
        let base = base_name(cmd);
        self.network_commands.iter().any(|n| n == base)
    }

    pub fn is_shell(&self, cmd: &str) -> bool {
        let base = base_name(cmd);
        self.shells.iter().any(|s| s == base)
    }

    /// The command fetches from the network (downloaders and `git clone`).
    pub fn downloads(&self, c: &crate::parser::Command) -> bool {
        self.is_network(&c.name) || (base_name(&c.name) == "git" && c.has_arg("clone"))
    }
}

/// The final path component of a command name, so `/usr/bin/curl` matches `curl`.
pub fn base_name(cmd: &str) -> &str {
    cmd.rsplit('/').next().unwrap_or(cmd)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OnRed {
    Ask,
    Abort,
    Proceed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FollowRemote {
    Ask,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Descend {
    /// Fetch literal forwards ahead of time; shim dynamic ones at run time.
    Hybrid,
    /// Only fetch ahead; dynamic forwards are reported but not intercepted.
    FetchAhead,
    /// Never fetch ahead; every forward re-enters bashka through the shim.
    Shim,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Interaction {
    pub on_red: OnRed,
    /// No red flags but fewer green than `policy.green_min`.
    pub on_neutral: OnRed,
    pub follow_remote: FollowRemote,
    pub descend: Descend,
    pub max_depth: usize,
}

impl Default for Interaction {
    fn default() -> Self {
        Self {
            on_red: OnRed::Ask,
            on_neutral: OnRed::Ask,
            follow_remote: FollowRemote::Ask,
            descend: Descend::Hybrid,
            max_depth: 5,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// Green findings (weighted) needed to run without a prompt when there are no reds.
    pub green_min: u32,
    /// Red findings (weighted) from which the stronger gate applies.
    pub strong_gate_reds: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            green_min: 3,
            strong_gate_reds: 3,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub shared: Shared,
    pub flags: toml::Table,
    pub interaction: Interaction,
    pub policy: Policy,
    pub ui: crate::ui::Ui,
}

pub fn user_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("bashka").join("config.toml"))
}

/// Embedded defaults merged with the user file (explicit path, or the default location if present).
pub fn load(path: Option<&Path>) -> Result<Config> {
    let mut merged: toml::Table = toml::from_str(DEFAULTS).context("embedded defaults.toml")?;
    let user = match path {
        Some(p) => Some(p.to_path_buf()),
        None => user_config_path().filter(|p| p.exists()),
    };
    if let Some(p) = user {
        let text =
            std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        let table: toml::Table =
            toml::from_str(&text).with_context(|| format!("parsing {}", p.display()))?;
        merge(&mut merged, table);
    }
    toml::Value::Table(merged)
        .try_into()
        .context("invalid configuration")
}

/// Deep-merges `over` into `base`; tables recurse, everything else is replaced.
fn merge(base: &mut toml::Table, over: toml::Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(o)) => merge(b, o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

impl Config {
    /// Builds only the enabled flags, validating every config eagerly.
    pub fn build_flags(&self) -> Result<Vec<BuiltFlag>> {
        registry::all()
            .into_iter()
            .filter_map(|reg| {
                (reg.build)(self.flags.get(reg.id), &self.shared)
                    .transpose()
                    .map(|f| f.map(|flag| (reg, flag)))
            })
            .collect()
    }

    /// `[flags.*]` keys that match no registered flag.
    pub fn unknown_flags(&self) -> Vec<&str> {
        self.flags
            .keys()
            .map(String::as_str)
            .filter(|k| registry::find(k).is_none())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_is_deep_for_tables_only() {
        let mut base: toml::Table = toml::from_str(
            "[flags]\na = true\nb = { x = 1 }\n[shared]\nnetwork_commands = ['curl']",
        )
        .unwrap();
        let over: toml::Table = toml::from_str("[flags]\nb = false\nc = { y = 2 }\n").unwrap();
        merge(&mut base, over);
        let flags = base["flags"].as_table().unwrap();
        assert_eq!(flags["a"], toml::Value::Boolean(true));
        assert_eq!(flags["b"], toml::Value::Boolean(false));
        assert!(flags["c"].is_table());
        assert!(base["shared"].is_table());
    }

    #[test]
    fn embedded_defaults_parse() {
        let cfg: Config = toml::from_str(DEFAULTS).unwrap();
        assert_eq!(cfg.interaction.max_depth, 5);
    }
}
