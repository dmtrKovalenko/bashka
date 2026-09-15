use crate::config::Descend;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "bashka",
    version,
    about = "A safety guard for `curl … | bash`: analyzes the script before it runs"
)]
pub struct Cli {
    #[command(flatten)]
    pub opts: Options,
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
    /// Arguments forwarded to the script's shell (after `--`).
    #[arg(last = true)]
    pub shell_args: Vec<String>,
}

// Each bool is an independent CLI switch; an enum would not read better on the command line.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, Args)]
pub struct Options {
    /// Answer "yes" wherever the configuration says `ask` (the strong gate still needs --force).
    #[arg(short = 'y', long)]
    pub yes: bool,
    /// Never prompt; an unanswered `ask` aborts.
    #[arg(long, conflicts_with = "yes")]
    pub non_interactive: bool,
    /// Proceed past the strong gate (3+ red flags).
    #[arg(long)]
    pub force: bool,
    /// Analyze and report only, never run. Exit code: 0 green, 1 neutral, 2 red, 3 strong gate.
    #[arg(long, conflicts_with_all = ["yes", "force"])]
    pub check: bool,
    /// Maximum chain depth to follow.
    #[arg(long, value_name = "N")]
    pub max_depth: Option<usize>,
    /// How forwarded scripts are analyzed.
    #[arg(long, value_enum)]
    pub descend: Option<Descend>,
    /// Config file (default: ~/.config/bashka/config.toml).
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Name to record the installed software under (default: derived from the source URL).
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
}

impl Options {
    /// Re-encodes the options so the runtime shim can parse them again (`--name` is top-level only).
    pub fn to_argv(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.yes {
            v.push("--yes".into());
        }
        if self.non_interactive {
            v.push("--non-interactive".into());
        }
        if self.force {
            v.push("--force".into());
        }
        if let Some(d) = self.max_depth {
            v.extend(["--max-depth".into(), d.to_string()]);
        }
        if let Some(d) = self.descend {
            v.extend([
                "--descend".into(),
                clap::ValueEnum::to_possible_value(&d)
                    .unwrap()
                    .get_name()
                    .to_string(),
            ]);
        }
        if let Some(p) = &self.config {
            v.extend(["--config".into(), p.display().to_string()]);
        }
        v
    }
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// List every registered flag.
    Flags,
    /// List the software installed through bashka.
    List {
        /// Full details for every package instead of the table.
        #[arg(short, long)]
        long: bool,
    },
    /// Show everything recorded about one installed package.
    Info {
        /// Package name as shown by `bashka list`.
        name: String,
    },
    /// Remove every binary and directory a recorded install created, and forget the package.
    Remove {
        /// Package name as shown by `bashka list`.
        name: String,
        /// Only print what would be removed.
        #[arg(long)]
        dry_run: bool,
    },
    /// Re-fetch a recorded installer and run it again through the usual review.
    Update {
        /// Package name as shown by `bashka list`.
        name: String,
    },
    /// Configuration helpers.
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    /// Print a fully commented default configuration.
    Init,
}
