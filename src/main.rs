mod acquire;
mod agents;
mod analysis;
mod chain;
mod checks;
mod cli;
mod config;
mod install_paths;
mod installed;
mod interaction;
mod introspect;
mod model;
mod origin;
mod parser;
mod policy;
mod report;
mod runner;
mod shim;
mod ui;
mod url;
mod vet;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Cmd, ConfigCmd};
use runner::Inherit;
use sha2::{Digest, Sha256};
use std::process::ExitCode;

pub fn sha256(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let result = match shim::shell_name(&argv[0]) {
        Some(shell) => shim::run(shell, argv[1..].to_vec()),
        None => run(Cli::parse()),
    };
    match result {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            anstream::eprintln!("{} {e:#}", ui::paint(ui::RED, "bashka:"));
            ExitCode::FAILURE
        }
    }
}

/// Usage hint plus the install registry, shown when bashka runs with no script piped in.
fn welcome() -> Result<String> {
    let prog = std::env::args()
        .next()
        .map(|a| {
            std::path::Path::new(&a)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or(a)
        })
        .unwrap_or_else(|| "bashka".into());
    let mut out = format!(
        "{} curl -fsSL <url> | {prog}\n{}\n\n",
        ui::paint(ui::BOLD, "usage:"),
        ui::paint(ui::DIM, format!("       {prog} --help for options")),
    );
    out.push_str(&installed::list(false)?);
    Ok(out)
}

fn run(cli: Cli) -> Result<i32> {
    match cli.cmd {
        Some(Cmd::Flags) => {
            anstream::print!("{}", introspect::list_flags());
            return Ok(0);
        }
        Some(Cmd::Config {
            cmd: ConfigCmd::Init,
        }) => {
            print!("{}", introspect::config_init());
            return Ok(0);
        }
        Some(Cmd::List { long }) => {
            anstream::print!("{}", installed::list(long)?);
            return Ok(0);
        }
        Some(Cmd::Info { name }) => {
            anstream::print!("{}", installed::info(&name)?);
            return Ok(0);
        }
        Some(Cmd::Remove { name, dry_run }) => return installed::remove(&name, dry_run),
        Some(Cmd::Update { name }) => return installed::update(&name, &cli.opts),
        None => {}
    }
    // Invoked bare from a terminal: nothing to analyze, so show how to use it and what is installed.
    if acquire::stdin_is_terminal() {
        anstream::print!("{}", welcome()?);
        return Ok(0);
    }
    // Discover the source URL from the sibling fetcher before draining stdin (curl is still alive).
    let origin = origin::source();
    let source_url = origin.as_ref().map(|o| o.url.clone());
    let label = source_url.clone().unwrap_or_else(|| "<stdin>".into());
    let source = acquire::stdin_script()?;
    let mut session = vet::Session::new(cli.opts.clone())?;
    if cli.opts.check {
        return Ok(match session.check(source, label, 0)? {
            policy::Outcome::Green => 0,
            policy::Outcome::Neutral => 1,
            policy::Outcome::Red => 2,
            policy::Outcome::StrongGate => 3,
            policy::Outcome::Critical => 4,
        });
    }
    let Some(approval) = session.vet(source.clone(), label, 0)? else {
        return Ok(1);
    };
    let inherit = Inherit {
        depth: 0,
        vetted: approval.vetted.clone(),
        ancestors: vec![sha256(&source)],
        opts_argv: cli.opts.to_argv(),
    };
    let invocation = installed::Invocation {
        source_url,
        fetcher: origin.map(|o| o.command),
        name: cli.opts.name.clone(),
        bashka_opts: cli.opts.to_argv(),
        shell_args: cli.shell_args.clone(),
    };
    installed::run_tracked(
        &mut session,
        &approval,
        &source,
        &inherit,
        &invocation,
        None,
    )
}
