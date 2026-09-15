use crate::cli::{Cli, Options};
use crate::runner::{self, Inherit};
use crate::ui::{self, paint};
use crate::vet::Session;
use anyhow::{Context, Result, bail};
use clap::Parser;
use std::io::Read;
use std::path::Path;

/// `Some(shell)` when argv[0] is a shell name and we were spawned by a bashka runner.
pub fn shell_name(argv0: &str) -> Option<&str> {
    let name = Path::new(argv0).file_name()?.to_str()?;
    (std::env::var_os(runner::ENV_REAL_PATH).is_some() && ["bash", "sh"].contains(&name))
        .then_some(name)
}

/// Where the shell's script comes from, as bash would interpret its arguments.
enum Input {
    Stdin,
    CommandString(String),
    File(String),
}

fn parse_shell_args(args: &[String]) -> (Input, Vec<String>) {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-c" => {
                return (
                    args.get(i + 1)
                        .map_or(Input::Stdin, |s| Input::CommandString(s.clone())),
                    args[(i + 2).min(args.len())..].to_vec(),
                );
            }
            "-s" | "-" => return (Input::Stdin, args[i + 1..].to_vec()),
            "--" => {
                return match args.get(i + 1) {
                    Some(f) => (Input::File(f.clone()), args[i + 2..].to_vec()),
                    None => (Input::Stdin, vec![]),
                };
            }
            "-o" | "-O" | "+O" => i += 2,
            _ if a.starts_with('-') || a.starts_with('+') => i += 1,
            _ => return (Input::File(a.to_string()), args[i + 1..].to_vec()),
        }
    }
    (Input::Stdin, vec![])
}

pub fn run(shell: &str, args: &[String]) -> Result<i32> {
    let opts_argv: Vec<String> = std::env::var(runner::ENV_OPTS)
        .map(|s| {
            s.split(runner::OPTS_SEP)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    let opts: Options =
        Cli::parse_from(std::iter::once("bashka".to_string()).chain(opts_argv.iter().cloned()))
            .opts;
    let depth = env_usize(runner::ENV_DEPTH) + 1;
    let vetted = env_list(runner::ENV_VETTED);
    let mut ancestors = env_list(runner::ENV_ANCESTORS);

    let (input, positional) = parse_shell_args(args);
    let (source, label) = match &input {
        Input::Stdin => (read_stdin()?, format!("<{shell} stdin>")),
        Input::CommandString(s) => (s.clone(), format!("<{shell} -c>")),
        Input::File(f) => (
            std::fs::read_to_string(f).with_context(|| format!("reading {f}"))?,
            f.clone(),
        ),
    };
    let hash = crate::sha256(&source);
    if ancestors.contains(&hash) {
        bail!("cycle detected: this script is already running higher up the chain");
    }

    let mut session = Session::new(opts.clone())?;
    let max_depth = opts
        .max_depth
        .unwrap_or(session.config.interaction.max_depth);
    if depth > max_depth {
        bail!("chain depth {depth} exceeds max_depth={max_depth}; refusing to run a deeper layer");
    }

    let approval = if vetted.contains(&hash) {
        let line = format!(
            "{} layer {depth} ({label}) matches a vetted script; running\n",
            paint(ui::GREEN, "bashka:")
        );
        session.prompter.say(&line);
        crate::vet::Approval {
            vetted: vetted.clone(),
            needs_shim: true,
            layers: vec![],
        }
    } else {
        let line = format!(
            "{} intercepted `{shell}` at chain depth {depth}\n",
            paint(ui::CYAN, "bashka:")
        );
        session.prompter.say(&line);
        match session.vet(&source, label.clone(), depth)? {
            Some(a) => a,
            None => return Ok(1),
        }
    };

    ancestors.push(hash);
    let mut all_vetted = vetted;
    all_vetted.extend(approval.vetted);
    let inherit = Inherit {
        depth,
        vetted: all_vetted,
        ancestors,
        opts_argv: opts.to_argv(),
    };
    session.run(
        &label,
        shell,
        &source,
        &positional,
        &inherit,
        approval.needs_shim,
    )
}

fn read_stdin() -> Result<String> {
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn env_usize(key: &str) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn env_list(key: &str) -> Vec<String> {
    std::env::var(key)
        .map(|v| {
            v.split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> (String, Vec<String>) {
        let (input, rest) = parse_shell_args(
            &args
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>(),
        );
        let input = match input {
            Input::Stdin => "stdin".to_string(),
            Input::CommandString(s) => format!("-c:{s}"),
            Input::File(f) => format!("file:{f}"),
        };
        (input, rest)
    }

    #[test]
    fn mirrors_bash_argument_rules() {
        assert_eq!(parse(&[]), ("stdin".into(), vec![]));
        assert_eq!(
            parse(&["-s", "--", "--skip-shell"]),
            ("stdin".into(), vec!["--".into(), "--skip-shell".into()])
        );
        assert_eq!(
            parse(&["-c", "echo hi", "x"]),
            ("-c:echo hi".into(), vec!["x".into()])
        );
        assert_eq!(
            parse(&["-e", "/dev/fd/63", "a"]),
            ("file:/dev/fd/63".into(), vec!["a".into()])
        );
        assert_eq!(
            parse(&["-o", "pipefail", "script.sh"]),
            ("file:script.sh".into(), vec![])
        );
    }
}
