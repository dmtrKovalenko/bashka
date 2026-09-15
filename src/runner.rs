use anyhow::{Context, Result, bail};
use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;

pub const ENV_REAL_PATH: &str = "BASHFLAGS_REAL_PATH";
pub const ENV_DEPTH: &str = "BASHFLAGS_DEPTH";
pub const ENV_VETTED: &str = "BASHFLAGS_VETTED";
pub const ENV_ANCESTORS: &str = "BASHFLAGS_ANCESTORS";
pub const ENV_OPTS: &str = "BASHFLAGS_OPTS";
pub const OPTS_SEP: char = '\u{1f}';

/// What the child needs to re-enter bashka through the shim.
pub struct Inherit {
    pub depth: usize,
    pub vetted: Vec<String>,
    pub ancestors: Vec<String>,
    pub opts_argv: Vec<String>,
}

pub struct Runner {
    shim: Option<Shim>,
}

impl Runner {
    pub fn new(with_shim: bool) -> Result<Self> {
        Ok(Self {
            shim: with_shim.then(Shim::create).transpose()?,
        })
    }

    /// Feeds `source` to the real shell on stdin, streams its output through, and returns its exit code.
    pub fn run(
        &self,
        shell: &str,
        source: &str,
        shell_args: &[String],
        inherit: &Inherit,
    ) -> Result<i32> {
        let real_path = real_path();
        let shell_bin = find_in_path(shell, &real_path)
            .with_context(|| format!("no `{shell}` found in PATH"))?;
        let mut cmd = Command::new(shell_bin);
        cmd.arg("-s").args(shell_args).stdin(Stdio::piped());
        cmd.env(ENV_REAL_PATH, &real_path)
            .env(ENV_DEPTH, inherit.depth.to_string())
            .env(ENV_VETTED, inherit.vetted.join(","))
            .env(ENV_ANCESTORS, inherit.ancestors.join(","))
            .env(ENV_OPTS, inherit.opts_argv.join(&OPTS_SEP.to_string()));
        match &self.shim {
            Some(shim) => cmd.env("PATH", format!("{}:{real_path}", shim.dir.path().display())),
            None => cmd.env("PATH", &real_path),
        };
        let mut child = cmd.spawn().context("spawning shell")?;
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(source.as_bytes())
            .context("feeding script to shell")?;
        let status = child.wait()?;
        Ok(status.code().unwrap_or(1))
    }
}

/// A directory whose `bash` and `sh` are this executable.
struct Shim {
    dir: TempDir,
}

impl Shim {
    fn create() -> Result<Self> {
        let exe = env::current_exe().context("locating bashka executable")?;
        let dir = tempfile::Builder::new().prefix("bashka-shim-").tempdir()?;
        for name in ["bash", "sh"] {
            std::os::unix::fs::symlink(&exe, dir.path().join(name))
                .with_context(|| format!("creating {name} shim"))?;
        }
        Ok(Self { dir })
    }
}

/// The PATH without any shim directory, so the real shell can be found.
pub fn real_path() -> String {
    env::var(ENV_REAL_PATH)
        .or_else(|_| env::var("PATH"))
        .unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into())
}

pub fn find_in_path(name: &str, path: &str) -> Result<PathBuf> {
    for dir in path.split(':').filter(|d| !d.is_empty()) {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() && !is_self(&candidate) {
            return Ok(candidate);
        }
    }
    bail!("`{name}` not found")
}

fn is_self(p: &Path) -> bool {
    match (
        std::fs::canonicalize(p),
        env::current_exe().and_then(std::fs::canonicalize),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
