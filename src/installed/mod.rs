pub mod name;
pub mod store;
pub mod track;

use crate::chain::net;
use crate::cli::Options;
use crate::runner::{self, Inherit};
use crate::ui::{self, paint};
use crate::vet::{Approval, Session};
use anyhow::{Context, Result, bail};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use store::{Lockfile, Package};

/// bashka's own registry entry.
pub const SELF_NAME: &str = "bashka";
/// The bootstrap installer; `bashka update bashka` re-fetches it through the usual review.
pub const SELF_INSTALLER: &str =
    "https://raw.githubusercontent.com/dmtrKovalenko/bashka/main/install.sh";

/// Bin directories a release of bashka is installed into (by `install.sh` or by hand).
/// `$PREFIX/bin` covers Termux, whose home has no `.local/bin` on PATH.
fn bin_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("/usr/local/bin")];
    if let Some(h) = home {
        dirs.extend([h.join(".local/bin"), h.join("bin"), h.join(".cargo/bin")]);
    }
    // Termux: `$PREFIX/bin` is where install.sh puts bashka on Android.
    if let Some(prefix) = std::env::var_os("PREFIX").filter(|p| !p.is_empty()) {
        dirs.push(PathBuf::from(prefix).join("bin"));
    }
    dirs
}

/// bashka's own record, synthesized when the running binary sits in a bin directory. The first
/// install goes through plain `bash`, so nothing else would ever put bashka in its own registry.
/// A development build under `target/` yields `None`.
pub fn self_package(exe: &Path, home: Option<&Path>) -> Option<Package> {
    let parent = exe.parent()?;
    if !bin_dirs(home).iter().any(|d| d == parent) {
        return None;
    }
    let installed_at = std::fs::metadata(exe)
        .and_then(|m| m.modified())
        .map_or_else(|_| store::now(), store::rfc3339);
    Some(Package {
        name: SELF_NAME.into(),
        source: SELF_INSTALLER.into(),
        command: format!("curl --proto '=https' --tlsv1.2 -fsSL {SELF_INSTALLER} | bash"),
        installed_at,
        version: env!("CARGO_PKG_VERSION").into(),
        binaries: vec![exe.to_path_buf()],
        ..Package::default()
    })
}

/// The lock file plus bashka's own entry when it is installed but not yet recorded.
fn load_registry() -> Result<Lockfile> {
    let mut lock = store::load()?;
    if lock.get(SELF_NAME).is_none()
        && let Ok(exe) = std::env::current_exe()
        && let Some(me) = self_package(&exe, track::home().as_deref())
    {
        lock.upsert(me);
    }
    Ok(lock)
}

/// How the installer was invoked, for the record.
pub struct Invocation {
    pub source_url: Option<String>,
    /// The fetcher's command line as seen in the process table (`curl -fsSL https://…`).
    pub fetcher: Option<String>,
    pub name: Option<String>,
    pub bashka_opts: Vec<String>,
    pub shell_args: Vec<String>,
}

impl Invocation {
    fn command(&self) -> String {
        let fetch = match (&self.fetcher, &self.source_url) {
            (Some(f), _) => f.clone(),
            (None, Some(u)) => format!("curl -fsSL {u}"),
            (None, None) => "…".into(),
        };
        let mut cmd = format!("{fetch} | bashka");
        for o in &self.bashka_opts {
            cmd.push(' ');
            cmd.push_str(o);
        }
        if !self.shell_args.is_empty() {
            cmd.push_str(" --");
            for a in &self.shell_args {
                cmd.push(' ');
                cmd.push_str(a);
            }
        }
        cmd
    }
}

/// Runs an approved top-level script and records what it installed.
#[allow(clippy::too_many_lines)]
pub fn run_tracked(
    session: &mut Session,
    approval: &Approval,
    source: &str,
    inherit: &Inherit,
    inv: &Invocation,
    previous: Option<&Package>,
) -> Result<i32> {
    let label = inv.source_url.clone().unwrap_or_else(|| "<stdin>".into());
    let watch = track::Watch::for_layers(&approval.layers, &runner::real_path(), track::home());
    let before = track::Snapshot::take(&watch);
    let code = session.run(
        &label,
        "bash",
        source,
        &inv.shell_args,
        inherit,
        approval.needs_shim,
    )?;
    if code != 0 {
        session.prompter.say(&format!(
            "{}\n",
            paint(
                ui::DIM,
                format!("not recorded: the installer exited with code {code}")
            )
        ));
        return Ok(code);
    }
    let after = track::Snapshot::take(&watch);
    let changes = track::diff(&before, &after, &watch);
    if changes.binaries.is_empty()
        && changes.created_dirs.is_empty()
        && !watch.unresolved.is_empty()
    {
        session.prompter.say(&format!(
            "{} no new binaries seen; the installer's destinations were computed at run time ({})\n",
            paint(ui::YELLOW, "note:"),
            watch.unresolved.join(", ")
        ));
    }
    let sha = crate::sha256(source);
    let script = crate::parser::parse(source).ok();
    let name = match previous {
        Some(p) => p.name.clone(),
        None => {
            if let Some(n) = name::derive(
                inv.name.as_deref(),
                &changes.binaries,
                &watch.flat,
                inv.source_url.as_deref(),
                script.as_ref(),
                &inv.shell_args,
            ) {
                n
            } else {
                let mut msg = format!(
                    "{} the installer finished but bashka could not name what it installed; \
                 nothing was recorded. Rerun with `--name <name>` to register it.\n",
                    paint(ui::RED, "error:")
                );
                for b in &changes.binaries {
                    let _ = writeln!(msg, "   {} {}", paint(ui::DIM, "+"), tilde(b));
                }
                for d in &changes.created_dirs {
                    let _ = writeln!(msg, "   {} {}/", paint(ui::DIM, "+"), tilde(d));
                }
                session.prompter.say(&msg);
                return Ok(code);
            }
        }
    };
    let now = store::now();
    let mut pkg = Package {
        name: name.clone(),
        source: label,
        command: inv.command(),
        installed_at: previous.map_or_else(|| now.clone(), |p| p.installed_at.clone()),
        updated_at: previous.map(|_| now),
        version: store::UNKNOWN_VERSION.into(),
        script_sha256: sha,
        bashka_opts: inv.bashka_opts.clone(),
        shell_args: inv.shell_args.clone(),
        binaries: changes.binaries.clone(),
        dirs: changes.created_dirs.clone(),
    };
    if let Some(prev) = previous {
        // Files from the previous install that were not rewritten still belong to the package.
        for b in prev.binaries.iter().filter(|b| b.exists()) {
            if !pkg.binaries.contains(b) {
                pkg.binaries.push(b.clone());
            }
        }
        for d in prev.dirs.iter().filter(|d| d.is_dir()) {
            if !pkg.dirs.contains(d) {
                pkg.dirs.push(d.clone());
            }
        }
        pkg.binaries.sort();
        pkg.dirs.sort();
    }
    pkg.version = pkg
        .binaries
        .first()
        .map_or_else(|| store::UNKNOWN_VERSION.into(), |b| probe_version(b));
    let mut lock = store::load()?;
    lock.upsert(pkg.clone());
    store::save(&lock)?;
    session.prompter.say(&describe_record(&pkg, &changes));
    Ok(code)
}

/// Asks the installed binary for its version: `--version`, then `-version`, then `version`.
/// The first run that exits 0 and prints something wins; a version-looking token (`1.2.3`,
/// `v0.4.0`) is preferred over the whole line. Anything else is `0.0.0-unknown`.
pub fn probe_version(bin: &Path) -> String {
    for flag in ["--version", "-version", "version"] {
        let out = std::process::Command::new(bin)
            .arg(flag)
            .stdin(std::process::Stdio::null())
            .env_remove("BASHFLAGS_REAL_PATH")
            .output();
        let Ok(out) = out else { continue };
        if !out.status.success() {
            continue;
        }
        let text = if out.stdout.iter().any(|b| !b.is_ascii_whitespace()) {
            String::from_utf8_lossy(&out.stdout).into_owned()
        } else {
            String::from_utf8_lossy(&out.stderr).into_owned()
        };
        let Some(line) = text.lines().map(str::trim).find(|l| !l.is_empty()) else {
            continue;
        };
        let looks_like_version = |w: &str| {
            let w = w.trim_start_matches('v');
            w.starts_with(|c: char| c.is_ascii_digit()) && w.contains('.')
        };
        return line
            .split_whitespace()
            .map(|w| w.trim_matches(|c: char| ",;()".contains(c)))
            .find(|w| looks_like_version(w))
            .unwrap_or(line)
            .chars()
            .take(60)
            .collect();
    }
    store::UNKNOWN_VERSION.into()
}

fn describe_record(pkg: &Package, changes: &track::Changes) -> String {
    let mut out = format!(
        "{} recorded {} {} in the install registry",
        "📦",
        paint(ui::BOLD, &pkg.name),
        paint(ui::DIM, &pkg.version)
    );
    if changes.binaries.is_empty() && changes.created_dirs.is_empty() {
        out.push_str(&paint(ui::DIM, " (no new binaries detected)"));
    }
    out.push('\n');
    for b in &changes.binaries {
        let _ = writeln!(out, "   {} {}", paint(ui::GREEN, "+"), tilde(b));
    }
    for d in &changes.created_dirs {
        let _ = writeln!(out, "   {} {}/", paint(ui::GREEN, "+"), tilde(d));
    }
    out.push_str(&paint(
        ui::DIM,
        format!("   bashka update {0} | bashka remove {0}\n", pkg.name),
    ));
    out
}

/// `/home/me/.local/bin/x` -> `~/.local/bin/x` for display.
pub fn tilde(p: &Path) -> String {
    let s = p.display().to_string();
    match std::env::var("HOME") {
        Ok(h) if !h.is_empty() && (s == h || s.starts_with(&format!("{h}/"))) => {
            format!("~{}", &s[h.len()..])
        }
        _ => s,
    }
}

/// `bashka list`: one aligned row per package, pacman `-Q` style.
pub fn list(long: bool) -> Result<String> {
    let lock = load_registry()?;
    if lock.packages.is_empty() {
        return Ok(format!(
            "{}\n",
            paint(
                ui::DIM,
                "nothing installed through bashka yet (run `curl … | bashka` to add one)"
            )
        ));
    }
    if long {
        let blocks: Vec<String> = lock.packages.iter().map(info_block).collect();
        return Ok(blocks.join("\n"));
    }
    let header = ["NAME", "VERSION", "INSTALLED", "UPDATED", "FILES", "SOURCE"];
    let rows: Vec<[String; 6]> = lock
        .packages
        .iter()
        .map(|p| {
            let missing = p.paths().filter(|x| !x.exists()).count();
            let count = p.binaries.len() + p.dirs.len();
            let files = match (count, missing) {
                (0, _) => "-".to_string(),
                (n, 0) => n.to_string(),
                (n, m) => format!("{n} ({m} missing)"),
            };
            [
                p.name.clone(),
                p.version.clone(),
                day(&p.installed_at),
                p.updated_at.as_deref().map_or_else(|| "-".into(), day),
                files,
                p.source.clone(),
            ]
        })
        .collect();
    let mut widths: Vec<usize> = header.iter().map(|h| h.len()).collect();
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row.iter()) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    let line = |cells: &[&str], styles: &[Option<anstyle::Style>]| -> String {
        let mut l = String::new();
        for (i, cell) in cells.iter().enumerate() {
            let pad = if i + 1 < cells.len() {
                widths[i] - cell.chars().count() + 2
            } else {
                0
            };
            let text = match styles.get(i).copied().flatten() {
                Some(st) => paint(st, cell),
                None => cell.to_string(),
            };
            l.push_str(&text);
            l.push_str(&" ".repeat(pad));
        }
        l.trim_end().to_string()
    };
    out.push_str(&line(&header, &[Some(ui::BOLD); 6]));
    out.push('\n');
    for row in &rows {
        let cells: Vec<&str> = row.iter().map(String::as_str).collect();
        let files_style = if row[4].contains("missing") {
            Some(ui::YELLOW)
        } else {
            None
        };
        out.push_str(&line(
            &cells,
            &[Some(ui::BOLD), None, None, None, files_style, Some(ui::DIM)],
        ));
        out.push('\n');
    }
    out.push_str(&paint(
        ui::DIM,
        format!(
            "\n{} package(s) recorded. Run `bashka info <name>` for details\n",
            lock.packages.len(),
        ),
    ));
    Ok(out)
}

/// `bashka info <name>`: pacman `-Qi` style key/value block.
pub fn info(name_arg: &str) -> Result<String> {
    let lock = load_registry()?;
    let Some(pkg) = lock.get(name_arg) else {
        bail!("`{name_arg}` is not in the install registry (see `bashka list`)");
    };
    Ok(info_block(pkg))
}

fn info_block(p: &Package) -> String {
    let mut out = String::new();
    let mut field = |key: &str, value: String| {
        let _ = writeln!(out, "{}: {value}", paint(ui::BOLD, format!("{key:<16}")));
    };
    let mark = |path: &Path, suffix: &str| {
        let shown = format!("{}{suffix}", tilde(path));
        if path.exists() {
            shown
        } else {
            format!("{shown} {}", paint(ui::YELLOW, "(missing)"))
        }
    };
    let listed = |items: Vec<String>| -> String {
        if items.is_empty() {
            "-".to_string()
        } else {
            items.join(&format!("\n{:<16}  ", ""))
        }
    };
    field("Name", p.name.clone());
    field("Version", p.version.clone());
    field("Source", p.source.clone());
    field("Installed", stamp(&p.installed_at));
    field(
        "Updated",
        p.updated_at.as_deref().map_or_else(|| "-".into(), stamp),
    );
    field("Script SHA256", p.script_sha256.clone());
    field("Command", p.command.clone());
    field(
        "Bashka Options",
        if p.bashka_opts.is_empty() {
            "-".into()
        } else {
            p.bashka_opts.join(" ")
        },
    );
    field(
        "Shell Args",
        if p.shell_args.is_empty() {
            "-".into()
        } else {
            p.shell_args.join(" ")
        },
    );
    field(
        "Binaries",
        listed(p.binaries.iter().map(|b| mark(b, "")).collect()),
    );
    field(
        "Directories",
        listed(p.dirs.iter().map(|d| mark(d, "/")).collect()),
    );
    out
}

/// `2026-09-15T21:59:33Z` -> `2026-09-15`.
fn day(ts: &str) -> String {
    ts.chars().take(10).collect()
}

/// `2026-09-15T21:59:33Z` -> `2026-09-15 21:59 UTC`.
fn stamp(ts: &str) -> String {
    match ts.split_once('T') {
        Some((d, t)) => format!(
            "{d} {} UTC",
            t.trim_end_matches('Z').chars().take(5).collect::<String>()
        ),
        None => ts.to_string(),
    }
}

/// `bashka remove <name>`: deletes every recorded binary and created directory, then forgets
/// the package.
pub fn remove(name_arg: &str, dry_run: bool) -> Result<i32> {
    let mut lock = load_registry()?;
    let Some(pkg) = lock.get(name_arg).cloned() else {
        bail!("`{name_arg}` is not in the install registry (see `bashka list`)");
    };
    if pkg.name == SELF_NAME {
        return remove_self(&lock, &pkg, dry_run);
    }
    if pkg.paths().next().is_none() {
        anstream::eprintln!(
            "{} no files were tracked when `{}` was installed (the installer wrote nowhere bashka \
             could see, or handed off to another program), so this only removes the registry \
             entry. Any files it installed stay on disk.",
            paint(ui::YELLOW, "note:"),
            pkg.name
        );
    }
    let mut failed = Vec::new();
    for path in pkg.paths() {
        let shown = tilde(path);
        if dry_run {
            anstream::println!("would remove {shown}");
            continue;
        }
        match remove_path(path) {
            Ok(Removed::File) => anstream::println!("{} {shown}", paint(ui::RED, "-")),
            Ok(Removed::Dir) => anstream::println!("{} {shown}/", paint(ui::RED, "-")),
            Ok(Removed::Absent) => {
                anstream::println!(
                    "{} {shown} {}",
                    paint(ui::DIM, "·"),
                    paint(ui::DIM, "(already gone)")
                );
            }
            Err(e) => {
                anstream::eprintln!("{} {shown}: {e:#}", paint(ui::RED, "failed:"));
                failed.push(path.to_path_buf());
            }
        }
    }
    if dry_run {
        return Ok(0);
    }
    if failed.is_empty() {
        lock.remove(&pkg.name);
        store::save(&lock)?;
        anstream::println!("{} {} removed", "🗑️ ", paint(ui::BOLD, &pkg.name));
        Ok(0)
    } else {
        let mut rest = pkg.clone();
        rest.binaries.retain(|b| failed.contains(b));
        rest.dirs.retain(|d| failed.contains(d));
        lock.upsert(rest);
        store::save(&lock)?;
        anstream::eprintln!(
            "{} {} path(s) could not be removed; `{}` stays in the registry with just those \
             (try again with sudo)",
            paint(ui::YELLOW, "warning:"),
            failed.len(),
            pkg.name
        );
        Ok(1)
    }
}

enum Removed {
    File,
    Dir,
    Absent,
}

fn remove_path(path: &Path) -> Result<Removed> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Removed::Absent),
        Err(e) => return Err(e.into()),
    };
    if meta.is_dir() {
        guard_dir(path, track::home().as_deref())?;
        std::fs::remove_dir_all(path)?;
        Ok(Removed::Dir)
    } else {
        std::fs::remove_file(path)?;
        Ok(Removed::File)
    }
}

/// Never recursively delete something that could not have been created by a single installer.
fn guard_dir(path: &Path, home: Option<&Path>) -> Result<()> {
    if track::is_broad(path, home) {
        bail!(
            "refusing to remove shared directory {} recursively",
            path.display()
        );
    }
    if path.components().count() < 3 {
        bail!(
            "refusing to remove {} recursively (too shallow)",
            path.display()
        );
    }
    Ok(())
}

/// `bashka remove bashka`: deletes the binary, then bashka's own configuration and the install
/// registry, and says goodbye. Other recorded packages stay on disk but are no longer tracked.
fn remove_self(lock: &Lockfile, me: &Package, dry_run: bool) -> Result<i32> {
    let others: Vec<&str> = lock
        .packages
        .iter()
        .filter(|p| p.name != SELF_NAME)
        .map(|p| p.name.as_str())
        .collect();
    if !others.is_empty() {
        anstream::eprintln!(
            "{} {} other package(s) are tracked here ({}); they stay installed but their records \
             go with the registry. `bashka remove <name>` them first to delete their files too.",
            paint(ui::YELLOW, "note:"),
            others.len(),
            others.join(", ")
        );
    }
    let config = crate::config::user_config_path();
    let registry = store::path()?;
    // The binary, then the config file and the lock file, each followed by its directory
    // (removed only when empty, so nothing else that lives there is touched).
    let mut targets: Vec<PathBuf> = me.paths().map(Path::to_path_buf).collect();
    for file in config.iter().chain(std::iter::once(&registry)) {
        targets.push(file.clone());
        if let Some(dir) = file
            .parent()
            .filter(|d| d.file_name().is_some_and(|n| n == "bashka"))
        {
            targets.push(dir.to_path_buf());
        }
    }
    let mut failed = 0;
    for path in &targets {
        let shown = tilde(path);
        if dry_run {
            anstream::println!("would remove {shown}");
            continue;
        }
        let result = match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => Err(e),
            Ok(m) if m.is_dir() => std::fs::remove_dir(path),
            Ok(_) => std::fs::remove_file(path),
        };
        match result {
            Ok(()) => anstream::println!("{} {shown}", paint(ui::RED, "-")),
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                anstream::println!(
                    "{} {shown}/ {}",
                    paint(ui::DIM, "·"),
                    paint(ui::DIM, "(kept: not empty)")
                );
            }
            Err(e) => {
                anstream::eprintln!("{} {shown}: {e}", paint(ui::RED, "failed:"));
                failed += 1;
            }
        }
    }
    if dry_run {
        return Ok(0);
    }
    if failed > 0 {
        anstream::eprintln!(
            "{} {failed} path(s) could not be removed (try again with sudo)",
            paint(ui::YELLOW, "warning:")
        );
        return Ok(1);
    }
    anstream::println!(
        "\n👋 {} bashka, its configuration and its install registry are gone.\n   {}\n   {}",
        paint(ui::BOLD, "bye-bye!"),
        paint(ui::DIM, "come back any time:"),
        paint(ui::DIM, &me.command)
    );
    Ok(0)
}

/// `bashka update <name>`: re-fetches the recorded installer and runs it through the full review.
pub fn update(name_arg: &str, current: &Options) -> Result<i32> {
    let lock = load_registry()?;
    let Some(pkg) = lock.get(name_arg).cloned() else {
        bail!("`{name_arg}` is not in the install registry (see `bashka list`)");
    };
    let Some(url) = pkg.url() else {
        bail!(
            "`{}` was installed from stdin without a known URL, so it cannot be re-fetched; \
             re-run the original command instead:\n  {}",
            pkg.name,
            pkg.command
        );
    };
    // The recorded options are the baseline; anything passed now is layered on top.
    let mut opts = Options::from_argv(&pkg.bashka_opts);
    opts.yes |= current.yes;
    opts.non_interactive |= current.non_interactive;
    opts.force |= current.force;
    opts.check |= current.check;
    if current.max_depth.is_some() {
        opts.max_depth = current.max_depth;
    }
    if current.descend.is_some() {
        opts.descend = current.descend;
    }
    if current.config.is_some() {
        opts.config.clone_from(&current.config);
    }
    if opts.yes {
        opts.non_interactive = false;
    }
    let mut session = Session::new(opts.clone())?;
    let spinner = session
        .prompter
        .spinner(&format!("{} fetching {url}", session.prompter.icons.fetch));
    let source = match net::fetch(url) {
        Ok(s) => {
            spinner.finish(format!(
                "{} fetched {url} ({} lines)",
                session.prompter.icons.fetch,
                s.lines().count()
            ));
            s
        }
        Err(e) => {
            spinner.clear();
            return Err(e).with_context(|| format!("updating {}", pkg.name));
        }
    };
    if crate::sha256(&source) == pkg.script_sha256 {
        session.prompter.say(&format!(
            "{}\n",
            paint(ui::DIM, "installer script is unchanged since the last run")
        ));
    }
    if opts.check {
        return Ok(match session.check(source, url.to_string(), 0)? {
            crate::policy::Outcome::Green => 0,
            crate::policy::Outcome::Neutral => 1,
            crate::policy::Outcome::Red => 2,
            crate::policy::Outcome::StrongGate => 3,
            crate::policy::Outcome::Critical => 4,
        });
    }
    let Some(approval) = session.vet(&source, url.to_string(), 0)? else {
        return Ok(1);
    };
    let inherit = Inherit {
        depth: 0,
        vetted: approval.vetted.clone(),
        ancestors: vec![crate::sha256(&source)],
        opts_argv: opts.to_argv(),
    };
    let inv = Invocation {
        source_url: Some(url.to_string()),
        fetcher: pkg.command.split(" | bashka").next().map(String::from),
        name: Some(pkg.name.clone()),
        bashka_opts: opts.to_argv(),
        shell_args: pkg.shell_args.clone(),
    };
    run_tracked(&mut session, &approval, &source, &inherit, &inv, Some(&pkg))
}

impl Options {
    /// Inverse of `to_argv`.
    pub fn from_argv(argv: &[String]) -> Self {
        <crate::cli::Cli as clap::Parser>::parse_from(
            std::iter::once("bashka".to_string()).chain(argv.iter().cloned()),
        )
        .opts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_the_invocation() {
        let inv = Invocation {
            source_url: Some("https://mise.run".into()),
            fetcher: Some("curl -fsSL https://mise.run".into()),
            name: None,
            bashka_opts: vec!["--yes".into()],
            shell_args: vec!["--skip-shell".into()],
        };
        assert_eq!(
            inv.command(),
            "curl -fsSL https://mise.run | bashka --yes -- --skip-shell"
        );
        let inv = Invocation {
            source_url: Some("https://x.io/i".into()),
            fetcher: None,
            name: None,
            bashka_opts: vec![],
            shell_args: vec![],
        };
        assert_eq!(inv.command(), "curl -fsSL https://x.io/i | bashka");
    }

    #[test]
    fn guards_against_deleting_broad_directories() {
        let home = Some(Path::new("/home/t"));
        assert!(guard_dir(Path::new("/"), home).is_err());
        assert!(guard_dir(Path::new("/usr/local"), home).is_err());
        assert!(guard_dir(Path::new("/opt"), home).is_err());
        assert!(guard_dir(Path::new("/home/t"), home).is_err());
        assert!(guard_dir(Path::new("/home/t/.local"), home).is_err());
        assert!(guard_dir(Path::new("/home/t/.local/bin"), home).is_err());
        assert!(guard_dir(Path::new("/x"), home).is_err(), "too shallow");
        assert!(guard_dir(Path::new("/opt/x"), home).is_ok());
        assert!(guard_dir(Path::new("/home/t/.foo"), home).is_ok());
    }

    #[test]
    fn self_package_only_for_installed_binaries() {
        let home = Some(Path::new("/home/t"));
        let me = self_package(Path::new("/home/t/.local/bin/bashka"), home).unwrap();
        assert_eq!(me.name, "bashka");
        assert_eq!(me.source, SELF_INSTALLER);
        assert!(me.command.ends_with("| bash"), "{}", me.command);
        assert_eq!(
            me.binaries,
            vec![PathBuf::from("/home/t/.local/bin/bashka")]
        );
        assert!(me.dirs.is_empty());
        assert!(self_package(Path::new("/usr/local/bin/bashka"), home).is_some());
        assert!(self_package(Path::new("/home/t/.cargo/bin/bashka"), home).is_some());
        assert!(
            self_package(Path::new("/home/t/dev/bashka/target/release/bashka"), home).is_none(),
            "development builds are not an install"
        );
        assert!(self_package(Path::new("/home/t/.local/bin/bashka"), None).is_none());
    }

    #[test]
    fn probe_version_tries_flags_then_gives_up() {
        let dir = tempfile::tempdir().unwrap();
        let script = |name: &str, body: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            let mut perm = std::fs::metadata(&p).unwrap().permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut perm, 0o755);
            std::fs::set_permissions(&p, perm).unwrap();
            p
        };
        let dashdash = script(
            "a",
            "[ \"$1\" = --version ] && echo 'tool 1.2.3 (abc)' || exit 2",
        );
        assert_eq!(probe_version(&dashdash), "1.2.3");
        let dash = script("b", "[ \"$1\" = -version ] && echo 'v0.4.0' || exit 1");
        assert_eq!(probe_version(&dash), "v0.4.0");
        let sub = script(
            "c",
            "[ \"$1\" = version ] && echo 'go version go1.22.1 linux/amd64' || exit 1",
        );
        assert_eq!(
            probe_version(&sub),
            "go version go1.22.1 linux/amd64",
            "no bare version token: the whole line"
        );
        let stderr_only = script("d", "echo 'x 9.8' >&2");
        assert_eq!(probe_version(&stderr_only), "9.8");
        let plain = script("e", "echo demo");
        assert_eq!(
            probe_version(&plain),
            "demo",
            "no version token: the whole line"
        );
        let mute = script("f", "exit 1");
        assert_eq!(probe_version(&mute), store::UNKNOWN_VERSION);
        assert_eq!(
            probe_version(dir.path().join("missing").as_path()),
            store::UNKNOWN_VERSION
        );
    }
}
