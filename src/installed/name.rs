use crate::parser::Ctx;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Path segments and host labels that say nothing about *what* is installed.
const GENERIC: &[&str] = &[
    "install",
    "installer",
    "setup",
    "get",
    "i",
    "run",
    "index",
    "download",
    "downloads",
    "dl",
    "latest",
    "main",
    "master",
    "head",
    "scripts",
    "script",
    "bootstrap",
    "bin",
    "raw",
    "releases",
    "release",
    "www",
    "sh",
    "cli",
    "app",
    "src",
    "dist",
    "static",
    "assets",
    "contrib",
    "ci",
    "x",
    "s",
    "tools",
    "tool",
    "stable",
    "current",
    "cdn",
    "api",
    "repo",
    "repos",
    "true",
    "false",
    "yes",
    "no",
    "null",
    "none",
    "default",
    "local",
    "usr",
    "home",
    "tmp",
    "bash",
    "shell",
    "github",
    "githubusercontent",
    "gitlab",
    "bitbucket",
    "amazonaws",
    "cloudfront",
    "googleapis",
    "storage",
    "objects",
    "files",
    "pkg",
    "packages",
    "archive",
    "mirror",
    "mirrors",
    "version",
    "versions",
    "txt",
    "json",
    "tar",
    "gz",
    "zip",
    "linux",
    "darwin",
    "macos",
    "windows",
    "amd64",
    "x86_64",
    "arm64",
    "aarch64",
    "unknown",
    "gnu",
    "musl",
    "apple",
    "registry",
    "npmjs",
    "pypi",
    "crates",
    "docker",
    "ghcr",
    "quay",
];

const GITHUB_HOSTS: &[&str] = &[
    "raw.githubusercontent.com",
    "github.com",
    "raw.github.com",
    "api.github.com",
    "gist.githubusercontent.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
];

/// Variables an installer typically uses to hold its own name.
const NAME_HINTS: &[&str] = &[
    "NAME", "APP", "TOOL", "BIN", "PKG", "PACKAGE", "PROJECT", "PROGRAM", "CMD", "REPO", "PRODUCT",
    "BINARY",
];
/// …unless the variable is really about one of these.
const NOT_NAME: &[&str] = &[
    "DIR", "PATH", "URL", "VERSION", "HOME", "FILE", "TMP", "TEMP", "ARCH", "OS", "SUM", "HASH",
    "SHA", "EXT", "PLATFORM", "TARGET", "PREFIX", "ROOT", "BASE", "USER", "OWNER", "ORG",
];

/// The name to record: explicit override, else binaries, URL, script, invocation arguments.
pub fn derive(
    override_name: Option<&str>,
    binaries: &[PathBuf],
    bin_dirs: &BTreeSet<PathBuf>,
    url: Option<&str>,
    script: Option<&Ctx>,
    shell_args: &[String],
) -> Option<String> {
    if let Some(n) = override_name.map(sanitize).filter(|n| !n.is_empty()) {
        return Some(n);
    }
    from_binaries(binaries, bin_dirs)
        .or_else(|| url.and_then(from_url))
        .or_else(|| script.and_then(from_script))
        .or_else(|| from_args(shell_args))
}

/// Generic installers take the project on the command line: `-- --git cantino/mcfly`.
pub fn from_args(shell_args: &[String]) -> Option<String> {
    shell_args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .find_map(|a| {
            let (_, repo) = a.split_once('/')?;
            (!repo.contains('/')).then(|| accept(repo)).flatten()
        })
}

/// The script reads `$1`, `$2`, `$@`…: what it installs may only be known from its arguments.
pub fn takes_arguments(ctx: &Ctx) -> bool {
    let positional = |text: &str| {
        text.contains("$@")
            || text.contains("$#")
            || text.contains("${1")
            || text.contains("${2")
            || (1..=9).any(|i| text.contains(&format!("${i}")))
    };
    ctx.commands()
        .flat_map(|c| c.args.iter().map(|w| w.text.as_str()))
        .chain(ctx.assignments().map(|a| a.value.text.as_str()))
        .any(positional)
}

/// What can be known before the run: URL first, then the script itself.
pub fn static_name(url: Option<&str>, script: &Ctx) -> Option<String> {
    url.and_then(from_url).or_else(|| from_script(script))
}

/// The single binary the installer put on a bin directory, or the single binary overall.
pub fn from_binaries(binaries: &[PathBuf], bin_dirs: &BTreeSet<PathBuf>) -> Option<String> {
    let in_bin: Vec<&PathBuf> = binaries
        .iter()
        .filter(|b| b.parent().is_some_and(|p| bin_dirs.contains(p)))
        .collect();
    let pick = match in_bin.as_slice() {
        [only] => Some(*only),
        [] => match binaries {
            [only] => Some(only),
            _ => None,
        },
        _ => None,
    };
    pick.and_then(|p| file_stem_name(p))
}

fn file_stem_name(p: &Path) -> Option<String> {
    let name = p.file_name()?.to_str()?;
    let name = name
        .strip_suffix(".sh")
        .or_else(|| name.strip_suffix(".bash"))
        .unwrap_or(name);
    accept(name)
}

/// `https://get.pnpm.io/install.sh` -> `pnpm`; `https://claude.anthropic.ai` -> `claude`.
pub fn from_url(url: &str) -> Option<String> {
    from_url_path(url).or_else(|| from_url_host(url))
}

fn url_parts(url: &str) -> Option<(String, Vec<&str>)> {
    let host = crate::url::host(url)?;
    let after = url.split_once("://")?.1;
    let path = after
        .split_once('/')
        .map_or("", |(_, p)| p)
        .split(['?', '#'])
        .next()
        .unwrap_or("");
    Some((host, path.split('/').filter(|s| !s.is_empty()).collect()))
}

fn is_github_host(host: &str) -> bool {
    GITHUB_HOSTS.contains(&host)
}

/// A name from the URL's path: the GitHub repository, or the first telling segment.
pub fn from_url_path(url: &str) -> Option<String> {
    let (host, segments) = url_parts(url)?;
    if is_github_host(&host) {
        // `api.github.com/repos/<owner>/<repo>/…` carries a leading `repos`.
        let segs: Vec<&str> = segments
            .iter()
            .copied()
            .skip_while(|s| *s == "repos")
            .collect();
        let owner = segs.first().map(|s| stem(s));
        let repo = segs.get(1).map(|s| stem(s));
        return [repo, owner]
            .into_iter()
            .flatten()
            .find_map(|cand| accept(&cand));
    }
    segments
        .iter()
        .filter(|seg| !seg.contains(['$', '`']))
        .map(|seg| stem(seg))
        .filter(|s| !is_version(s))
        .find_map(|s| accept(&s))
}

/// A name from the host: most specific label first, TLD dropped (`claude.anthropic.ai` -> `claude`).
pub fn from_url_host(url: &str) -> Option<String> {
    let (host, _) = url_parts(url)?;
    if is_github_host(&host) {
        return None;
    }
    let mut labels: Vec<&str> = host.split('.').collect();
    if labels.len() > 1 {
        labels.pop();
    }
    if labels.len() > 1 && labels.last().is_some_and(|l| l.len() <= 3) {
        labels.pop(); // `co.uk`-style second-level suffixes
    }
    labels.into_iter().find_map(accept)
}

/// Commands that fetch: their URLs say what is being installed, unlike URLs in help text.
const FETCHERS: &[&str] = &["curl", "wget", "fetch", "git", "aria2c", "http", "https"];

/// The script's own idea of what it installs.
pub fn from_script(ctx: &Ctx) -> Option<String> {
    let vars = crate::chain::resolve::literal_vars(ctx);
    let folded = |text: &str| crate::chain::resolve::fold(text, &vars);
    // A URL that stays partly dynamic still names things in its literal head:
    // `https://dl.deno.land/release/${v}/deno.zip` -> `https://dl.deno.land/release/`.
    // URLs with a literal host are kept whole; `from_url_path` skips the `$…` segments, so
    // `$BASE/$version/$platform/claude` still yields `claude`.
    let urls_in_words = |words: Vec<String>| -> Vec<String> {
        words
            .iter()
            .flat_map(|w| {
                crate::url::urls_in(w)
                    .filter(|u| crate::url::host(u).is_some_and(|h| !h.contains('$')))
                    .map(String::from)
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let is_github = |u: &str| crate::url::host(u).is_some_and(|h| is_github_host(&h));

    let words_of = |cmds: Vec<&crate::parser::Command>| -> Vec<String> {
        cmds.iter()
            .flat_map(|c| c.args.iter().map(|w| folded(&w.text)))
            .collect()
    };
    // URLs by how much they say: downloaded ones first, then those kept in variables, then
    // anything mentioned in messages.
    let fetched = urls_in_words(words_of(
        ctx.commands()
            .filter(|c| FETCHERS.contains(&c.name.as_str()))
            .collect(),
    ));
    let assigned = urls_in_words(ctx.assignments().map(|a| folded(&a.value.text)).collect());
    let mentioned = urls_in_words(words_of(
        ctx.commands()
            .filter(|c| !FETCHERS.contains(&c.name.as_str()))
            .collect(),
    ));
    let github = |urls: &[String]| {
        urls.iter()
            .filter(|u| is_github(u))
            .find_map(|u| from_url_path(u))
    };

    // 1. A GitHub repository the script downloads from.
    if let Some(n) = github(&fetched).or_else(|| github(&assigned)) {
        return Some(n);
    }
    // 2. `APP_NAME="zoxide"`, `REPO=astral-sh/rye`, `BINARY="rye-${ARCH}"`, `executable='pnpm'` …
    let from_var = ctx.assignments().find_map(|a| {
        let upper = a.name.to_ascii_uppercase();
        let hinted = NAME_HINTS.iter().any(|h| upper.contains(h));
        let excluded = NOT_NAME.iter().any(|h| upper.contains(h));
        if !hinted || excluded {
            return None;
        }
        let value = folded(&a.value.text);
        let literal_head = value.split(['$', '`']).next().unwrap_or("");
        let head = literal_head.trim_end_matches(['-', '_', '.', '/']);
        // `owner/repo` -> `repo`
        let head = head.rsplit('/').next().unwrap_or(head);
        accept(head)
    });
    if from_var.is_some() {
        return from_var;
    }
    // 3. The program the script downloads and runs: `binary_path="$DIR/claude-$version"` -> `claude`.
    let head_name = |text: &str| {
        let value = crate::install_paths::fold_all(ctx, text);
        let base = value.rsplit('/').next().unwrap_or(&value);
        let head = base.split(['$', '`']).next().unwrap_or("");
        accept(head.trim_end_matches(['-', '_', '.']))
    };
    if let Some(n) = crate::install_paths::executed_downloads(ctx)
        .iter()
        .chain(crate::install_paths::staged_files(ctx).iter())
        .find_map(|f| head_name(f))
    {
        return Some(n);
    }
    // 4. The file an install/copy puts into a bin directory: `install t "$BIN_DIR/zoxide"`.
    for dest in crate::install_paths::destinations(ctx, None) {
        let raw = dest.raw.as_str();
        let Some((dir, file)) = raw.rsplit_once('/') else {
            continue;
        };
        let bin_like = dir.ends_with("bin") || dir.ends_with("_DIR}") || dir.ends_with("_DIR");
        if file.contains('$') || !bin_like {
            continue;
        }
        if let Some(n) = accept(file) {
            return Some(n);
        }
    }
    // 5. Telling path segments (`registry.npmjs.org/pnpm`), then host names, of the URLs the
    //    script fetches or stores; URLs that only appear in messages come last.
    let trusted: Vec<&String> = fetched.iter().chain(&assigned).collect();
    if let Some(n) = trusted.iter().find_map(|u| from_url_path(u)) {
        return Some(n);
    }
    if let Some(n) = trusted.iter().find_map(|u| from_url_host(u)) {
        return Some(n);
    }
    if let Some(n) = mentioned.iter().find_map(|u| from_url_path(u)) {
        return Some(n);
    }
    // 6. A hidden directory the script creates under HOME: `DOWNLOAD_DIR="$HOME/.claude/…"`.
    crate::install_paths::destinations(ctx, None)
        .iter()
        .find_map(|d| {
            let folded_raw = crate::install_paths::fold_all(ctx, &d.raw);
            let rest = ["$HOME/.", "${HOME}/.", "~/."]
                .iter()
                .find_map(|p| folded_raw.strip_prefix(p))?;
            let dir = rest.split(['/', '$']).next()?;
            accept(dir)
        })
}

fn stem(segment: &str) -> String {
    let mut s = segment.to_string();
    for ext in [
        ".tar.gz", ".tgz", ".zip", ".sh", ".bash", ".zsh", ".txt", ".run", ".git", ".py",
    ] {
        if let Some(base) = s.strip_suffix(ext) {
            s = base.to_string();
            break;
        }
    }
    s
}

/// Generic when the whole word is, or when every `-`/`_`/`.` token is (`release-latest`).
fn is_generic(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    let word = |w: &str| w.is_empty() || w.len() == 1 || GENERIC.contains(&w);
    word(&l) || l.split(['-', '_', '.']).all(|t| word(t) || is_version(t))
}

/// `v1.2.3`, `1.2`, `2024-01`: a version or date, not a name.
fn is_version(s: &str) -> bool {
    let body = s.strip_prefix('v').unwrap_or(s);
    body.starts_with(|c: char| c.is_ascii_digit())
        && body
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | '_'))
}

/// A usable name: identifier-like, not generic, not a version, 2–40 chars.
fn accept(candidate: &str) -> Option<String> {
    let plain = candidate.trim();
    if plain.is_empty()
        || plain.len() > 40
        || plain.contains(['/', ' ', '$', '{', '}', '"', '\'', '`', ':', '@'])
        || !plain.starts_with(|c: char| c.is_ascii_alphabetic())
    {
        return None;
    }
    let mut n = sanitize(&stem(plain));
    // `rustup-init`, `deno_install`, `install-fff-mcp` name the program, not the stager.
    for suffix in [
        "-installer",
        "_installer",
        "-install",
        "_install",
        "-init",
        "-setup",
        "_setup",
    ] {
        if let Some(base) = n.strip_suffix(suffix)
            && base.len() >= 2
        {
            n = base.to_string();
            break;
        }
    }
    for prefix in ["install-", "install_", "setup-", "get-"] {
        if let Some(base) = n.strip_prefix(prefix)
            && base.len() >= 2
        {
            n = base.to_string();
            break;
        }
    }
    (!is_generic(&n) && !is_version(&n) && n.len() >= 2).then_some(n)
}

/// Lower-case `[a-z0-9._-]`, trimmed of leading/trailing punctuation.
pub fn sanitize(s: &str) -> String {
    let lowered: String = s
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    lowered.trim_matches(['.', '-', '_']).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    #[test]
    fn names_from_real_installer_urls() {
        let cases = [
            ("https://mise.run", "mise"),
            ("https://sh.rustup.rs", "rustup"),
            ("https://bun.sh/install", "bun"),
            ("https://deno.land/install.sh", "deno"),
            ("https://get.pnpm.io/install.sh", "pnpm"),
            ("https://astral.sh/uv/install.sh", "uv"),
            ("https://starship.rs/install.sh", "starship"),
            ("https://fnm.vercel.app/install", "fnm"),
            ("https://get.volta.sh", "volta"),
            ("https://nixos.org/nix/install", "nix"),
            ("https://install.python-poetry.org", "python-poetry"),
            ("https://claude.anthropic.ai", "claude"),
            (
                "https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh",
                "nvm",
            ),
            (
                "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh",
                "homebrew",
            ),
            (
                "https://api.github.com/repos/ajeetdsouza/zoxide/releases/latest",
                "zoxide",
            ),
            ("https://rye.astral.sh/get", "rye"),
            ("https://ollama.com/install.sh", "ollama"),
            ("https://example.com/v1.2.3/widget.sh?x=1", "widget"),
            ("https://dmtrkovalenko.dev/install-fff-mcp.sh", "fff-mcp"),
        ];
        for (url, want) in cases {
            assert_eq!(from_url(url).as_deref(), Some(want), "{url}");
        }
        assert_eq!(from_url("http://127.0.0.1:8080/install.sh"), None);
        assert_eq!(from_url("https://x.io/i"), None);
    }

    #[test]
    fn names_from_the_script_itself() {
        let ctx = parse("APP_NAME=\"zoxide\"\nINSTALL_DIR=/opt\ncurl -o x https://x.io/i").unwrap();
        assert_eq!(from_script(&ctx).as_deref(), Some("zoxide"));
        let ctx = parse("VERSION=1.2\nBIN_DIR=$HOME/.local/bin\nurl=https://github.com/cargo-bins/cargo-binstall/releases/latest/download/x.tgz\n").unwrap();
        assert_eq!(from_script(&ctx).as_deref(), Some("cargo-binstall"));
        let ctx = parse("install -m755 t \"$BIN_DIR/starship\"").unwrap();
        assert_eq!(from_script(&ctx).as_deref(), Some("starship"));
        let ctx = parse("curl -sL https://static.rust-lang.org/rustup/dist/x86/rustup-init -o f")
            .unwrap();
        assert_eq!(from_script(&ctx).as_deref(), Some("rustup"));
        let ctx = parse("curl -fsSL https://x.io/t.tgz | tar xz\necho done").unwrap();
        assert_eq!(from_script(&ctx), None);
        // Claude Code's stager: dynamic URL with a literal tail, and a versioned binary name.
        let ctx = parse(
            "DOWNLOAD_DIR=\"$HOME/.claude/downloads\"\nbinary_path=\"$DOWNLOAD_DIR/claude-$version-$platform\"\ncurl -fsSL -o \"$binary_path\" \"$BASE/$version/$platform/claude\"\nchmod +x \"$binary_path\"\n\"$binary_path\" install",
        )
        .unwrap();
        assert_eq!(from_script(&ctx).as_deref(), Some("claude"));
        let ctx =
            parse("D=\"$HOME/.widget/dl\"\nmkdir -p \"$D\"\ncurl -o \"$D/$f\" \"$U/$f\"").unwrap();
        assert_eq!(from_script(&ctx).as_deref(), Some("widget"));
        let ctx = parse("NAME=\"$(basename $0)\"\ncurl https://x.io/i").unwrap();
        assert_eq!(from_script(&ctx), None, "computed values are not names");
    }

    #[test]
    fn names_from_binaries_prefer_the_bin_dir() {
        let bins: BTreeSet<PathBuf> = ["/home/t/.local/bin"].map(PathBuf::from).into();
        let one = [PathBuf::from("/home/t/.local/bin/mise")];
        assert_eq!(from_binaries(&one, &bins).as_deref(), Some("mise"));
        let mixed = [
            PathBuf::from("/home/t/.local/bin/uv"),
            PathBuf::from("/home/t/.uv/libexec/helper"),
        ];
        assert_eq!(from_binaries(&mixed, &bins).as_deref(), Some("uv"));
        let two = [
            PathBuf::from("/home/t/.local/bin/uv"),
            PathBuf::from("/home/t/.local/bin/uvx"),
        ];
        assert_eq!(from_binaries(&two, &bins), None);
        let elsewhere = [PathBuf::from("/opt/widget/bin/widget")];
        assert_eq!(from_binaries(&elsewhere, &bins).as_deref(), Some("widget"));
    }

    #[test]
    fn derive_order_and_no_fallback() {
        let bins = BTreeSet::new();
        let ctx = parse("APP=zoxide").unwrap();
        let none: &[String] = &[];
        let url = Some("https://mise.run");
        let d = |o: Option<&str>, b: &[PathBuf], u: Option<&str>, c: Option<&Ctx>, a: &[String]| {
            derive(o, b, &bins, u, c, a)
        };
        assert_eq!(
            d(Some("My Tool"), &[], url, Some(&ctx), none).as_deref(),
            Some("my-tool")
        );
        let one = [PathBuf::from("/x/bin/demo")];
        assert_eq!(
            d(None, &one, url, Some(&ctx), none).as_deref(),
            Some("demo")
        );
        assert_eq!(d(None, &[], url, Some(&ctx), none).as_deref(), Some("mise"));
        assert_eq!(
            d(None, &[], None, Some(&ctx), none).as_deref(),
            Some("zoxide")
        );
        let args = ["--git".to_string(), "cantino/mcfly".to_string()];
        assert_eq!(d(None, &[], None, None, &args).as_deref(), Some("mcfly"));
        assert_eq!(d(None, &[], None, None, none), None);
    }
}

#[cfg(test)]
mod fixture_names {
    /// Every benign fixture is analyzed without an origin URL, so the script alone must name it.
    #[test]
    fn benign_installers_name_themselves() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/benign");
        let expected = [
            ("bun.sh", "bun"),
            ("chezmoi.sh", "chezmoi"),
            ("deno.sh", "deno"),
            ("fnm.sh", "fnm"),
            ("homebrew.sh", "brew"),
            ("mise.sh", "mise"),
            ("nix.sh", "nix"),
            ("nvm.sh", "nvm"),
            ("pnpm.sh", "pnpm"),
            ("rustup.sh", "rustup"),
            ("rye.sh", "rye"),
            ("starship.sh", "starship"),
            ("uv.sh", "uv"),
            ("volta.sh", "volta"),
            ("zoxide.sh", "zoxide"),
        ];
        for (file, want) in expected {
            let src = std::fs::read_to_string(dir.join(file)).unwrap();
            let ctx = crate::parser::parse(&src).unwrap();
            assert_eq!(super::from_script(&ctx).as_deref(), Some(want), "{file}");
        }
        // mcfly ships a generic installer: the project arrives as `--git owner/repo`.
        let src = std::fs::read_to_string(dir.join("mcfly.sh")).unwrap();
        let ctx = crate::parser::parse(&src).unwrap();
        assert_eq!(super::from_script(&ctx), None);
        assert!(super::takes_arguments(&ctx));
    }
}
