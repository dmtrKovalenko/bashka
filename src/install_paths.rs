use crate::chain::resolve;
use crate::parser::{Command, Ctx};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Commands whose arguments name where files land.
const INSTALLERS: &[&str] = &[
    "install", "cp", "mv", "ln", "mkdir", "tar", "unzip", "git", "chmod", "curl", "wget", "tee",
];

/// Identifier-like commands that take a command name as an argument *without* running it.
const NOT_WRAPPERS: &[&str] = &[
    "echo",
    "printf",
    "log",
    "info",
    "warn",
    "warning",
    "err",
    "error",
    "die",
    "abort",
    "say",
    "need_cmd",
    "check_cmd",
    "has",
    "have",
    "hash",
    "type",
    "which",
    "test",
    "require",
    "requires",
    "usage",
    "help",
    "debug",
    "fatal",
    "msg",
    "note",
    "ok",
    "fail",
    "success",
    "step",
    "print",
];

/// Anything with these fragments is scratch space, not an install location.
const TEMP_MARKERS: &[&str] = &[
    "mktemp", "/tmp", "TMP", "TEMP", "tmp_", "_tmp", ".tmp", "/dev/",
];

#[derive(Debug, Clone)]
pub struct Destination {
    /// The argument as written (after quote stripping): `"$INSTALL_DIR/mise"`.
    pub raw: String,
    /// The path with every statically known variable substituted and `~`/`$HOME` expanded.
    /// `None` when something remains dynamic; then `prefix` may still hold a usable directory.
    pub path: Option<PathBuf>,
    /// For dynamic destinations: the longest literal leading directory (`$HOME/.local/bin/$NAME`
    /// -> `~/.local/bin`), if there is one.
    pub prefix: Option<PathBuf>,
}

impl Destination {
    /// The directory worth watching for this destination, if any.
    pub fn watch_root(&self) -> Option<&Path> {
        self.path.as_deref().or(self.prefix.as_deref())
    }
}

/// Every place the script visibly writes installed files to, in source order. `home` is used
/// to expand `~` and `$HOME`; without it those stay symbolic.
pub fn destinations(ctx: &Ctx, home: Option<&Path>) -> Vec<Destination> {
    let vars = deep_vars(ctx);
    let mut out = Vec::new();
    for c in ctx.commands() {
        for word in targets(c) {
            let folded = fold_deep(&word.text, &vars, 0);
            if is_temp(&word.text) || is_temp(&folded) || folded.is_empty() {
                continue;
            }
            let (path, prefix) = concretize(&folded, home);
            out.push(Destination {
                raw: word.text.clone(),
                path,
                prefix,
            });
        }
    }
    out
}

fn is_temp(text: &str) -> bool {
    TEMP_MARKERS.iter().any(|m| text.contains(m))
}

/// Peels wrapper functions: `ensure try_sudo mkdir -p x` is seen as `mkdir -p x`. Any run of
/// plain identifier-like words (shell functions such as `ensure`, `run`, `try_sudo`) before a
/// known installer command counts, except for commands that merely *mention* another command.
fn unwrap(c: &Command) -> (&str, &[crate::parser::Word]) {
    let mut name = c.name.as_str();
    let mut args = c.args.as_slice();
    loop {
        let base = name.rsplit('/').next().unwrap_or(name);
        if INSTALLERS.contains(&base) || !is_identifier(name) || NOT_WRAPPERS.contains(&base) {
            break;
        }
        match args.split_first() {
            Some((first, rest)) if is_identifier(&first.text) => {
                name = first.text.as_str();
                args = rest;
            }
            _ => break,
        }
    }
    (name, args)
}

fn is_identifier(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Files the script downloads or marks executable, as written (temp paths included).
pub fn staged_files(ctx: &Ctx) -> Vec<String> {
    ctx.commands()
        .flat_map(|c| {
            let (name, args) = unwrap(c);
            match name.rsplit('/').next().unwrap_or(name) {
                "chmod" => operands(args, &[]).into_iter().skip(1).collect::<Vec<_>>(),
                "curl" => option_value(args, &["-o", "--output"])
                    .into_iter()
                    .collect(),
                "wget" => option_value(args, &["-O", "--output-document"])
                    .into_iter()
                    .collect(),
                _ => Vec::new(),
            }
        })
        .map(|w| w.text.clone())
        .collect()
}

/// Shells and interpreters that run whatever is fed to them.
const RUNNERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "python", "python2", "python3", "perl",
    "ruby", "node", "deno", "bun", "php", "pwsh", "eval", "exec", "source", ".",
];

fn is_runner(name: &str) -> bool {
    let base = name.rsplit('/').next().unwrap_or(name);
    RUNNERS.contains(&base) || base.starts_with("python")
}

/// Files the script obtains and then executes: downloaded or chmod'ed paths that later appear
/// as a command (`chmod +x "$f"; "$f" self install`), extracted `./binary` names, and files handed
/// to `sh`/`exec`. Empty when the script never runs what it downloaded.
pub fn executed_downloads(ctx: &Ctx) -> Vec<String> {
    let staged = staged_files(ctx);
    let runs_staged = |w: &str| staged.iter().any(|s| s == w);
    let mut out: Vec<String> = Vec::new();
    for c in ctx.commands() {
        let name = c.name.as_str();
        if runs_staged(name) || name.starts_with("./") || name.starts_with("../") {
            out.push(name.to_string());
            continue;
        }
        if !matches!(
            name,
            "sh" | "bash" | "zsh" | "dash" | "exec" | "source" | "."
        ) {
            continue;
        }
        // `sh "$f"`, `exec ./x`
        if let Some(a) = c.args.iter().find(|a| !a.text.starts_with('-'))
            && (runs_staged(&a.text) || a.text.starts_with("./"))
        {
            out.push(a.text.clone());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The script feeds fetched or computed content to a shell or interpreter (`echo "$s" | sh`,
/// `curl … | "$PYTHON" -`, `eval "$code"`), so what runs is decided at run time.
pub fn pipes_into_interpreter(ctx: &Ctx) -> bool {
    let commands = ctx.commands().any(|c| {
        let name = c.name.as_str();
        if !is_runner(name) {
            return false;
        }
        let first = c
            .args
            .iter()
            .find(|a| !a.text.starts_with('-') || a.text == "-");
        match (name, first) {
            ("eval" | "exec" | "source" | ".", Some(_)) => true,
            (_, Some(a)) => a.text == "-" || a.text.contains('$'),
            (_, None) => c.arg_texts().any(|a| a == "-s" || a == "-c"),
        }
    });
    commands
        || ctx.nodes.iter().any(|n| match n {
            crate::parser::Node::Pipeline(p) => p
                .stages
                .last()
                .is_some_and(|last| is_runner(&last.name) || last.name.contains('$')),
            _ => false,
        })
}

/// Either form of hand-off: the install location is decided elsewhere.
pub fn delegates_to_download(ctx: &Ctx) -> bool {
    !executed_downloads(ctx).is_empty() || pipes_into_interpreter(ctx)
}

/// The arguments of `c` that name a destination.
fn targets(c: &Command) -> Vec<&crate::parser::Word> {
    let (name, args) = unwrap(c);
    let name = name.rsplit('/').next().unwrap_or(name);
    match name {
        "install" => {
            if let Some(t) = option_value(args, &["-t", "--target-directory"]) {
                return vec![t];
            }
            let ops = operands(args, &["-m", "-o", "-g", "--mode", "--owner", "--group"]);
            if args
                .iter()
                .any(|a| a.text == "-d" || a.text == "--directory")
            {
                return ops;
            }
            last_of_at_least(ops, 2)
        }
        "cp" | "mv" | "ln" => {
            if let Some(t) = option_value(args, &["-t", "--target-directory"]) {
                return vec![t];
            }
            last_of_at_least(operands(args, &[]), 2)
        }
        "mkdir" => operands(args, &["-m", "--mode"]),
        "tar" => {
            let mut out = Vec::new();
            let mut i = 0;
            while i < args.len() {
                let a = args[i].text.as_str();
                if a == "-C" || a == "--directory" || a == "--one-top-level" {
                    if let Some(next) = args.get(i + 1) {
                        out.push(next);
                    }
                    i += 2;
                    continue;
                }
                if a.starts_with("--directory=") || a.starts_with("--one-top-level=") {
                    out.push(&args[i]);
                } else if a.ends_with('C') && !a.starts_with("--") && (a.starts_with('-') || i == 0)
                {
                    // Bundled short options: `-xzC dir`, or old-style `tar xzC dir`.
                    if let Some(next) = args.get(i + 1) {
                        out.push(next);
                    }
                    i += 2;
                    continue;
                }
                i += 1;
            }
            out
        }
        "unzip" => option_value(args, &["-d"]).into_iter().collect(),
        "git" => {
            // `git [-c k=v]… clone [opts] url [dir]`
            let Some(at) = args.iter().position(|a| a.text == "clone") else {
                return Vec::new();
            };
            let ops = operands(
                &args[at + 1..],
                &[
                    "--depth",
                    "-b",
                    "--branch",
                    "-o",
                    "--origin",
                    "-c",
                    "--config",
                    "-j",
                    "--jobs",
                    "--reference",
                    "--separate-git-dir",
                    "--template",
                ],
            );
            last_of_at_least(ops, 2)
        }
        "chmod" => operands(args, &[]).into_iter().skip(1).collect(),
        "curl" => option_value(args, &["-o", "--output"])
            .into_iter()
            .filter(|w| w.text != "-")
            .collect(),
        "wget" => option_value(args, &["-O", "--output-document"])
            .into_iter()
            .filter(|w| w.text != "-")
            .collect(),
        "tee" => operands(args, &[]),
        _ => Vec::new(),
    }
}

/// Non-option arguments, skipping the value of every option in `with_value` (also `--opt=value`).
fn operands<'a>(
    args: &'a [crate::parser::Word],
    with_value: &[&str],
) -> Vec<&'a crate::parser::Word> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].text.as_str();
        if with_value.contains(&a) {
            i += 2;
            continue;
        }
        if a == "--" {
            out.extend(args[i + 1..].iter());
            break;
        }
        if a.starts_with('-') && a.len() > 1 {
            i += 1;
            continue;
        }
        out.push(&args[i]);
        i += 1;
    }
    out
}

fn option_value<'a>(
    args: &'a [crate::parser::Word],
    names: &[&str],
) -> Option<&'a crate::parser::Word> {
    args.iter().enumerate().find_map(|(i, a)| {
        if names.contains(&a.text.as_str()) {
            args.get(i + 1)
        } else if names
            .iter()
            .any(|n| n.starts_with("--") && a.text.starts_with(&format!("{n}=")))
        {
            Some(a)
        } else {
            None
        }
    })
}

fn last_of_at_least(ops: Vec<&crate::parser::Word>, n: usize) -> Vec<&crate::parser::Word> {
    if ops.len() >= n {
        ops.last().copied().into_iter().collect()
    } else {
        Vec::new()
    }
}

/// Every variable assigned exactly once, with its raw value text (may itself contain `$`).
fn deep_vars(ctx: &Ctx) -> HashMap<&str, Option<String>> {
    let mut vars: HashMap<&str, Option<String>> = HashMap::new();
    for a in ctx.assignments() {
        vars.entry(a.name.as_str())
            .and_modify(|v| *v = None)
            .or_insert(Some(a.value.text.clone()));
    }
    vars
}

/// `text` with every single-assignment variable substituted as far as it goes
/// (`$binary_path` -> `$HOME/.claude/downloads/claude-$version-$platform`).
pub fn fold_all(ctx: &Ctx, text: &str) -> String {
    fold_deep(text, &deep_vars(ctx), 0)
}

/// Substitutes known variables repeatedly (`$_file` -> `${_dir}/x` -> `$(mktemp)/x`), bounded.
fn fold_deep(text: &str, vars: &HashMap<&str, Option<String>>, depth: usize) -> String {
    let folded = resolve::fold(text, vars);
    if depth >= 6 || folded == text || !folded.contains('$') {
        return folded;
    }
    fold_deep(&folded, vars, depth + 1)
}

/// Expands `~` and `$HOME`, then splits into a fully literal path or a literal prefix directory.
fn concretize(folded: &str, home: Option<&Path>) -> (Option<PathBuf>, Option<PathBuf>) {
    let home = home
        .map(|h| h.display().to_string())
        .filter(|h| !h.is_empty());
    let mut text = folded.to_string();
    if let Some(home) = &home {
        for pat in ["${HOME}", "$HOME"] {
            text = text.replace(pat, home);
        }
        if text == "~" || text.starts_with("~/") {
            text = format!("{home}{}", &text[1..]);
        }
    }
    if !text.contains('$') && !text.contains('`') {
        return (Some(PathBuf::from(text)), None);
    }
    let literal = &text[..text.find(['$', '`']).unwrap_or(0)];
    let dir = match literal.rfind('/') {
        Some(0) => "/",
        Some(i) => &literal[..i],
        None => return (None, None),
    };
    // A bare `/` or the home directory itself is too broad to be a useful prefix.
    let too_broad = dir == "/" || home.as_deref() == Some(dir);
    if too_broad || !dir.starts_with('/') {
        return (None, None);
    }
    (None, Some(PathBuf::from(dir)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    fn raws(src: &str) -> Vec<String> {
        destinations(&parse(src).unwrap(), None)
            .into_iter()
            .map(|d| d.raw)
            .collect()
    }

    #[test]
    fn finds_install_style_destinations() {
        assert_eq!(
            raws("install -m 755 tool /usr/local/bin/tool"),
            ["/usr/local/bin/tool"]
        );
        assert_eq!(raws("cp -r dist \"$HOME/.foo\""), ["$HOME/.foo"]);
        assert_eq!(
            raws("mkdir -p ~/.local/bin /opt/x"),
            ["~/.local/bin", "/opt/x"]
        );
        assert_eq!(raws("tar -xzf a.tgz -C /opt/tool"), ["/opt/tool"]);
        assert_eq!(raws("tar xzC /opt/tool -f a.tgz"), ["/opt/tool"]);
        assert_eq!(raws("unzip -q a.zip -d ~/.x"), ["~/.x"]);
        assert_eq!(
            raws("command git clone -o origin --depth=1 https://x/y.git \"${INSTALL_DIR}\""),
            ["${INSTALL_DIR}"]
        );
        assert_eq!(
            raws("git -c advice.detachedHead=0 clone --branch \"$3\" --depth 1 \"$1\" \"$2\""),
            ["$2"]
        );
        assert_eq!(raws("chmod +x ~/.local/bin/a ~/.local/bin/b").len(), 2);
        assert_eq!(
            raws("curl -fsSL https://x/a -o ~/.local/bin/a"),
            ["~/.local/bin/a"]
        );
        assert_eq!(
            raws("ensure mkdir -p \"$HOME/.cargo/bin\""),
            ["$HOME/.cargo/bin"]
        );
        assert_eq!(
            raws("ensure try_sudo mkdir -p -- \"${_ZOXIDE_BIN_DIR}\""),
            ["${_ZOXIDE_BIN_DIR}"]
        );
        assert!(raws("echo mkdir -p /opt/x").is_empty());
        assert!(raws("need_cmd chmod\nneed_cmd mkdir").is_empty());
        assert!(raws("cp only-one-arg").is_empty());
        assert!(raws("curl -o - https://x").is_empty());
    }

    #[test]
    fn skips_temporary_locations() {
        assert!(raws("TMP=$(mktemp -d)\ncurl -o \"$TMP/a\" https://x").is_empty());
        assert!(
            raws(
                "_dir=\"$(ensure mktemp -d)\"\n_file=\"${_dir}/rustup-init\"\nchmod u+x \"$_file\""
            )
            .is_empty()
        );
        assert!(raws("mkdir -p /tmp/x").is_empty());
    }

    #[test]
    fn detects_hand_off_to_a_downloaded_program() {
        let ctx =
            parse("F=$(mktemp)\ncurl -o \"$F\" https://x\nchmod +x \"$F\"\n\"$F\" self install")
                .unwrap();
        assert!(delegates_to_download(&ctx));
        let ctx = parse("curl -o t https://x\nchmod +x t\nsh t --yes").unwrap();
        assert!(delegates_to_download(&ctx));
        let ctx = parse("curl -o t https://x\nchmod +x t\ninstall t /usr/local/bin/t").unwrap();
        assert!(!delegates_to_download(&ctx));
        // Extracted binary, variable-fed shell, interpreter named at run time.
        assert!(delegates_to_download(
            &parse("curl -sL $u | tar xz\n./tool --self-install").unwrap()
        ));
        assert!(delegates_to_download(
            &parse("s=$(curl -sL $u)\necho \"$s\" | sh").unwrap()
        ));
        assert!(delegates_to_download(
            &parse("curl -sSf \"$U\" | \"$PYTHON_EXECUTABLE\" - \"$@\"").unwrap()
        ));
        assert!(delegates_to_download(
            &parse("eval \"$(curl -sL $u)\"").unwrap()
        ));
        assert!(!delegates_to_download(
            &parse("curl -sL $u | tar xz\necho done").unwrap()
        ));
    }

    #[test]
    fn concretizes_paths_through_variables() {
        let home = Some(Path::new("/home/t"));
        let d = destinations(
            &parse("BIN_DIR=\"$HOME/.local/bin\"\ninstall t \"$BIN_DIR/t\"").unwrap(),
            home,
        );
        assert_eq!(
            d[0].path.as_deref(),
            Some(Path::new("/home/t/.local/bin/t"))
        );
        let d = destinations(
            &parse("install t \"$HOME/.local/bin/$NAME\"").unwrap(),
            home,
        );
        assert_eq!(d[0].path, None);
        assert_eq!(
            d[0].prefix.as_deref(),
            Some(Path::new("/home/t/.local/bin"))
        );
        let d = destinations(&parse("install t \"$DEST/t\"").unwrap(), home);
        assert_eq!(d[0].watch_root(), None);
        let d = destinations(
            &parse("D=\"${X:-/opt/tool}\"\nmkdir -p \"$D\"").unwrap(),
            home,
        );
        assert_eq!(d[0].path.as_deref(), Some(Path::new("/opt/tool")));
        let d = destinations(&parse("mkdir -p ~/.x").unwrap(), home);
        assert_eq!(d[0].path.as_deref(), Some(Path::new("/home/t/.x")));
    }
}
