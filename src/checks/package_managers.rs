//! Red/Yellow: the installer reaches into another package ecosystem and pulls code from it,
//! multiplying the trust surface. Red when the source is unpinned, a URL/git ref, a foreign
//! registry, or integrity/TLS is disabled; yellow for a plain global install onto PATH.

use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::Command;
use crate::register_flag;

fn base(name: &str) -> &str {
    crate::config::base_name(name)
}

/// A package spec that is inherently unaudited: a URL, VCS ref, tarball, or local path.
fn risky_spec(s: &str) -> bool {
    s.starts_with("git+")
        || s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with("git@")
        || s.starts_with("file:")
        || s.ends_with(".tar.gz")
        || std::path::Path::new(s)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("tgz") || ext.eq_ignore_ascii_case("whl"))
}

/// A version ref that changes over time (`pkg@latest`, `mod@master`).
fn mutable_ref(s: &str) -> bool {
    matches!(
        s.rsplit(['@', '#']).next().unwrap_or(""),
        "latest" | "master" | "main" | "HEAD" | "next" | "canary" | "edge"
    )
}

struct Finding {
    what: String,
    red: bool,
}

// One arm per package manager; splitting it up would only scatter the table.
#[allow(clippy::too_many_lines)]
fn examine(c: &Command) -> Option<Finding> {
    let name = base(&c.name);
    let args: Vec<&str> = c.arg_texts().collect();
    let has = |f: &str| args.contains(&f);
    let operands = || args.iter().copied().filter(|a| !a.starts_with('-'));

    match name {
        "npm" | "pnpm" | "yarn" | "bun" => {
            let global = has("-g") || has("--global") || args.first() == Some(&"global");
            let installs = args
                .iter()
                .any(|a| matches!(*a, "install" | "i" | "add" | "global"));
            let dlx = args.iter().any(|a| matches!(*a, "dlx" | "create"));
            if has("--registry") && args.iter().any(|a| a.starts_with("http://")) {
                return Some(Finding {
                    what: format!("{name} install from a plaintext registry"),
                    red: true,
                });
            }
            let specs: Vec<&str> = operands()
                .filter(|a| !matches!(*a, "install" | "i" | "add" | "global" | "dlx" | "create"))
                .collect();
            if dlx {
                return Some(Finding {
                    what: format!("`{name}` runs a package fetched on the fly (dlx/create)"),
                    red: true,
                });
            }
            if installs && (global || specs.iter().any(|s| risky_spec(s) || mutable_ref(s))) {
                let red = specs.iter().any(|s| risky_spec(s) || mutable_ref(s));
                return Some(Finding {
                    what: format!("global {name} install: {}", specs.join(" ").trim()),
                    red: red || specs.is_empty() && global,
                });
            }
            None
        }
        "npx" | "bunx" | "pnpx" => Some(Finding {
            what: format!("`{name}` downloads and runs a package immediately"),
            red: true,
        }),
        "pip" | "pip3" | "pipx" | "uv" => {
            let installs = args.iter().any(|a| matches!(*a, "install"))
                || (name == "uv" && has("tool") && has("install"));
            if !installs {
                return None;
            }
            if args.iter().any(|a| a.starts_with("--trusted-host")) {
                return Some(Finding {
                    what: format!("{name} install with --trusted-host (TLS check off)"),
                    red: true,
                });
            }
            if args.iter().any(|a| {
                a.starts_with("--index-url")
                    || a.starts_with("--extra-index-url")
                    || a.starts_with("-i")
            }) {
                return Some(Finding {
                    what: format!("{name} install from a custom index (dependency-confusion risk)"),
                    red: true,
                });
            }
            let specs: Vec<&str> = operands()
                .filter(|a| !matches!(*a, "install" | "tool"))
                .collect();
            if specs.iter().any(|s| risky_spec(s)) {
                return Some(Finding {
                    what: format!(
                        "{name} install from a URL/VCS/local path: {}",
                        specs.join(" ")
                    ),
                    red: true,
                });
            }
            None
        }
        "cargo" => {
            if has("install") && args.iter().any(|a| a.starts_with("--git")) {
                return Some(Finding {
                    what: "cargo install --git (unaudited, no crates.io review)".into(),
                    red: true,
                });
            }
            None
        }
        "go" => {
            if has("install") && args.iter().any(|a| mutable_ref(a) && a.contains('@')) {
                let spec = args.iter().find(|a| mutable_ref(a)).copied().unwrap_or("");
                return Some(Finding {
                    what: format!("go install of a moving ref (`{spec}`)"),
                    red: true,
                });
            }
            None
        }
        "gem" => (has("install")
            && args
                .iter()
                .any(|a| a.starts_with("--source") || risky_spec(a)))
        .then(|| Finding {
            what: "gem install from a custom source".into(),
            red: true,
        }),
        "brew" => {
            if args.first() == Some(&"tap") && args.iter().any(|a| a.contains("://")) {
                return Some(Finding {
                    what: "brew tap from an arbitrary git URL".into(),
                    red: true,
                });
            }
            if has("--no-quarantine") {
                return Some(Finding {
                    what: "brew cask install with --no-quarantine (Gatekeeper off)".into(),
                    red: true,
                });
            }
            None
        }
        "code" | "codium" | "cursor" => (has("--install-extension")).then(|| Finding {
            what: format!("{name} installs an editor extension (runs on every launch)"),
            red: true,
        }),
        "gh" => {
            (args.first() == Some(&"extension") && args.get(1) == Some(&"install")).then(|| {
                Finding {
                    what: "gh extension install (arbitrary code on every gh run)".into(),
                    red: true,
                }
            })
        }
        "docker" | "podman" => {
            if args.first() == Some(&"run") || args.first() == Some(&"create") {
                if has("--privileged") {
                    return Some(Finding {
                        what: format!("{name} run --privileged (full host access)"),
                        red: true,
                    });
                }
                if args
                    .iter()
                    .any(|a| *a == "--net=host" || *a == "--pid=host")
                {
                    return Some(Finding {
                        what: format!("{name} run shares the host network/PID namespace"),
                        red: true,
                    });
                }
                if args.windows(2).any(|w| {
                    (w[0] == "-v" || w[0] == "--volume")
                        && (w[1].starts_with("/:") || w[1].starts_with("/:/") || w[1] == "/:/host")
                }) || args
                    .iter()
                    .any(|a| a.starts_with("-v/:") || a.contains("/var/run/docker.sock"))
                {
                    return Some(Finding {
                        what: format!("{name} run mounts the host root or docker socket"),
                        red: true,
                    });
                }
            }
            None
        }
        _ => None,
    }
}

pub struct PackageManagers {
    reported: bool,
}

impl Flag for PackageManagers {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if self.reported {
            return Verdict::Ignore;
        }
        let Some(f) = examine(c) else {
            return Verdict::Ignore;
        };
        self.reported = true;
        let detail = Detail::new(
            format!("pulls code from another package ecosystem: {}", f.what),
            "Whatever that package or image contains runs with your permissions, and its own install scripts are never reviewed here.",
        )
        .fix("Pin an exact version from the official registry, or install it yourself after review.")
        .at(c.span.clone());
        if f.red {
            Verdict::Red(detail)
        } else {
            Verdict::Yellow(detail)
        }
    }
}

register_flag! {
    id: "package_managers",
    kind: Red,
    category: Remote,
    description: "Invokes npm/npx/pip/cargo/go/gem/brew/docker/editor extensions; red on URL/git/mutable/foreign-registry/--privileged",
    config: NoConfig,
    build: |_cfg, _shared| PackageManagers { reported: false },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;
    use crate::model::FlagKind;

    #[test]
    fn flags_risky_ecosystem_pulls() {
        assert_eq!(
            kind("package_managers", "npx some-tool"),
            Some(FlagKind::Red)
        );
        assert_eq!(
            kind("package_managers", "npm install -g git+https://x/y"),
            Some(FlagKind::Red)
        );
        assert_eq!(
            kind("package_managers", "pip install --trusted-host x.io pkg"),
            Some(FlagKind::Red)
        );
        assert_eq!(
            kind(
                "package_managers",
                "pip3 install --index-url http://x/simple pkg"
            ),
            Some(FlagKind::Red)
        );
        assert_eq!(
            kind("package_managers", "cargo install --git https://x/y"),
            Some(FlagKind::Red)
        );
        assert_eq!(
            kind("package_managers", "go install example.com/x@latest"),
            Some(FlagKind::Red)
        );
        assert_eq!(
            kind("package_managers", "docker run --privileged img"),
            Some(FlagKind::Red)
        );
        assert_eq!(
            kind("package_managers", "docker run -v /:/host img"),
            Some(FlagKind::Red)
        );
        assert_eq!(
            kind("package_managers", "brew install --cask x --no-quarantine"),
            Some(FlagKind::Red)
        );
        assert_eq!(
            kind("package_managers", "gh extension install owner/repo"),
            Some(FlagKind::Red)
        );
    }

    #[test]
    fn plain_global_install_is_yellow_and_pinned_local_is_clean() {
        assert_eq!(
            kind("package_managers", "npm install -g typescript"),
            Some(FlagKind::Yellow)
        );
        assert!(!fires("package_managers", "pip install requests==2.31.0"));
        assert!(!fires(
            "package_managers",
            "cargo install ripgrep --version 14.1.0"
        ));
        assert!(!fires("package_managers", "docker run -v ./data:/data img"));
        assert!(!fires("package_managers", "npm ci"));
    }
}
