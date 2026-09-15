use crate::analysis::Flag;
use crate::config::Recommended;
use crate::model::{Detail, Verdict};
use crate::parser::{Assignment, Command};
use crate::register_flag;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct InstallDirCfg {
    pub dirs: Vec<String>,
}

impl Default for InstallDirCfg {
    fn default() -> Self {
        Self::recommended()
    }
}

impl Recommended for InstallDirCfg {
    fn recommended() -> Self {
        Self {
            dirs: [
                "/usr/local/bin",
                "~/.local/bin",
                "$HOME/.local/bin",
                "${HOME}/.local/bin",
            ]
            .map(String::from)
            .to_vec(),
        }
    }
}

const INSTALLERS: &[&str] = &["install", "cp", "mv", "ln", "mkdir"];

pub struct InstallDir {
    dirs: Vec<String>,
    reported: bool,
}

impl InstallDir {
    /// `dir` appears as a whole path component, also inside `${VAR:-dir}` defaults.
    fn matches(&self, text: &str) -> bool {
        self.dirs.iter().any(|d| {
            text.match_indices(d.as_str()).any(|(i, _)| {
                let before = text[..i].chars().next_back();
                let after = text[i + d.len()..].chars().next();
                !matches!(before, Some(c) if c.is_alphanumeric() || "_.~/".contains(c))
                    && matches!(after, None | Some('/' | '}' | '"' | '\'' | ' ' | ':'))
            })
        })
    }

    fn report(&mut self, span: crate::model::Span, what: &str) -> Verdict {
        if self.reported {
            return Verdict::Ignore;
        }
        self.reported = true;
        Verdict::Green(
            Detail::new(
                format!("installs into a conventional directory: {what}"),
                "Files land in a standard binary directory instead of being scattered or hidden.",
            )
            .at(span),
        )
    }
}

impl Flag for InstallDir {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if !INSTALLERS.contains(&c.name.as_str()) {
            return Verdict::Ignore;
        }
        match c.args.iter().find(|w| self.matches(&w.text)) {
            Some(w) => {
                let text = w.text.clone();
                self.report(w.span.clone(), &text)
            }
            None => Verdict::Ignore,
        }
    }

    fn visit_assignment(&mut self, a: &Assignment) -> Verdict {
        let looks_like_dir_var =
            a.name.ends_with("DIR") || a.name.ends_with("PREFIX") || a.name.ends_with("PATH");
        if looks_like_dir_var && self.matches(&a.value.text) {
            let text = a.value.text.clone();
            return self.report(a.span.clone(), &text);
        }
        Verdict::Ignore
    }
}

register_flag! {
    id: "install_dir",
    kind: Green,
    category: Path,
    description: "Installs into /usr/local/bin or ~/.local/bin",
    config: InstallDirCfg,
    build: |cfg, _shared| InstallDir { dirs: cfg.dirs, reported: false },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn recognizes_conventional_install_targets() {
        assert!(fires(
            "install_dir",
            "install -m755 tool /usr/local/bin/tool"
        ));
        assert!(fires(
            "install_dir",
            "BIN_DIR=\"$HOME/.local/bin\"\nmkdir -p \"$BIN_DIR\""
        ));
        assert!(!fires("install_dir", "cp tool /opt/tool/bin/tool"));
        assert!(fires("install_dir", "BIN_DIR=${BIN_DIR:-/usr/local/bin}"));
        assert!(fires(
            "install_dir",
            "INSTALL_PATH=\"${MISE_INSTALL_PATH:-$HOME/.local/bin/mise}\""
        ));
        assert_eq!(
            titles(
                "install_dir",
                "mkdir -p /usr/local/bin\ncp a /usr/local/bin/a"
            )
            .len(),
            1
        );
    }
}
