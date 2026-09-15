use crate::analysis::Flag;
use crate::config::Recommended;
use crate::model::{Detail, Verdict};
use crate::parser::Command;
use crate::register_flag;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SensitiveWriteCfg {
    /// Flag edits of ~/.bashrc, ~/.zshrc, ~/.profile and friends (installers commonly do this).
    pub shell_rc: bool,
    /// Additional paths (`~/` is matched against `$HOME/` too).
    pub additional_paths: Vec<String>,
}

impl Default for SensitiveWriteCfg {
    fn default() -> Self {
        Self {
            shell_rc: true,
            additional_paths: Vec::new(),
        }
    }
}

impl Recommended for SensitiveWriteCfg {
    fn recommended() -> Self {
        Self::default()
    }
}

const SHELL_RC: &[&str] = &[
    "~/.bashrc",
    "~/.bash_profile",
    "~/.zshrc",
    "~/.zprofile",
    "~/.profile",
    "~/.config/fish/config.fish",
];
const ALWAYS: &[&str] = &[
    "~/.ssh/authorized_keys",
    "~/.ssh/config",
    "~/.ssh/",
    "/etc/sudoers",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/cron",
    "/var/spool/cron",
    "/etc/ld.so.preload",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/environment",
];
/// Commands whose arguments name files they modify.
const WRITERS: &[&str] = &[
    "tee", "sed", "cp", "mv", "install", "ln", "truncate", "dd", "perl",
];

pub struct SensitiveWrite {
    paths: Vec<String>,
}

fn normalize(path: &str) -> String {
    path.trim_matches(['"', '\''])
        .replacen("${HOME}/", "~/", 1)
        .replacen("$HOME/", "~/", 1)
}

impl SensitiveWrite {
    fn new(cfg: SensitiveWriteCfg) -> Self {
        let mut paths: Vec<String> = ALWAYS.iter().map(|s| s.to_string()).collect();
        if cfg.shell_rc {
            paths.extend(SHELL_RC.iter().map(|s| s.to_string()));
        }
        paths.extend(cfg.additional_paths);
        Self { paths }
    }

    fn sensitive(&self, raw: &str) -> Option<String> {
        let p = normalize(raw);
        self.paths
            .iter()
            .any(|s| {
                p == *s
                    || (s.ends_with('/') && p.starts_with(s.as_str()))
                    || p.starts_with(&format!("{s}."))
            })
            .then_some(p)
    }
}

impl Flag for SensitiveWrite {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if c.name == "crontab" && !c.has_arg("-l") {
            return Verdict::Red(
                Detail::new(
                    "installs a crontab",
                    "Schedules code to keep running after the installer exits.",
                )
                .at(c.span.clone()),
            );
        }
        let via_redirect = c
            .redirects
            .iter()
            .find_map(|w| self.sensitive(&w.text).map(|p| (p, "redirect")));
        let via_writer = WRITERS
            .contains(&c.name.as_str())
            .then(|| {
                c.args
                    .iter()
                    .find_map(|w| self.sensitive(&w.text).map(|p| (p, c.name.as_str())))
            })
            .flatten();
        match via_redirect.or(via_writer) {
            Some((path, how)) => Verdict::Red(
                Detail::new(
                    format!("writes to sensitive file `{path}` via {how}"),
                    "Changes persist beyond the install and affect every future shell, login or privilege check.",
                )
                .fix("Prefer installers that print the lines to add instead of editing files for you.")
                .at(c.span.clone()),
            ),
            None => Verdict::Ignore,
        }
    }
}

register_flag! {
    id: "sensitive_write",
    kind: Red,
    category: Sensitive,
    description: "Writes to ~/.bashrc, ~/.ssh/authorized_keys, /etc/sudoers or crontab",
    config: SensitiveWriteCfg,
    build: |cfg, _shared| SensitiveWrite::new(cfg),
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn rc_files_ssh_sudoers_cron() {
        assert!(fires("sensitive_write", "echo x >> ~/.bashrc"));
        assert!(fires("sensitive_write", "echo x >> \"$HOME/.zshrc\""));
        assert!(fires(
            "sensitive_write",
            "cat key >> ~/.ssh/authorized_keys"
        ));
        assert!(fires(
            "sensitive_write",
            "echo 'u ALL=(ALL) NOPASSWD: ALL' | sudo tee -a /etc/sudoers.d/u"
        ));
        assert!(fires("sensitive_write", "sed -i 's/a/b/' ~/.profile"));
        assert!(fires("sensitive_write", "crontab -"));
        assert!(!fires("sensitive_write", "crontab -l"));
        assert!(!fires("sensitive_write", "echo x >> ~/.tool/config"));
    }

    #[test]
    fn shell_rc_can_be_opted_out() {
        let cfg: toml::Value = toml::from_str("shell_rc = false").unwrap();
        let reg = crate::analysis::registry::find("sensitive_write").unwrap();
        let flag = (reg.build)(Some(&cfg), &Default::default())
            .unwrap()
            .unwrap();
        let ctx =
            crate::parser::parse("echo x >> ~/.bashrc\necho k >> ~/.ssh/authorized_keys").unwrap();
        assert_eq!(crate::analysis::analyze(&ctx, &mut [(reg, flag)]).len(), 1);
    }
}
