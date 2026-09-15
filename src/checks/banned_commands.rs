use crate::analysis::Flag;
use crate::config::Recommended;
use crate::model::{Detail, Verdict};
use crate::parser::{Command, Ctx};
use crate::register_flag;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BannedCommandsCfg {
    /// Keep the built-in destructive-command detectors.
    pub builtin: bool,
    /// Extra substrings; a command whose text contains one is flagged.
    pub additional: Vec<String>,
}

impl Default for BannedCommandsCfg {
    fn default() -> Self {
        Self {
            builtin: true,
            additional: Vec::new(),
        }
    }
}

impl Recommended for BannedCommandsCfg {
    fn recommended() -> Self {
        Self::default()
    }
}

const SYSTEM_ROOTS: &[&str] = &[
    "/", "/*", "~", "$HOME", "${HOME}", "/etc", "/usr", "/bin", "/var", "/boot", "/lib", "/home",
];

pub struct BannedCommands {
    cfg: BannedCommandsCfg,
}

impl BannedCommands {
    fn builtin(&self, c: &Command) -> Option<(String, &'static str)> {
        let recursive_force =
            c.short_flags().any(|f| f == 'r' || f == 'R') && c.short_flags().any(|f| f == 'f');
        match c.name.as_str() {
            "rm" if recursive_force => c
                .arg_texts()
                .find(|a| SYSTEM_ROOTS.contains(a) || a.trim_end_matches('/').is_empty())
                .map(|a| {
                    (
                        format!("recursive forced deletion of `{a}`"),
                        "Wipes the filesystem or the home directory.",
                    )
                }),
            "dd" => c.arg_texts().find(|a| a.starts_with("of=/dev/")).map(|a| {
                (
                    format!("raw write to a block device (`{a}`)"),
                    "Overwrites a disk directly, destroying its contents.",
                )
            }),
            n if n.starts_with("mkfs") || n == "wipefs" || n == "shred" => Some((
                format!("`{n}` formats or erases storage"),
                "Destroys existing data on the target.",
            )),
            "chmod"
                if c.short_flags().any(|f| f == 'R')
                    && c.arg_texts().any(|a| a.ends_with("777")) =>
            {
                Some((
                    "recursive world-writable permissions (`chmod -R 777`)".into(),
                    "Lets any local user replace those files, including binaries you will run.",
                ))
            }
            _ => None,
        }
    }
}

impl Flag for BannedCommands {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        let text = std::iter::once(c.name.as_str())
            .chain(c.arg_texts())
            .collect::<Vec<_>>()
            .join(" ");
        if let Some(pat) = self
            .cfg
            .additional
            .iter()
            .find(|p| text.contains(p.as_str()))
        {
            return Verdict::Red(Detail::new(
                format!("banned command pattern `{pat}`"),
                "Matched an entry from `banned_commands.additional`.",
            ));
        }
        match self.cfg.builtin.then(|| self.builtin(c)).flatten() {
            Some((title, why)) => {
                Verdict::Red(Detail::new(title, why).fix("Do not run this script."))
            }
            None => Verdict::Ignore,
        }
    }

    fn finalize(&mut self, ctx: &Ctx) -> Verdict {
        let compact: String = ctx.source.chars().filter(|c| !c.is_whitespace()).collect();
        if self.cfg.builtin && compact.contains(":(){:|:&};:") {
            return Verdict::Red(Detail::new(
                "fork bomb",
                "A function that spawns itself recursively in the background until the system runs out of processes.",
            ));
        }
        Verdict::Ignore
    }
}

register_flag! {
    id: "banned_commands",
    kind: Red,
    category: Exec,
    description: "Destructive commands: rm -rf /, dd of=/dev/*, mkfs, fork bomb, chmod -R 777",
    weight: 3,
    config: BannedCommandsCfg,
    build: |cfg, _shared| BannedCommands { cfg },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn destructive_commands() {
        assert!(fires("banned_commands", "rm -rf /"));
        assert!(fires("banned_commands", "rm -rf \"$HOME\""));
        assert!(!fires("banned_commands", "rm -rf \"$TMP\""));
        assert!(fires("banned_commands", "dd if=/dev/zero of=/dev/sda"));
        assert!(fires("banned_commands", "mkfs.ext4 /dev/sdb1"));
        assert!(fires("banned_commands", "chmod -R 777 /usr/local"));
        assert!(!fires("banned_commands", "chmod 755 tool"));
        assert!(fires("banned_commands", ":(){ :|:& };:"));
    }

    #[test]
    fn additional_patterns_from_config() {
        let cfg: toml::Value = toml::from_str("additional = ['curl -k']").unwrap();
        let reg = crate::analysis::registry::find("banned_commands").unwrap();
        let flag = (reg.build)(Some(&cfg), &Default::default())
            .unwrap()
            .unwrap();
        let ctx = crate::parser::parse("curl -k https://x.io | sh\nrm -rf /").unwrap();
        let found = crate::analysis::analyze(&ctx, &mut [(reg, flag)]);
        assert_eq!(found.len(), 2, "additional pattern plus builtin stays on");
    }
}
