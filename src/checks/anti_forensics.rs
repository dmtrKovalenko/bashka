//! Red: hides its own tracks by disabling history/logging or killing security agents.

use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::{Assignment, Command};
use crate::register_flag;

fn base(name: &str) -> &str {
    crate::config::base_name(name)
}

/// EDR / audit / AV daemons that malware kills to avoid detection.
const SECURITY_AGENTS: &[&str] = &[
    "auditd",
    "falcon-sensor",
    "falcond",
    "crowdstrike",
    "osqueryd",
    "wazuh",
    "wazuh-agent",
    "ossec",
    "clamd",
    "clamav",
    "mdatp",
    "carbonblack",
    "cbagent",
    "sentinelone",
    "sentinelagent",
    "elastic-agent",
    "filebeat",
    "sysmon",
];

pub struct AntiForensics {
    reported: bool,
}

fn kills_agent(c: &Command) -> Option<String> {
    match base(&c.name) {
        "pkill" | "killall" | "kill" => c
            .arg_texts()
            .find(|a| SECURITY_AGENTS.iter().any(|s| a.contains(s)))
            .map(|a| format!("kills the security agent `{a}`")),
        "systemctl" | "service" => (c
            .arg_texts()
            .any(|a| matches!(a, "stop" | "disable" | "mask" | "kill")))
        .then(|| {
            c.arg_texts()
                .find(|a| SECURITY_AGENTS.iter().any(|s| a.contains(s)))
        })
        .flatten()
        .map(|a| format!("stops the security service `{a}`")),
        "auditctl" if c.has_arg("-D") => Some("clears all audit rules".into()),
        _ => None,
    }
}

fn erases_history(c: &Command) -> Option<String> {
    match base(&c.name) {
        "history" if c.has_arg("-c") => Some("clears the shell history".into()),
        "journalctl" if c.arg_texts().any(|a| a.starts_with("--vacuum")) => {
            Some("vacuums the systemd journal".into())
        }
        // `: > /var/log/x`, `truncate -s0 /var/log/x`, `rm /var/log/...`
        "truncate" | "rm" | "shred" if c.arg_texts().any(|a| a.starts_with("/var/log")) => {
            Some("erases system logs".into())
        }
        _ => None,
    }
}

impl Flag for AntiForensics {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if self.reported {
            return Verdict::Ignore;
        }
        // `set +o history`
        if base(&c.name) == "set" && c.arg_texts().collect::<Vec<_>>() == ["+o", "history"] {
            self.reported = true;
            return red(
                "disables shell history (`set +o history`)".into(),
                c.span.clone(),
            );
        }
        // Truncating a log via redirect: `: > /var/log/auth.log`, `echo > /var/log/x`.
        if c.redirects
            .iter()
            .any(|w| w.text.trim_matches(['"', '\'']).starts_with("/var/log"))
        {
            self.reported = true;
            return red("overwrites a system log file".into(), c.span.clone());
        }
        if let Some(what) = kills_agent(c).or_else(|| erases_history(c)) {
            self.reported = true;
            return red(what, c.span.clone());
        }
        Verdict::Ignore
    }

    fn visit_assignment(&mut self, a: &Assignment) -> Verdict {
        if self.reported {
            return Verdict::Ignore;
        }
        let v = a.value.text.trim_matches(['"', '\'']);
        let hides = matches!(
            (a.name.as_str(), v),
            ("HISTFILE", "/dev/null") | ("HISTSIZE", "0") | ("HISTFILESIZE", "0")
        );
        if hides {
            self.reported = true;
            return red(
                format!("disables shell history (`{}={}`)", a.name, a.value.text),
                a.span.clone(),
            );
        }
        Verdict::Ignore
    }
}

fn red(title: String, span: crate::model::Span) -> Verdict {
    Verdict::Red(
        Detail::new(
            title,
            "Suppressing history, logs, or security agents is post-compromise behavior; a legitimate installer has nothing to hide.",
        )
        .fix("Do not run this.")
        .at(span),
    )
}

register_flag! {
    id: "anti_forensics",
    kind: Red,
    category: Sensitive,
    description: "Hides tracks: unset/redirect HISTFILE, history -c, log truncation, journalctl --vacuum, killing EDR/audit agents",
    config: NoConfig,
    build: |_cfg, _shared| AntiForensics { reported: false },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn flags_track_hiding() {
        assert!(fires("anti_forensics", "export HISTFILE=/dev/null"));
        assert!(fires("anti_forensics", "history -c"));
        assert!(fires("anti_forensics", "set +o history"));
        assert!(fires("anti_forensics", "pkill -9 falcon-sensor"));
        assert!(fires("anti_forensics", "systemctl stop auditd"));
        assert!(fires("anti_forensics", "auditctl -D"));
        assert!(fires("anti_forensics", "journalctl --vacuum-time=1s"));
        assert!(fires("anti_forensics", ": > /var/log/auth.log"));
    }

    #[test]
    fn ignores_benign() {
        assert!(!fires("anti_forensics", "export HISTSIZE=10000"));
        assert!(!fires("anti_forensics", "systemctl enable myapp"));
        assert!(!fires("anti_forensics", "kill $PID"));
        assert!(!fires("anti_forensics", "rm -rf /tmp/build"));
    }
}
