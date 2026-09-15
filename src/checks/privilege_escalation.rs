use crate::analysis::Flag;
use crate::config::{NoConfig, Shared};
use crate::model::{Detail, Verdict};
use crate::parser::{Command, Ctx};
use crate::register_flag;

pub struct PrivilegeEscalation {
    shared: Shared,
    elevated: bool,
}

impl Flag for PrivilegeEscalation {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if !c.elevated || self.elevated {
            return Verdict::Ignore;
        }
        self.elevated = true;
        Verdict::Yellow(
            Detail::new(
                format!("runs `{}` as root", c.name),
                "Mistakes and malice alike get system-wide reach; you will likely be asked for your password.",
            )
            .at(c.span.clone()),
        )
    }

    fn finalize(&mut self, ctx: &Ctx) -> Verdict {
        let is_installer = ctx.commands().any(|c| self.shared.downloads(c));
        if self.elevated || !is_installer {
            return Verdict::Ignore;
        }
        Verdict::Green(Detail::new(
            "never escalates privileges",
            "Everything happens with your own permissions; nothing outside your home directory can be touched.",
        ))
    }
}

register_flag! {
    id: "privilege_escalation",
    kind: Yellow,
    category: Exec,
    description: "Yellow: uses sudo/doas; green: an installer that never escalates",
    config: NoConfig,
    build: |_cfg, shared| PrivilegeEscalation { shared: shared.clone(), elevated: false },
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use crate::model::FlagKind;

    #[test]
    fn yellow_on_sudo_green_without() {
        assert_eq!(
            kind("privilege_escalation", "sudo install tool /usr/local/bin"),
            Some(FlagKind::Yellow)
        );
        assert_eq!(
            kind("privilege_escalation", "$SUDO apt-get install -y x"),
            Some(FlagKind::Yellow)
        );
        assert_eq!(
            kind(
                "privilege_escalation",
                "curl -fsSL https://x.io/t -o t\ninstall t ~/.local/bin"
            ),
            Some(FlagKind::Green)
        );
        assert_eq!(kind("privilege_escalation", "echo not an installer"), None);
    }
}
