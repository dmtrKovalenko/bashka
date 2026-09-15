use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::Command;
use crate::register_flag;

pub struct Persistence {
    reported: bool,
}

const SERVICE_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/etc/init.d",
    "/Library/LaunchDaemons",
    "/Library/LaunchAgents",
    "Library/LaunchAgents",
    ".config/systemd/user",
];

fn persists(c: &Command) -> Option<String> {
    let mentions_service_dir = c
        .args
        .iter()
        .chain(&c.redirects)
        .any(|w| SERVICE_DIRS.iter().any(|d| w.text.contains(d)));
    match c.name.as_str() {
        "systemctl"
            if c.arg_texts()
                .any(|a| matches!(a, "enable" | "start" | "restart")) =>
        {
            Some("systemd service".into())
        }
        "launchctl"
            if c.arg_texts()
                .any(|a| matches!(a, "load" | "bootstrap" | "enable")) =>
        {
            Some("macOS launch agent".into())
        }
        "update-rc.d" | "chkconfig" | "rc-update" => Some("init service".into()),
        _ if mentions_service_dir => Some("service definition".into()),
        _ => None,
    }
}

impl Flag for Persistence {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        let Some(what) = persists(c).filter(|_| !self.reported) else {
            return Verdict::Ignore;
        };
        self.reported = true;
        Verdict::Yellow(
            Detail::new(
                format!("installs a {what} that keeps running after the installer exits"),
                "Background services run at every boot; make sure that is what you expect from this tool.",
            )
            .at(c.span.clone()),
        )
    }
}

register_flag! {
    id: "persistence",
    kind: Yellow,
    category: Sensitive,
    description: "Installs systemd/launchd services or init scripts",
    config: NoConfig,
    build: |_cfg, _shared| Persistence { reported: false },
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;

    #[test]
    fn detects_services() {
        assert!(fires("persistence", "systemctl enable --now k3s"));
        assert!(fires(
            "persistence",
            "launchctl load ~/Library/LaunchAgents/com.x.plist"
        ));
        assert!(fires(
            "persistence",
            "cat > /etc/systemd/system/x.service <<EOF\nfoo\nEOF"
        ));
        assert!(!fires("persistence", "systemctl status docker"));
    }
}
