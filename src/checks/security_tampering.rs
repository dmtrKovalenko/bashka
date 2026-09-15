use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::Command;
use crate::register_flag;

const SECURITY_UNITS: &[&str] = &[
    "firewalld",
    "ufw",
    "apparmor",
    "auditd",
    "selinux",
    "iptables",
    "nftables",
];

pub struct SecurityTampering;

fn tampering(c: &Command) -> Option<&'static str> {
    let args: Vec<&str> = c.arg_texts().collect();
    let hits_security_unit = || {
        args.iter()
            .any(|a| SECURITY_UNITS.iter().any(|u| a.contains(u)))
    };
    match c.name.as_str() {
        "setenforce" if args.first() == Some(&"0") || args.first() == Some(&"Permissive") => {
            Some("puts SELinux in permissive mode")
        }
        "ufw" if args.contains(&"disable") => Some("disables the ufw firewall"),
        "systemctl"
            if args
                .iter()
                .any(|a| matches!(*a, "stop" | "disable" | "mask"))
                && hits_security_unit() =>
        {
            Some("stops or disables a security service")
        }
        "service" if args.contains(&"stop") && hits_security_unit() => {
            Some("stops a security service")
        }
        "iptables" | "ip6tables"
            if args.iter().any(|a| *a == "-F" || *a == "--flush")
                || args.windows(3).any(|w| w[0] == "-P" && w[2] == "ACCEPT") =>
        {
            Some("flushes firewall rules")
        }
        "nft" if args.contains(&"flush") && args.contains(&"ruleset") => {
            Some("flushes the nftables ruleset")
        }
        "spctl"
            if args
                .iter()
                .any(|a| a.contains("master-disable") || *a == "--global-disable") =>
        {
            Some("disables macOS Gatekeeper")
        }
        "csrutil" if args.contains(&"disable") => {
            Some("disables macOS System Integrity Protection")
        }
        "aa-disable" | "aa-teardown" => Some("disables AppArmor"),
        _ => None,
    }
}

impl Flag for SecurityTampering {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        let Some(what) = tampering(c) else {
            return Verdict::Ignore;
        };
        Verdict::Red(
            Detail::new(
                format!("disables a security control: {what}"),
                "Turning off the firewall, SELinux, Gatekeeper or SIP lowers your defenses well beyond what an install needs.",
            )
            .fix("An installer should never weaken system security; do not run this.")
            .at(c.span.clone()),
        )
    }
}

register_flag! {
    id: "security_tampering",
    kind: Red,
    category: Sensitive,
    description: "Disables firewall/SELinux/AppArmor/Gatekeeper/SIP (setenforce 0, ufw disable, csrutil disable)",
    weight: 2,
    config: NoConfig,
    build: |_cfg, _shared| SecurityTampering,
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;

    #[test]
    fn detects_security_disabling() {
        assert!(fires("security_tampering", "sudo setenforce 0"));
        assert!(fires("security_tampering", "sudo ufw disable"));
        assert!(fires("security_tampering", "systemctl stop firewalld"));
        assert!(fires("security_tampering", "iptables -F"));
        assert!(fires("security_tampering", "csrutil disable"));
        assert!(!fires("security_tampering", "systemctl start docker"));
        assert!(!fires("security_tampering", "ufw allow 22"));
    }
}
