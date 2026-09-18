use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::Command;
use crate::register_flag;

pub struct PackageRepos {
    reported: bool,
}

const REPO_DIRS: &[&str] = &[
    "/etc/apt/sources.list",
    "/etc/apt/trusted.gpg.d",
    "/etc/apt/keyrings",
    "/usr/share/keyrings",
    "/etc/yum.repos.d",
    "/etc/zypp/repos.d",
    "/etc/pacman.d",
];

fn adds_repo(c: &Command) -> Option<&'static str> {
    let touches_repo_dir = c
        .args
        .iter()
        .chain(&c.redirects)
        .any(|w| REPO_DIRS.iter().any(|d| w.text.starts_with(d)));
    match c.name.as_str() {
        "apt-key" if c.has_arg("add") => Some("APT signing key"),
        "add-apt-repository" => Some("APT repository"),
        "rpm" if c.has_arg("--import") => Some("RPM signing key"),
        "dnf" | "yum" if c.has_arg("config-manager") || c.has_arg("--add-repo") => {
            Some("YUM/DNF repository")
        }
        "zypper" if c.has_arg("addrepo") || c.has_arg("ar") => Some("zypper repository"),
        // An uninstaller removing its own repo file adds nothing.
        "rm" | "unlink" => None,
        _ if touches_repo_dir => Some("package repository definition"),
        _ => None,
    }
}

impl Flag for PackageRepos {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        let Some(what) = adds_repo(c).filter(|_| !self.reported) else {
            return Verdict::Ignore;
        };
        self.reported = true;
        Verdict::Yellow(
            Detail::new(
                format!("adds a {what} to the system package manager"),
                "Future `apt upgrade` / `dnf update` runs will trust and install whatever that repository publishes.",
            )
            .at(c.span.clone()),
        )
    }
}

register_flag! {
    id: "package_repos",
    kind: Yellow,
    category: Sensitive,
    description: "Adds apt/yum/zypper repositories or signing keys",
    config: NoConfig,
    build: |_cfg, _shared| PackageRepos { reported: false },
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;

    #[test]
    fn detects_repo_additions() {
        assert!(fires(
            "package_repos",
            "curl -fsSL https://x.io/key | sudo apt-key add -"
        ));
        assert!(fires(
            "package_repos",
            "echo 'deb https://x.io stable main' > /etc/apt/sources.list.d/x.list"
        ));
        assert!(fires(
            "package_repos",
            "sudo dnf config-manager --add-repo https://x.io/x.repo"
        ));
        assert!(
            !fires(
                "package_repos",
                "rm -f /etc/zypp/repos.d/rancher-k3s-common*.repo"
            ),
            "removing a repo file adds nothing"
        );
        assert!(!fires("package_repos", "apt-get install -y curl"));
    }
}
