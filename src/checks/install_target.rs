use crate::analysis::Flag;
use crate::chain::detect;
use crate::config::{NoConfig, Shared};
use crate::install_paths;
use crate::model::{Detail, Verdict};
use crate::parser::Ctx;
use crate::register_flag;

pub struct InstallTarget {
    shared: Shared,
}

impl Flag for InstallTarget {
    fn finalize(&mut self, ctx: &Ctx) -> Verdict {
        let downloads = ctx.commands().any(|c| self.shared.downloads(c));
        // A forwarder's destination is decided by the script it hands off to; that layer is judged.
        if !downloads || !detect::forwards(ctx, &self.shared).is_empty() {
            return Verdict::Ignore;
        }
        let dests = install_paths::destinations(ctx, None);
        if !dests.is_empty() {
            return Verdict::Ignore;
        }
        // Hand-offs are judged by `staged_installer` / `remote_exec`; nothing to add here.
        if install_paths::delegates_to_download(ctx) {
            return Verdict::Ignore;
        }
        Verdict::Red(
            Detail::new(
                "cannot tell where the installer writes files",
                "The script downloads something, but no install, copy, move, link, mkdir, \
                 extract or chmod names a destination. bashka cannot record what it installs, \
                 so `bashka uninstall` would have nothing to remove.",
            )
            .fix(
                "Installers should place files with an explicit path (e.g. `install -m755 tool \
                 \"$HOME/.local/bin/tool\"`). If you proceed, bashka still watches the PATH \
                 directories for new binaries.",
            ),
        )
    }
}

register_flag! {
    id: "install_target",
    kind: Red,
    category: Path,
    description: "Downloads files but never reveals where they are installed",
    config: NoConfig,
    build: |_cfg, shared| InstallTarget { shared: shared.clone() },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn fires_only_for_opaque_installers() {
        assert!(fires(
            "install_target",
            "curl -fsSL https://x.io/t.tgz | tar xz\necho done"
        ));
        assert!(!fires(
            "install_target",
            "curl -fsSL https://x.io/t.tgz | tar xz -C /opt/t"
        ));
        assert!(!fires(
            "install_target",
            "curl -fsSL https://x.io/t -o t\ninstall -m755 t \"$HOME/.local/bin/t\""
        ));
        assert!(
            !fires("install_target", "echo hi"),
            "no download, no opinion"
        );
        assert!(
            !fires("install_target", "curl -fsSL https://x.io/i.sh | bash"),
            "forwarders defer to the next layer"
        );
        assert!(!fires(
            "install_target",
            "git clone https://x.io/r.git \"$HOME/.r\""
        ));
        assert!(
            !fires(
                "install_target",
                "F=$(mktemp)\ncurl -o \"$F\" https://x.io/i\nchmod +x \"$F\"\n\"$F\" self install"
            ),
            "hand-off to a downloaded installer is staged_installer's finding"
        );
        assert_eq!(
            kind(
                "install_target",
                "curl -fsSL https://x.io/t.tgz | tar xz\necho done"
            ),
            Some(crate::model::FlagKind::Red)
        );
    }
}
