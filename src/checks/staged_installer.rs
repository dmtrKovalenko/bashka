//! Red: the script downloads a program and runs it to perform the installation.

use crate::analysis::Flag;
use crate::config::{NoConfig, Shared};
use crate::install_paths;
use crate::model::{Detail, Verdict};
use crate::parser::Ctx;
use crate::register_flag;

pub struct StagedInstaller {
    shared: Shared,
}

impl Flag for StagedInstaller {
    fn finalize(&mut self, ctx: &Ctx) -> Verdict {
        if !ctx.commands().any(|c| self.shared.downloads(c)) {
            return Verdict::Ignore;
        }
        let executed = install_paths::executed_downloads(ctx);
        if executed.is_empty() {
            return Verdict::Ignore;
        }
        Verdict::Red(
            Detail::new(
                format!(
                    "installs by running a downloaded program: {}",
                    executed.join(", ")
                ),
                "The shell script is only a stager: the real installer is a binary it fetches and \
                 executes. bashka can analyze this script, but not what that program does or \
                 where it writes, so the review covers only the first stage.",
            )
            .fix(
                "Prefer installers that place files themselves. If you trust the publisher, \
                 check `bashka list` afterwards; binaries the second stage puts on PATH are still \
                 recorded.",
            ),
        )
    }
}

register_flag! {
    id: "staged_installer",
    kind: Red,
    category: Exec,
    description: "Downloads a program and runs it to do the install (second stage is opaque)",
    config: NoConfig,
    build: |_cfg, shared| StagedInstaller { shared: shared.clone() },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn fires_when_a_downloaded_program_is_executed() {
        assert!(fires(
            "staged_installer",
            "F=$(mktemp)\ncurl -o \"$F\" https://x.io/i\nchmod +x \"$F\"\n\"$F\" install"
        ));
        assert!(fires(
            "staged_installer",
            "curl -sL https://x.io/t.tgz | tar xz\n./tool --self-install"
        ));
        assert!(!fires(
            "staged_installer",
            "curl -o t https://x.io/t\ninstall -m755 t /usr/local/bin/t"
        ));
        assert!(
            !fires("staged_installer", "curl -fsSL https://x.io/i.sh | bash"),
            "pipe-to-shell is remote_exec's business"
        );
        assert!(
            !fires("staged_installer", "chmod +x ./local.sh\n./local.sh"),
            "no download"
        );
    }
}
