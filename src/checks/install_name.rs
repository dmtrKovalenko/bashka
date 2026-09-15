use crate::analysis::Flag;
use crate::chain::detect;
use crate::config::{NoConfig, Shared};
use crate::installed::name;
use crate::model::{Detail, Verdict};
use crate::parser::Ctx;
use crate::register_flag;

pub struct InstallName {
    shared: Shared,
}

impl Flag for InstallName {
    fn finalize(&mut self, ctx: &Ctx) -> Verdict {
        // A forwarder's name is the forwarded script's business; that layer is judged.
        if !ctx.commands().any(|c| self.shared.downloads(c))
            || !detect::forwards(ctx, &self.shared).is_empty()
        {
            return Verdict::Ignore;
        }
        if name::static_name(ctx.origin.as_deref(), ctx).is_some() {
            return Verdict::Ignore;
        }
        if name::takes_arguments(ctx) {
            return Verdict::Yellow(
                Detail::new(
                    "the software installed is decided by the script's arguments",
                    "Nothing in the URL or the script names a program, but the script reads its \
                     positional arguments, so the project is probably passed on the command line \
                     (e.g. `-- --git owner/repo`). bashka takes the name from an `owner/repo` \
                     argument; otherwise pass `--name`.",
                )
                .fix("Pass `--name <name>` if the recorded name turns out wrong."),
            );
        }
        Verdict::Red(
            Detail::new(
                "cannot tell what software this installs",
                "Neither the source URL nor the script names a program: no product variable, no \
                 GitHub repository, no file placed into a bin directory, no telling URL. \
                 Legitimate installers say what they install; bashka also needs a name to \
                 record it for `bashka list` / `uninstall` / `update`.",
            )
            .fix("If you know what this is, rerun with `--name <name>`."),
        )
    }
}

register_flag! {
    id: "install_name",
    kind: Red,
    category: Path,
    description: "Downloads files but nothing names the software being installed",
    config: NoConfig,
    build: |_cfg, shared| InstallName { shared: shared.clone() },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn fires_only_when_nothing_names_the_program() {
        assert!(fires(
            "install_name",
            "curl -fsSL https://x.io/t.tgz | tar xz\necho done"
        ));
        assert!(!fires(
            "install_name",
            "APP=widget\ncurl -fsSL https://x.io/t.tgz | tar xz"
        ));
        assert!(!fires(
            "install_name",
            "curl -fsSL https://github.com/o/widget/releases/latest/download/w.tgz | tar xz"
        ));
        assert!(!fires("install_name", "echo hi"), "no download, no opinion");
        assert!(
            !fires("install_name", "curl -fsSL http://$HOST/i.sh | bash"),
            "forwarders defer to the next layer"
        );
        assert_eq!(
            kind(
                "install_name",
                "repo=$2\ncurl -fsSL \"https://github.com/$repo/releases/latest/download/x.tgz\" | tar xz"
            ),
            Some(crate::model::FlagKind::Yellow),
            "argument-driven installers are advisory"
        );
        // The source URL alone can name it.
        assert!(
            findings_from(
                "install_name",
                "https://get.widget.io/install.sh",
                "curl -fsSL https://x.io/t.tgz | tar xz"
            )
            .is_empty()
        );
    }
}
