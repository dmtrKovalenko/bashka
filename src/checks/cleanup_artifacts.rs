use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Span, Verdict};
use crate::parser::{Command, Ctx};
use crate::register_flag;

#[derive(Default)]
pub struct CleanupArtifacts {
    trap_exit: Option<Span>,
    mktemp: bool,
    rm: Option<Span>,
}

impl Flag for CleanupArtifacts {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        match c.name.as_str() {
            "trap"
                if c.arg_texts()
                    .any(|a| a.split_whitespace().any(|s| s == "EXIT" || s == "0")) =>
            {
                self.trap_exit.get_or_insert(c.span.clone());
            }
            "mktemp" => self.mktemp = true,
            "rm" if c.short_flags().any(|f| f == 'r' || f == 'f') => {
                self.rm.get_or_insert(c.span.clone());
            }
            _ => {}
        }
        Verdict::Ignore
    }

    fn finalize(&mut self, _ctx: &Ctx) -> Verdict {
        let (span, how) = match (&self.trap_exit, self.mktemp, &self.rm) {
            (Some(span), _, _) => (span.clone(), "an EXIT trap"),
            (None, true, Some(span)) => (span.clone(), "removing its mktemp directory"),
            _ => return Verdict::Ignore,
        };
        Verdict::Green(
            Detail::new(
                format!("cleans up after itself with {how}"),
                "Temporary artifacts are removed even on failure, a sign of a carefully written installer.",
            )
            .at(span),
        )
    }
}

register_flag! {
    id: "cleanup_artifacts",
    kind: Green,
    category: Path,
    description: "Removes temporary files via `trap … EXIT` or `rm` of `mktemp` paths",
    config: NoConfig,
    build: |_cfg, _shared| CleanupArtifacts::default(),
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn trap_exit_or_rm_of_mktemp() {
        assert!(fires("cleanup_artifacts", "trap 'rm -rf \"$TMP\"' EXIT"));
        assert!(fires(
            "cleanup_artifacts",
            "TMP=$(mktemp -d)\nrm -rf \"$TMP\""
        ));
        assert!(!fires("cleanup_artifacts", "TMP=$(mktemp -d)\necho leaks"));
        assert!(!fires("cleanup_artifacts", "trap 'echo bye' INT"));
    }
}
