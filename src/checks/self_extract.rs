//! Red: the script extracts a payload from its own bytes and runs it (comment-smuggled code).

use crate::analysis::Flag;
use crate::config::{NoConfig, Shared};
use crate::model::{Detail, Verdict};
use crate::parser::Pipeline;
use crate::register_flag;

fn base(name: &str) -> &str {
    crate::config::base_name(name)
}

/// Tools that read a file's bytes and emit part of them.
const SLICERS: &[&str] = &[
    "sed", "awk", "tail", "head", "grep", "dd", "cut", "tr", "base64", "xxd", "openssl",
];

pub struct SelfExtract {
    shared: Shared,
}

/// A command that reads `$0` (the running script) as input.
fn reads_self(c: &crate::parser::Command) -> bool {
    if !SLICERS.contains(&base(&c.name)) {
        return false;
    }
    c.args.iter().chain(&c.redirects).any(|w| {
        let t = w.text.trim_matches(['"', '\'']);
        t == "$0" || t == "${0}" || t.contains("$0") || t == "\"$0\""
    })
}

impl Flag for SelfExtract {
    fn visit_pipeline(&mut self, p: &Pipeline) -> Verdict {
        let Some(at) = p.stages.iter().position(reads_self) else {
            return Verdict::Ignore;
        };
        let executes = p.stages[at + 1..]
            .iter()
            .any(|c| self.shared.is_shell(&c.name) || c.name == "eval");
        if !executes {
            return Verdict::Ignore;
        }
        Verdict::Red(
            Detail::new(
                "extracts a payload from its own file (`$0`) and runs it",
                "The real code is smuggled inside this script's bytes (after an `exit`, or as a comment/appended blob) and is invisible to a normal read.",
            )
            .fix("Read the whole file, including anything past the visible end, before running it.")
            .at(p.span.clone()),
        )
    }
}

register_flag! {
    id: "self_extract",
    kind: Red,
    category: Obfuscation,
    description: "Reads its own bytes ($0) with sed/tail/dd/base64 and pipes the result into a shell",
    config: NoConfig,
    build: |_cfg, shared| SelfExtract { shared: shared.clone() },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn flags_self_extraction() {
        assert!(fires("self_extract", "tail -n +50 \"$0\" | bash"));
        assert!(fires("self_extract", "sed '1,/^__END__$/d' $0 | sh"));
        assert!(fires(
            "self_extract",
            "base64 -d <(tail -c 200 \"$0\") | bash"
        ));
    }

    #[test]
    fn ignores_benign_self_reference() {
        assert!(!fires("self_extract", "echo \"usage: $0 [opts]\""));
        assert!(!fires("self_extract", "tail -n 5 logfile | grep x"));
    }
}
