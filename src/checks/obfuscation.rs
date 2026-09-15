use crate::analysis::Flag;
use crate::config::{NoConfig, Shared};
use crate::model::{Detail, Verdict};
use crate::parser::{Command, Pipeline};
use crate::register_flag;

pub struct Obfuscation {
    shared: Shared,
}

fn decodes(c: &Command) -> bool {
    match c.name.as_str() {
        "base64" | "base32" => {
            c.short_flags().any(|f| f == 'd' || f == 'D') || c.has_arg("--decode")
        }
        "xxd" => c.short_flags().any(|f| f == 'r'),
        "openssl" => c.has_arg("enc") && c.has_arg("-d"),
        "gunzip" | "zcat" | "uudecode" => true,
        _ => false,
    }
}

impl Flag for Obfuscation {
    fn visit_pipeline(&mut self, p: &Pipeline) -> Verdict {
        let Some(decoder_at) = p.stages.iter().position(decodes) else {
            return Verdict::Ignore;
        };
        let executes = p.stages[decoder_at + 1..]
            .iter()
            .any(|c| self.shared.is_shell(&c.name) || c.name == "eval");
        if !executes {
            return Verdict::Ignore;
        }
        Verdict::Red(
            Detail::new(
                format!("decodes with `{}` and pipes the result into a shell", p.stages[decoder_at].name),
                "The real payload is hidden from readers and static analysis; only the decoder is visible.",
            )
            .at(p.span.clone()),
        )
    }

    fn visit_command(&mut self, c: &Command) -> Verdict {
        // `eval echo ~"$USER"` / `eval wget $ARGS` name the command; `eval "$CMD"` / `eval $(gen)` do not.
        let opaque_eval = c.name == "eval"
            && (c
                .args
                .first()
                .is_some_and(|w| w.text.starts_with('$') || w.text.starts_with('`'))
                || c.args
                    .iter()
                    .any(|w| w.text.contains("$(") || w.text.contains('`')));
        let shell_of_decoded = self.shared.is_shell(&c.name) && c.substitutions.iter().any(decodes);
        if opaque_eval {
            return Verdict::Red(
                Detail::new("`eval` of computed content", "Whatever the expansion yields at run time is executed as code; it cannot be reviewed ahead of time.")
                    .at(c.span.clone()),
            );
        }
        if shell_of_decoded {
            return Verdict::Red(
                Detail::new(
                    "shell executes decoded content",
                    "An encoded blob is decoded and run, hiding the payload from review.",
                )
                .at(c.span.clone()),
            );
        }
        Verdict::Ignore
    }
}

register_flag! {
    id: "obfuscation",
    kind: Red,
    category: Obfuscation,
    description: "eval of opaque code (`eval \"$CMD\"`, `eval $(…)`), base64/xxd decode piped into a shell",
    config: NoConfig,
    build: |_cfg, shared| Obfuscation { shared: shared.clone() },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn decode_then_exec_and_dynamic_eval() {
        assert!(fires("obfuscation", "echo aGk= | base64 -d | sh"));
        assert!(fires(
            "obfuscation",
            "bash -c \"$(echo aGk= | base64 --decode)\""
        ));
        assert!(fires("obfuscation", "eval \"$(fetch_payload)\""));
        assert!(fires("obfuscation", "eval \"${CMD}\""));
        assert!(!fires("obfuscation", "eval 'echo static'"));
        assert!(
            !fires("obfuscation", "resolved=$(eval echo ~\"$USER\")"),
            "known command with expanded args"
        );
        assert!(!fires("obfuscation", "eval wget $ARGS"));
        assert!(!fires("obfuscation", "echo aGk= | base64 -d > file"));
    }
}
