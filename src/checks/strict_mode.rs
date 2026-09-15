use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Span, Verdict};
use crate::parser::{Command, Ctx};
use crate::register_flag;

#[derive(Default)]
pub struct StrictMode {
    errexit: bool,
    nounset: bool,
    pipefail: bool,
    span: Option<Span>,
}

impl Flag for StrictMode {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if c.name != "set" {
            return Verdict::Ignore;
        }
        let args: Vec<&str> = c.arg_texts().collect();
        self.errexit |=
            c.short_flags().any(|f| f == 'e') || args.windows(2).any(|w| w == ["-o", "errexit"]);
        self.nounset |=
            c.short_flags().any(|f| f == 'u') || args.windows(2).any(|w| w == ["-o", "nounset"]);
        self.pipefail |= args.contains(&"pipefail");
        self.span.get_or_insert(c.span.clone());
        Verdict::Ignore
    }

    fn finalize(&mut self, _ctx: &Ctx) -> Verdict {
        if !(self.errexit && self.nounset && self.pipefail) {
            return Verdict::Ignore;
        }
        let mut d = Detail::new(
            "runs in strict mode (errexit, nounset, pipefail)",
            "The script stops at the first failing command instead of continuing with half-applied state.",
        );
        if let Some(s) = &self.span {
            d = d.at(s.clone());
        }
        Verdict::Green(d)
    }
}

register_flag! {
    id: "strict_mode",
    kind: Green,
    category: Exec,
    description: "Uses `set -euo pipefail`",
    config: NoConfig,
    build: |_cfg, _shared| StrictMode::default(),
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn needs_all_three_options() {
        assert!(fires("strict_mode", "set -euo pipefail"));
        assert!(fires("strict_mode", "set -e\nset -u\nset -o pipefail"));
        assert!(fires(
            "strict_mode",
            "set -o errexit -o nounset -o pipefail"
        ));
        assert!(!fires("strict_mode", "set -e"));
    }
}
