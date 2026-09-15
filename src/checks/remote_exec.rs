use crate::analysis::Flag;
use crate::chain::detect::{self, Forward};
use crate::config::{NoConfig, Shared};
use crate::model::{Detail, Verdict};
use crate::parser::{Command, Pipeline};
use crate::register_flag;

pub struct RemoteExec {
    shared: Shared,
}

fn report(f: Forward) -> Verdict {
    Verdict::Red(
        Detail::new(
            format!("executes a remote script via {}: {}", f.via, f.url.text),
            "The downloaded bytes run unreviewed with your privileges; the published script may differ from what this layer fetches at run time.",
        )
        .fix("bashka follows this forward and analyzes the inner script before anything runs.")
        .at(f.span),
    )
}

impl Flag for RemoteExec {
    fn visit_pipeline(&mut self, p: &Pipeline) -> Verdict {
        detect::in_pipeline(p, &self.shared).map_or(Verdict::Ignore, report)
    }

    fn visit_command(&mut self, c: &Command) -> Verdict {
        detect::in_command(c, &self.shared).map_or(Verdict::Ignore, report)
    }
}

register_flag! {
    id: "remote_exec",
    kind: Red,
    category: Remote,
    description: "Fetches a remote script and executes it (drives chain following)",
    config: NoConfig,
    build: |_cfg, shared| RemoteExec { shared: shared.clone() },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn forward_sinks_are_red() {
        assert!(fires("remote_exec", "curl -fsSL https://x.io/i | bash"));
        assert!(fires(
            "remote_exec",
            "f() {\n  bash <(curl -s https://x.io/i)\n}"
        ));
        assert!(fires("remote_exec", "eval \"$(curl -s https://x.io/i)\""));
        assert!(!fires("remote_exec", "curl -fsSL https://x.io/i -o i.sh"));
        assert!(!fires("remote_exec", "curl -fsSL https://x.io/i | tar xz"));
    }
}
