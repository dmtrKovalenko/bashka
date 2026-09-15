use crate::analysis::Flag;
use crate::config::Recommended;
use crate::model::{Detail, Verdict};
use crate::parser::{Command, Ctx};
use crate::register_flag;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MaxCommandsCfg {
    pub limit: usize,
}

impl Default for MaxCommandsCfg {
    fn default() -> Self {
        Self::recommended()
    }
}

impl Recommended for MaxCommandsCfg {
    fn recommended() -> Self {
        Self { limit: 1000 }
    }
}

pub struct MaxCommands {
    limit: usize,
    seen: usize,
}

impl Flag for MaxCommands {
    fn visit_command(&mut self, _c: &Command) -> Verdict {
        self.seen += 1;
        Verdict::Ignore
    }

    fn finalize(&mut self, _ctx: &Ctx) -> Verdict {
        if self.seen <= self.limit {
            return Verdict::Ignore;
        }
        Verdict::Red(Detail::new(
            format!("{} commands exceed the limit of {}", self.seen, self.limit),
            "Very long installers are hard to review by eye, which is exactly where a payload hides best.",
        ))
    }
}

register_flag! {
    id: "max_commands",
    kind: Red,
    category: Complexity,
    description: "Flags scripts with more commands than `limit`",
    config: MaxCommandsCfg,
    build: |cfg, _shared| MaxCommands { limit: cfg.limit, seen: 0 },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn counts_commands_against_limit() {
        let cfg: toml::Value = toml::from_str("limit = 2").unwrap();
        let reg = crate::analysis::registry::find("max_commands").unwrap();
        let run = |src: &str| {
            let flag = (reg.build)(Some(&cfg), &crate::config::Shared::default())
                .unwrap()
                .unwrap();
            crate::analysis::analyze(&crate::parser::parse(src).unwrap(), &mut [(reg, flag)]).len()
        };
        assert_eq!(run("a\nb"), 0);
        assert_eq!(run("a\nb\nc"), 1);
        assert!(!fires("max_commands", "echo fine"));
    }
}
