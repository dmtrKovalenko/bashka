//! Red: `rm -rf` on a path built from a variable that may be empty, risking a wider wipe.

use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::{Command, Ctx};
use crate::register_flag;
use std::collections::HashSet;

fn base(name: &str) -> &str {
    crate::config::base_name(name)
}

pub struct UnsafeRm {
    /// Variables assigned a non-empty literal somewhere, or guarded, so likely safe.
    guarded: HashSet<String>,
    strict_u: bool,
    findings: Vec<crate::model::Span>,
}

/// The variable name in `$VAR`, `${VAR}`, `${VAR:?}` at the start of a path.
fn leading_var(path: &str) -> Option<(String, bool)> {
    let p = path.trim_matches(['"', '\'']);
    let rest = p.strip_prefix('$')?;
    if let Some(inner) = rest.strip_prefix('{') {
        let end = inner.find('}')?;
        let body = &inner[..end];
        // `${VAR:?}` / `${VAR:-x}` / `${VAR:=x}` are guarded against empty.
        let guarded = body.contains(":?") || body.contains(":-") || body.contains(":=");
        let name: String = body
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        return (!name.is_empty()).then_some((name, guarded));
    }
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some((name, false))
}

impl Flag for UnsafeRm {
    fn begin(&mut self, ctx: &Ctx) {
        // `set -u` / `set -euo pipefail` makes an unset var abort rather than expand to empty.
        self.strict_u = ctx.commands().any(|c| {
            base(&c.name) == "set"
                && c.arg_texts()
                    .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('u'))
        });
        // A variable assigned a non-empty literal at least once is treated as guarded.
        for a in ctx.assignments() {
            if !a.value.text.trim_matches(['"', '\'']).is_empty() {
                self.guarded.insert(a.name.clone());
            }
        }
    }

    fn visit_command(&mut self, c: &Command) -> Verdict {
        if base(&c.name) != "rm"
            || !(c.short_flags().any(|f| f == 'r' || f == 'R') && c.short_flags().any(|f| f == 'f'))
        {
            return Verdict::Ignore;
        }
        if self.strict_u {
            return Verdict::Ignore;
        }
        for w in &c.args {
            let t = w.text.trim_matches(['"', '\'']);
            // Path is a variable expansion followed by a slash or glob: `$DIR/`, `$DIR/*`, `${DIR}/`.
            let dangerous_tail = t.ends_with('/') || t.ends_with("/*") || t.ends_with("/.");
            if !dangerous_tail {
                continue;
            }
            if let Some((var, guarded)) = leading_var(t)
                && !guarded
                && !self.guarded.contains(&var)
            {
                self.findings.push(c.span.clone());
                return Verdict::Red(
                    Detail::new(
                        format!("`rm -rf` on `{t}` where `${var}` may be empty"),
                        "If the variable is unset or empty, the path collapses to `/` or a parent directory and the recursive delete runs far wider than intended.",
                    )
                    .fix("Guard it: `rm -rf \"${{{var}:?}}/…\"`, or `set -u` at the top of the script.")
                    .at(c.span.clone()),
                );
            }
        }
        Verdict::Ignore
    }
}

register_flag! {
    id: "unsafe_rm",
    kind: Red,
    category: Exec,
    description: "rm -rf on \"$VAR/\" or \"$VAR/*\" with no empty-guard and no set -u",
    config: NoConfig,
    build: |_cfg, _shared| UnsafeRm { guarded: HashSet::new(), strict_u: false, findings: Vec::new() },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn flags_unguarded_variable_deletes() {
        assert!(fires("unsafe_rm", "rm -rf \"$STEAMROOT/\"*"));
        assert!(fires("unsafe_rm", "rm -rf $BUILD_DIR/"));
    }

    #[test]
    fn ignores_guarded_or_assigned_or_strict() {
        assert!(!fires("unsafe_rm", "rm -rf \"${DIR:?}/\"*"));
        assert!(!fires("unsafe_rm", "set -euo pipefail\nrm -rf \"$DIR/\"*"));
        assert!(!fires("unsafe_rm", "DIR=/tmp/build\nrm -rf \"$DIR/\"*"));
        assert!(!fires("unsafe_rm", "rm -rf /tmp/build"));
        assert!(
            !fires("unsafe_rm", "rm -rf \"$TMP/file.txt\""),
            "not a directory-slash tail"
        );
    }
}
