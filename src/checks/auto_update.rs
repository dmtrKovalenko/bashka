use crate::analysis::Flag;
use crate::config::{NoConfig, Shared};
use crate::model::{Detail, Verdict};
use crate::parser::Ctx;
use crate::register_flag;

pub struct AutoUpdate {
    shared: Shared,
}

impl Flag for AutoUpdate {
    fn finalize(&mut self, ctx: &Ctx) -> Verdict {
        for program in &ctx.programs {
            // With `<<EOF` a `$(curl …)` in the body runs while the file is written, so only
            // direct commands are the program's own.
            let inside = |c: &&crate::parser::Command| {
                program.span.start <= c.span.start
                    && c.span.end <= program.span.end
                    && !(program.expands && c.captured)
            };
            let Some(fetch) = ctx
                .commands()
                .filter(inside)
                .find(|c| self.shared.downloads(c))
            else {
                continue;
            };

            let progam_label = program
                .target
                .as_deref()
                .map_or_else(|| "a program".to_string(), |t| format!("`{t}`"));
            return Verdict::Red(
                Detail::new(
                    format!("installs {progam_label}, which can download on its own when it runs"),
                    "The launcher this installer writes to disk contains a network fetch, so it \
                     updates itself later without asking.",
                )
                .fix(
                    "Read the written program (the heredoc) and check what it fetches, from where, \
                     and whether that can be turned off.",
                )
                .at(fetch.span.clone()),
            );
        }
        Verdict::Ignore
    }
}

register_flag! {
    id: "auto_update",
    kind: Red,
    category: Exec,
    description: "Writes a program to disk (heredoc launcher) that downloads by itself when run: self-updating, never reviewed again",
    config: NoConfig,
    build: |_cfg, shared| AutoUpdate { shared: shared.clone() },
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;

    #[test]
    fn fires_on_a_launcher_that_fetches() {
        let t = titles(
            "auto_update",
            "cat > \"$B/bin/tool\" <<'EOF'\n#!/bin/sh\nrep=$(curl -fs \"$O/latest.json\")\nexec \"$B/current/tool\" \"$@\"\nEOF\nchmod +x \"$B/bin/tool\"",
        );
        assert_eq!(
            t,
            ["installs `$B/bin/tool`, which can download on its own when it runs"]
        );
    }

    #[test]
    fn ignores_launchers_that_only_run_what_is_installed() {
        assert!(!fires(
            "auto_update",
            "cat > \"$B/bin/tool\" <<'EOF'\n#!/bin/sh\nexport PATH=\"$B/bin:$PATH\"\nexec \"$B/lib/tool\" \"$@\"\nEOF"
        ));
        assert!(
            !fires(
                "auto_update",
                "curl -fsSL https://x.io/t.tgz -o t.tgz\ncat > notes <<'EOF'\n#!/bin/sh\necho hi\nEOF"
            ),
            "the installer's own download is not the program's"
        );
        assert!(
            !fires(
                "auto_update",
                "cat > \"$B/bin/tool\" <<EOF\n#!/bin/sh\nVERSION=$(curl -fs https://x.io/latest)\nexec \"$B/lib/tool-\\$VERSION\" \"\\$@\"\nEOF"
            ),
            "an unquoted heredoc expands $(curl) while the installer writes the file"
        );
        assert!(
            fires(
                "auto_update",
                "cat > \"$B/bin/tool\" <<EOF\n#!/bin/sh\ncurl -fs https://x.io/latest -o \"$B/latest\"\nEOF"
            ),
            "a direct command in an unquoted body is still the program's"
        );
    }
}
