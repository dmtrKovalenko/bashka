//! Red: points git at attacker-controlled hooks or a shell alias, so code runs on ordinary git use.

use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::Command;
use crate::register_flag;

fn base(name: &str) -> &str {
    crate::config::base_name(name)
}

pub struct GitHooks {
    reported: bool,
}

fn hijacks_git(c: &Command) -> Option<String> {
    // `git config core.hooksPath …`, `git config alias.x '!cmd'`, `git -c core.hooksPath=…`
    if base(&c.name) == "git" {
        let args: Vec<&str> = c.arg_texts().collect();
        // `-c key=value` inline overrides.
        for (i, a) in args.iter().enumerate() {
            if *a == "-c"
                && let Some(kv) = args.get(i + 1)
                && kv.to_ascii_lowercase().starts_with("core.hookspath=")
            {
                return Some("git -c core.hooksPath override".into());
            }
        }
        if args.first() == Some(&"config") {
            if args
                .iter()
                .any(|a| a.eq_ignore_ascii_case("core.hooksPath"))
            {
                return Some("git config core.hooksPath (redirects every hook)".into());
            }
            if args
                .iter()
                .any(|a| a.eq_ignore_ascii_case("core.fsmonitor"))
            {
                return Some("git config core.fsmonitor (runs a command on git status)".into());
            }
            if let Some(alias) = args.iter().find(|a| a.starts_with("alias."))
                && args.iter().any(|a| a.starts_with('!'))
            {
                return Some(format!("git shell alias `{alias}`"));
            }
        }
    }
    // Dropping a file into a hooks directory.
    let writes_hook = c.args.iter().chain(&c.redirects).any(|w| {
        let t = w.text.trim_matches(['"', '\'']);
        t.contains("/.git/hooks/")
            || t.contains("/hooks/pre-commit")
            || t.ends_with("hooks/post-checkout")
    });
    writes_hook.then(|| "writes a git hook script".to_string())
}

impl Flag for GitHooks {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        let Some(what) = hijacks_git(c).filter(|_| !self.reported) else {
            return Verdict::Ignore;
        };
        self.reported = true;
        Verdict::Red(
            Detail::new(
                format!("hijacks git execution: {what}"),
                "Git hooks and shell aliases run automatically during normal development, giving the attacker code execution on every commit, checkout or status.",
            )
            .fix("An installer should not repoint your git hooks or add executing aliases.")
            .at(c.span.clone()),
        )
    }
}

register_flag! {
    id: "git_hooks",
    kind: Red,
    category: Sensitive,
    description: "git config core.hooksPath/fsmonitor/alias '!cmd', or writing into .git/hooks",
    config: NoConfig,
    build: |_cfg, _shared| GitHooks { reported: false },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn flags_git_execution_hijacks() {
        assert!(fires(
            "git_hooks",
            "git config --global core.hooksPath /tmp/hooks"
        ));
        assert!(fires("git_hooks", "git -c core.hooksPath=/tmp/h clone x"));
        assert!(fires(
            "git_hooks",
            "git config --global alias.st '!sh /tmp/x'"
        ));
        assert!(fires("git_hooks", "cp evil .git/hooks/pre-commit"));
    }

    #[test]
    fn ignores_benign_git() {
        assert!(!fires("git_hooks", "git config --global user.name Alice"));
        assert!(!fires("git_hooks", "git clone https://github.com/o/r"));
    }
}
