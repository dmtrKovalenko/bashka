//! Red: the body is not a shell script at all (an HTTP redirect stub, an HTML error page, JSON),
//! so running it can only produce "command not found" noise, or worse.

use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::Ctx;
use crate::register_flag;
use crate::runner;

/// Scripts with more commands than this are treated as real scripts, whatever their names.
const MAX_COMMANDS: usize = 5;

const BUILTINS: &[&str] = &[
    "set", "export", "echo", "printf", "cd", "exit", "return", "source", ".", ":", "eval", "exec",
    "test", "[", "[[", "read", "shift", "trap", "local", "declare", "typeset", "readonly", "unset",
    "alias", "command", "type", "hash", "true", "false", "wait", "kill", "umask", "ulimit",
    "pushd", "popd", "let", "getopts", "break", "continue", "builtin", "enable", "sudo",
];

pub struct NotAScript;

/// `name()` or `function name` definitions, so calls to them count as resolved.
fn defines_function(source: &str, name: &str) -> bool {
    source.lines().any(|l| {
        let l = l.trim_start();
        let (keyword, body) = match l.strip_prefix("function ") {
            Some(rest) => (true, rest.trim_start()),
            None => (false, l),
        };
        let Some(rest) = body.strip_prefix(name) else {
            return false;
        };
        let rest = rest.trim_start();
        rest.starts_with("()") || (keyword && (rest.is_empty() || rest.starts_with('{')))
    })
}

fn resolvable(name: &str, source: &str, path: &str) -> bool {
    name.contains('/')
        || name.contains('$')
        || name.contains('=')
        || BUILTINS.contains(&name)
        || defines_function(source, name)
        || runner::find_in_path(name, path).is_ok()
}

fn looks_like_markup(text: &str) -> Option<&'static str> {
    let head: String = text
        .chars()
        .take(512)
        .collect::<String>()
        .to_ascii_lowercase();
    let head = head.trim_start_matches('\u{feff}').trim_start();
    if head.starts_with("<!doctype")
        || head.starts_with("<html")
        || head.starts_with("<?xml")
        || head.contains("<html")
        || head.contains("<head>")
        || head.contains("<body")
    {
        return Some("an HTML page");
    }
    if (head.starts_with('{') || head.starts_with('[')) && head.contains("\":") {
        return Some("a JSON document");
    }
    None
}

impl Flag for NotAScript {
    fn finalize(&mut self, ctx: &Ctx) -> Verdict {
        if ctx.source.trim().is_empty() {
            return Verdict::Ignore;
        }
        if let Some(what) = looks_like_markup(&ctx.source) {
            return Verdict::Red(
                Detail::new(
                    format!("this is not a shell script but {what}"),
                    "The server answered with a web page or API response instead of the installer: \
                     the URL is wrong, moved, or the request was rejected. The shell would run each \
                     line as a command.",
                )
                .fix("Open the URL in a browser to see what it serves, and fetch with `curl -fsSL` \
                      so HTTP errors fail instead of being piped into the shell."),
            );
        }
        let commands: Vec<_> = ctx.commands().collect();
        if commands.is_empty() || commands.len() > MAX_COMMANDS {
            return Verdict::Ignore;
        }
        let path = runner::real_path();
        if commands
            .iter()
            .any(|c| resolvable(&c.name, &ctx.source, &path))
        {
            return Verdict::Ignore;
        }
        let first = commands[0];
        let shown: String = first.name.chars().take(40).collect();
        Verdict::Red(
            Detail::new(
                format!("this does not look like a shell script: `{shown}` is not a command"),
                "None of the few words in this body is a program, builtin or function, so it is \
                 most likely an HTTP response (`Redirecting...`, `404 page not found`, `Moved \
                 Permanently`) that the server sent instead of the installer.",
            )
            .at(first.span.clone())
            .fix(
                "Fetch with `curl -fsSL <url>`: `-L` follows redirects and `-f` turns HTTP \
                  errors into a failed download instead of text piped into the shell.",
            ),
        )
    }
}

register_flag! {
    id: "not_a_script",
    kind: Red,
    category: Exec,
    description: "The body is an HTTP redirect stub, an HTML/JSON page, or has no recognizable command",
    config: NoConfig,
    build: |_cfg, _shared| NotAScript,
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;

    #[test]
    fn redirect_and_error_bodies_are_not_scripts() {
        assert!(fires("not_a_script", "Redirecting...\n"));
        assert!(fires("not_a_script", "404 page not found\n"));
        assert!(fires("not_a_script", "Moved Permanently\n"));
        assert!(fires("not_a_script", "Redirecting to https://x.io/i.sh\n"));
    }

    #[test]
    fn html_and_json_are_not_scripts() {
        assert!(fires(
            "not_a_script",
            "<!DOCTYPE html>\n<html><body>404</body></html>\n"
        ));
        assert!(fires(
            "not_a_script",
            "  <html>\n<head><title>Sign in</title></head>\n"
        ));
        assert!(fires(
            "not_a_script",
            "{\"message\": \"Not Found\", \"status\": 404}\n"
        ));
    }

    #[test]
    fn real_scripts_even_tiny_ones_pass() {
        assert!(!fires("not_a_script", ""));
        assert!(!fires("not_a_script", "# just a comment\n"));
        assert!(!fires("not_a_script", "echo hi\n"));
        assert!(!fires("not_a_script", "set -e\nls /tmp\n"));
        assert!(!fires("not_a_script", "main() { echo x; }\nmain\n"));
        assert!(!fires("not_a_script", "function main { echo x; }\nmain\n"));
        assert!(!fires(
            "not_a_script",
            "function greet\n{\n  frob\n}\ngreet\n"
        ));
        assert!(!fires("not_a_script", "greet() {\n  frob\n}\ngreet\n"));
        assert!(fires("not_a_script", "greet\n"), "undefined, not on PATH");
        assert!(!fires(
            "not_a_script",
            "\"$HOME/.cargo/bin/rustup\" update\n"
        ));
        assert!(!fires("not_a_script", "./configure\n"));
        assert!(!fires("not_a_script", "FOO=1 ./run\n"));
        // Unknown tools are fine once the body is clearly a script.
        assert!(!fires(
            "not_a_script",
            "frobnicate a\nfrobnicate b\nfrobnicate c\nfrobnicate d\nfrobnicate e\nfrobnicate f\n"
        ));
    }
}
