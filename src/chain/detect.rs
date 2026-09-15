use crate::config::Shared;
use crate::model::Span;
use crate::parser::{Command, Ctx, Node, Pipeline, Word};

#[derive(Debug, Clone)]
pub struct Forward {
    /// The URL word as written (may contain expansions).
    pub url: Word,
    pub span: Span,
    pub via: &'static str,
}

/// Every forward sink in the script, in source order.
pub fn forwards(ctx: &Ctx, shared: &Shared) -> Vec<Forward> {
    ctx.nodes
        .iter()
        .filter_map(|n| match n {
            Node::Pipeline(p) => in_pipeline(p, shared),
            Node::Command(c) => in_command(c, shared),
            Node::Assignment(_) => None,
        })
        .collect()
}

/// `curl … <url> | bash`
pub fn in_pipeline(p: &Pipeline, shared: &Shared) -> Option<Forward> {
    let (fetch_at, url) = p
        .stages
        .iter()
        .enumerate()
        .find_map(|(i, c)| fetch_url(c, shared).map(|u| (i, u)))?;
    let executes = p.stages[fetch_at + 1..]
        .iter()
        .any(|c| shared.is_shell(&c.name));
    executes.then(|| Forward {
        url: url.clone(),
        span: p.span.clone(),
        via: "pipe",
    })
}

/// `bash <(curl …)`, `bash < <(curl …)`, `eval "$(curl …)"`, `sh -c "$(curl …)"`
pub fn in_command(c: &Command, shared: &Shared) -> Option<Forward> {
    if !(shared.is_shell(&c.name) || c.name == "eval" || c.name == "source" || c.name == ".") {
        return None;
    }
    let fetch = c.substitutions.iter().find_map(|s| fetch_url(s, shared))?;
    Some(Forward {
        url: fetch.clone(),
        span: c.span.clone(),
        via: "substitution",
    })
}

/// The URL a network command downloads to stdout, if any.
/// Downloads written to a file (`curl -o`, `wget` without `-O-`) are not forwards.
pub fn fetch_url<'a>(c: &'a Command, shared: &Shared) -> Option<&'a Word> {
    if !shared.is_network(&c.name) || !to_stdout(c) {
        return None;
    }
    c.args.iter().find(|w| {
        w.text.contains("://")
            || (!w.literal && !w.text.starts_with('-'))
            || looks_like_host(&w.text)
    })
}

fn to_stdout(c: &Command) -> bool {
    match c.name.as_str() {
        "curl" => {
            !(c.short_flags().any(|f| f == 'o' || f == 'O')
                || c.has_arg("--output")
                || c.has_arg("--remote-name"))
        }
        "wget" => {
            let args: Vec<&str> = c.arg_texts().collect();
            args.iter()
                .any(|a| a.starts_with('-') && !a.starts_with("--") && a.ends_with("O-"))
                || args.windows(2).any(|w| {
                    (w[0].ends_with('O') && !w[0].starts_with("--") || w[0] == "--output-document")
                        && w[1] == "-"
                })
                || args.contains(&"--output-document=-")
        }
        _ => true,
    }
}

fn looks_like_host(w: &str) -> bool {
    !w.starts_with('-')
        && w.contains('.')
        && !w.contains('/')
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-".contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    fn fwds(src: &str) -> Vec<(String, &'static str)> {
        let ctx = parse(src).unwrap();
        forwards(&ctx, &Shared::default())
            .into_iter()
            .map(|f| (f.url.text, f.via))
            .collect()
    }

    #[test]
    fn detects_every_sink_shape() {
        assert_eq!(
            fwds("curl -fsSL https://a.io/i | bash"),
            [("https://a.io/i".to_string(), "pipe")]
        );
        assert_eq!(
            fwds("wget -qO- https://a.io/i | sh -s -- --x"),
            [("https://a.io/i".to_string(), "pipe")]
        );
        assert_eq!(
            fwds("bash <(curl -s https://a.io/i)"),
            [("https://a.io/i".to_string(), "substitution")]
        );
        assert_eq!(
            fwds("bash < <(curl -s https://a.io/i)"),
            [("https://a.io/i".to_string(), "substitution")]
        );
        assert_eq!(
            fwds(r#"eval "$(curl -s https://a.io/i)""#),
            [("https://a.io/i".to_string(), "substitution")]
        );
        assert_eq!(
            fwds(r#"/bin/bash -c "$(curl -fsSL https://a.io/i)""#),
            [("https://a.io/i".to_string(), "substitution")],
            "an absolute-path shell is resolved by basename"
        );
        assert_eq!(
            fwds(r#"f() { curl -sSL "$URL" | bash; }"#),
            [("$URL".to_string(), "pipe")]
        );
    }

    #[test]
    fn ignores_downloads_to_files() {
        assert!(fwds("curl -fsSL -o /tmp/x https://a.io/i | bash").is_empty());
        assert!(fwds("curl https://a.io/i | tar xz").is_empty());
        assert!(fwds("wget -O out.sh https://a.io/i").is_empty());
    }
}
