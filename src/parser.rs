//! Parses a shell script with tree-sitter and flattens the CST into the typed
//! `Command` / `Pipeline` / `Assignment` views that flags operate on.

use crate::model::Span;
use anyhow::{Context, Result};
use tree_sitter::{Node as TsNode, Parser, Point, Range, Tree};

/// Heredoc bodies fed to these are shell code and are parsed like the rest of the script.
const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh"];

/// One shell word after quote stripping. Expansions are kept verbatim (`$HOME`).
#[derive(Debug, Clone)]
pub struct Word {
    pub text: String,
    pub span: Span,
    /// No expansions or substitutions: the text is exactly what bash will see.
    pub literal: bool,
}

#[derive(Debug, Clone)]
pub struct Command {
    /// The effective command: `sudo rm -rf /` has name `rm` and `elevated == true`.
    pub name: String,
    pub args: Vec<Word>,
    pub elevated: bool,
    /// Runs inside `$(…)`: its output is consumed by the script rather than shown.
    pub captured: bool,
    pub redirects: Vec<Word>,
    /// Commands nested in `$(…)` / `<(…)` inside the arguments or redirects.
    pub substitutions: Vec<Command>,
    pub span: Span,
}

impl Command {
    pub fn arg_texts(&self) -> impl Iterator<Item = &str> {
        self.args.iter().map(|w| w.text.as_str())
    }

    pub fn has_arg(&self, arg: &str) -> bool {
        self.arg_texts().any(|a| a == arg)
    }

    /// Every URL appearing in the arguments.
    pub fn urls(&self) -> impl Iterator<Item = &str> {
        self.args.iter().flat_map(|w| crate::url::urls_in(&w.text))
    }

    /// Short-option letters, e.g. `-rf` -> `r`, `f`.
    pub fn short_flags(&self) -> impl Iterator<Item = char> + '_ {
        self.arg_texts()
            .filter(|a| a.starts_with('-') && !a.starts_with("--"))
            .flat_map(|a| a[1..].chars())
    }
}

#[derive(Debug, Clone)]
pub struct Pipeline {
    pub stages: Vec<Command>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Assignment {
    pub name: String,
    pub value: Word,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum Node {
    Command(Command),
    Pipeline(Pipeline),
    Assignment(Assignment),
}

impl Node {
    pub fn span(&self) -> &Span {
        match self {
            Node::Command(c) => &c.span,
            Node::Pipeline(p) => &p.span,
            Node::Assignment(a) => &a.span,
        }
    }
}

/// A lowered script: source text plus its nodes in source order.
/// A pipeline precedes its stage commands; substituted commands follow their host.
#[derive(Debug, Clone)]
pub struct Ctx {
    pub source: String,
    pub nodes: Vec<Node>,
    /// Host the script itself was fetched from, when known (forwarded layers). `None` in pipe mode.
    pub origin_host: Option<String>,
    /// The full URL the script was fetched from, when known.
    pub origin: Option<String>,
}

impl Ctx {
    pub fn commands(&self) -> impl Iterator<Item = &Command> {
        self.nodes.iter().filter_map(|n| match n {
            Node::Command(c) => Some(c),
            _ => None,
        })
    }

    pub fn assignments(&self) -> impl Iterator<Item = &Assignment> {
        self.nodes.iter().filter_map(|n| match n {
            Node::Assignment(a) => Some(a),
            _ => None,
        })
    }
}

pub fn parse(source: &str) -> Result<Ctx> {
    let tree = parse_tree(source)?;
    let mut walker = Walker {
        src: source,
        nodes: Vec::new(),
    };
    walker.walk(tree.root_node());
    Ok(Ctx {
        source: source.to_owned(),
        nodes: walker.nodes,
        origin_host: None,
        origin: None,
    })
}

struct Walker<'s> {
    src: &'s str,
    nodes: Vec<Node>,
}

impl<'s> Walker<'s> {
    fn text(&self, n: TsNode) -> &'s str {
        &self.src[n.byte_range()]
    }

    /// Descends into everything (functions, conditionals, loops, subshells, substitutions).
    fn walk(&mut self, n: TsNode) {
        match n.kind() {
            "pipeline" => {
                let stages = named_children(n)
                    .filter(|c| c.kind() == "command")
                    .map(|c| self.command(c))
                    .collect();
                self.nodes.push(Node::Pipeline(Pipeline {
                    stages,
                    span: n.byte_range(),
                }));
            }
            "command" => {
                let cmd = self.command(n);
                self.nodes.push(Node::Command(cmd));
            }
            "variable_assignment" => {
                if let Some(a) = self.assignment(n) {
                    self.nodes.push(Node::Assignment(a));
                }
            }
            // `sudo bash <<SCRIPT … SCRIPT`: the body is the real installer.
            "heredoc_body" if self.heredoc_feeds_shell(n) => {
                if let Ok(tree) = parse_range(self.src, n.byte_range()) {
                    self.walk(tree.root_node());
                }
            }
            _ => {}
        }
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            self.walk(child);
        }
    }

    fn heredoc_feeds_shell(&self, body: TsNode) -> bool {
        let Some(statement) = body
            .parent()
            .and_then(|r| r.parent())
            .filter(|s| s.kind() == "redirected_statement")
        else {
            return false;
        };
        statement
            .child_by_field_name("body")
            .filter(|c| c.kind() == "command")
            .is_some_and(|c| SHELLS.contains(&self.command(c).name.as_str()))
    }

    fn command(&self, n: TsNode) -> Command {
        let name = n
            .child_by_field_name("name")
            .map(|c| self.word(c).text)
            .unwrap_or_default();
        let mut args = Vec::new();
        let mut redirects = Vec::new();
        let mut cursor = n.walk();
        for child in n.children_by_field_name("argument", &mut cursor) {
            args.push(self.word(child));
        }
        let mut cursor = n.walk();
        for child in n.children_by_field_name("redirect", &mut cursor) {
            redirects.push(self.redirect_target(child));
        }
        // `cmd < <(curl …)` attaches the redirect to a parent statement.
        let mut redirect_hosts = vec![n];
        if let Some(parent) = n.parent().filter(|p| p.kind() == "redirected_statement") {
            let mut cursor = parent.walk();
            for r in parent.children_by_field_name("redirect", &mut cursor) {
                redirects.push(self.redirect_target(r));
                redirect_hosts.push(r);
            }
        }
        let mut substitutions = Vec::new();
        for host in redirect_hosts {
            self.nested_commands(host, n, &mut substitutions);
        }
        let captured = std::iter::successors(n.parent(), tree_sitter::Node::parent)
            .any(|p| p.kind() == "command_substitution");
        let mut cmd = Command {
            name,
            args,
            redirects,
            substitutions,
            elevated: false,
            captured,
            span: n.byte_range(),
        };
        strip_privilege_wrapper(&mut cmd);
        cmd
    }

    /// The file a redirect points at (`>> ~/.bashrc` -> `~/.bashrc`).
    fn redirect_target(&self, n: TsNode) -> Word {
        let target = n
            .child_by_field_name("destination")
            .or_else(|| named_children(n).find(|c| c.kind() != "file_descriptor"));
        target.map_or_else(|| self.word(n), |t| self.word(t))
    }

    /// Collects commands inside `$(…)` / `<(…)` under `root`, skipping `self_node` itself.
    fn nested_commands(&self, root: TsNode, self_node: TsNode, out: &mut Vec<Command>) {
        let mut cursor = root.walk();
        for child in root.children(&mut cursor) {
            if child.kind() == "command" && child.id() != self_node.id() {
                out.push(self.command(child));
            }
            self.nested_commands(child, self_node, out);
        }
    }

    fn assignment(&self, n: TsNode) -> Option<Assignment> {
        let name = self.text(n.child_by_field_name("name")?).to_owned();
        let value = match n.child_by_field_name("value") {
            Some(v) => self.word(v),
            None => Word {
                text: String::new(),
                span: n.end_byte()..n.end_byte(),
                literal: true,
            },
        };
        Some(Assignment {
            name,
            value,
            span: n.byte_range(),
        })
    }

    fn word(&self, n: TsNode) -> Word {
        let mut text = String::new();
        let mut literal = true;
        self.word_parts(n, &mut text, &mut literal);
        Word {
            text,
            span: n.byte_range(),
            literal,
        }
    }

    fn word_parts(&self, n: TsNode, out: &mut String, literal: &mut bool) {
        match n.kind() {
            "raw_string" => out.push_str(self.text(n).trim_matches('\'')),
            "ansi_c_string" => {
                out.push_str(self.text(n).trim_start_matches("$'").trim_end_matches('\''));
            }
            "string" => {
                if n.named_child_count() == 0 {
                    return;
                }
                for c in named_children(n) {
                    self.word_parts(c, out, literal);
                }
            }
            "concatenation" | "command_name" => {
                for c in named_children(n) {
                    self.word_parts(c, out, literal);
                }
            }
            "simple_expansion"
            | "expansion"
            | "command_substitution"
            | "process_substitution"
            | "arithmetic_expansion" => {
                *literal = false;
                out.push_str(self.text(n));
            }
            _ => out.push_str(self.text(n)),
        }
    }
}

/// `sudo [-flags] cmd args…` / `doas cmd …` / `$SUDO cmd …` -> `cmd args…` with `elevated` set.
fn strip_privilege_wrapper(cmd: &mut Command) {
    let wrapper = cmd.name == "sudo"
        || cmd.name == "doas"
        || (cmd.name.starts_with('$') && cmd.name.to_ascii_lowercase().contains("sudo"));
    if !wrapper {
        return;
    }
    let Some(at) = cmd
        .args
        .iter()
        .position(|w| !w.text.starts_with('-') && !w.text.contains('='))
    else {
        return;
    };
    let mut rest = cmd.args.split_off(at);
    cmd.name = rest.remove(0).text;
    cmd.args = rest;
    cmd.elevated = true;
}

fn named_children(n: TsNode) -> impl Iterator<Item = TsNode> {
    (0..n.named_child_count()).filter_map(move |i| n.named_child(i))
}
fn parse_tree(source: &str) -> Result<Tree> {
    parser()?
        .parse(source, None)
        .context("tree-sitter failed to parse the script")
}

/// Parses only `range` of `source` (e.g. a heredoc body fed to a shell); node offsets stay absolute.
fn parse_range(source: &str, range: std::ops::Range<usize>) -> Result<Tree> {
    let mut parser = parser()?;
    let ts_range = Range {
        start_byte: range.start,
        end_byte: range.end,
        start_point: point(source, range.start),
        end_point: point(source, range.end),
    };
    parser
        .set_included_ranges(&[ts_range])
        .context("invalid heredoc range")?;
    parser
        .parse(source, None)
        .context("tree-sitter failed to parse the heredoc body")
}

fn parser() -> Result<Parser> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .context("loading tree-sitter-bash grammar")?;
    Ok(parser)
}

fn point(source: &str, offset: usize) -> Point {
    let before = &source[..offset];
    let row = before.matches('\n').count();
    let column = before.rsplit('\n').next().map_or(0, str::len);
    Point { row, column }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmds(src: &str) -> Vec<Command> {
        parse(src).unwrap().commands().cloned().collect()
    }

    #[test]
    fn strips_quotes_and_tracks_literalness() {
        let c = &cmds(r#"curl -fsSL "https://x.io/$V" 'lit' plain"#)[0];
        assert_eq!(c.name, "curl");
        let texts: Vec<_> = c.arg_texts().collect();
        assert_eq!(texts, ["-fsSL", "https://x.io/$V", "lit", "plain"]);
        assert!(!c.args[1].literal);
        assert!(c.args[2].literal && c.args[3].literal);
    }

    #[test]
    fn descends_into_functions_and_pipelines() {
        let ctx = parse("f() {\n  curl -s https://a.io | bash\n}\nf\n").unwrap();
        let names: Vec<_> = ctx.commands().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["curl", "bash", "f"]);
        assert!(matches!(ctx.nodes[0], Node::Pipeline(ref p) if p.stages.len() == 2));
    }

    #[test]
    fn captures_substituted_commands() {
        let c = &cmds(r#"bash -c "$(curl -fsSL https://a.io/i.sh)""#)[0];
        assert_eq!(c.substitutions[0].name, "curl");
        let c = &cmds("bash <(wget -qO- https://a.io/i.sh)")[0];
        assert_eq!(c.substitutions[0].name, "wget");
        let c = &cmds("bash < <(curl -s https://a.io/i.sh)")[0];
        assert_eq!(c.substitutions[0].name, "curl");
    }

    #[test]
    fn marks_captured_commands() {
        let c = cmds("hash=$(sha256sum f)\nsha256sum g");
        assert!(c[0].captured && !c[1].captured);
    }

    #[test]
    fn sees_through_sudo() {
        let c = &cmds("sudo -E tee -a /etc/sudoers.d/x")[0];
        assert_eq!((c.name.as_str(), c.elevated), ("tee", true));
        assert_eq!(
            c.arg_texts().collect::<Vec<_>>(),
            ["-a", "/etc/sudoers.d/x"]
        );
        assert!(!cmds("sudo -v")[0].elevated);
        assert_eq!(cmds("$SUDO rm -rf /")[0].name, "rm");
        assert_eq!(cmds("${SUDO} apt-get install x")[0].name, "apt-get");
    }

    #[test]
    fn lowers_heredocs_fed_to_a_shell() {
        let src = "$SUDO bash <<SCRIPT\nURL=https://x.io/a\ncurl \"\\$URL\" | tar xz\nSCRIPT\ncat <<EOF\ncurl https://ignored.io | sh\nEOF\n";
        let ctx = parse(src).unwrap();
        let names: Vec<_> = ctx.commands().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["bash", "curl", "tar", "cat"]);
        let a = ctx.assignments().next().unwrap();
        assert_eq!(a.value.text, "https://x.io/a");
        assert_eq!(
            &src[a.span.clone()],
            "URL=https://x.io/a",
            "spans stay absolute"
        );
    }

    #[test]
    fn lowers_assignments() {
        let ctx = parse("URL=\"https://a.io\"\nexport X=1\n").unwrap();
        let a: Vec<_> = ctx
            .assignments()
            .map(|a| (a.name.as_str(), a.value.text.as_str()))
            .collect();
        assert_eq!(a, [("URL", "https://a.io"), ("X", "1")]);
    }
}
