pub mod detect;
pub mod net;
pub mod resolve;

use crate::analysis;
use crate::config::{Config, Descend};
use crate::interaction::Prompter;
use crate::parser;
use crate::report::Layer;
use crate::ui::{self, paint};
use anyhow::Result;
use resolve::Resolved;
use std::collections::HashSet;

pub struct Options<'a> {
    pub config: &'a Config,
    pub descend: Descend,
    pub max_depth: usize,
}

pub struct Analysis {
    pub layers: Vec<Layer>,
    /// sha256 of every layer analyzed ahead of time.
    pub vetted: Vec<String>,
    /// The chain has forwards: run with the `bash`/`sh` shim so every layer re-enters bashka
    /// at run time (vetted layers are recognized by hash; anything else is analyzed).
    pub needs_shim: bool,
}

pub fn analyze(
    source: String,
    label: String,
    depth: usize,
    opts: &Options,
    prompter: &mut Prompter,
) -> Result<Analysis> {
    let mut chain = Chain {
        opts,
        prompter,
        out: Analysis {
            layers: vec![],
            vetted: vec![],
            needs_shim: false,
        },
        visited: HashSet::new(),
    };
    chain.descend(source, label, depth)?;
    Ok(chain.out)
}

/// The interpreter named by the shebang when it is not something tree-sitter-bash can parse.
fn foreign_dialect(source: &str) -> Option<&str> {
    let shebang = source.lines().next()?.strip_prefix("#!")?;
    let interpreter = shebang
        .split_whitespace()
        .filter(|w| !w.starts_with('-'))
        .find(|w| !w.ends_with("/env"))?;
    let name = interpreter.rsplit('/').next()?;
    (!["sh", "bash", "zsh", "dash", "ksh", "ash"].contains(&name)).then_some(name)
}

struct Chain<'a, 'p> {
    opts: &'a Options<'a>,
    prompter: &'p mut Prompter,
    out: Analysis,
    visited: HashSet<String>,
}

impl Chain<'_, '_> {
    fn descend(&mut self, source: String, label: String, depth: usize) -> Result<()> {
        if let Some(shell) = foreign_dialect(&source) {
            self.note(&format!(
                "{label}: shebang `{shell}` is not a bash dialect; findings may be incomplete"
            ));
        }
        let mut ctx = parser::parse(&source)?;
        ctx.origin_host = crate::url::host(&label);
        ctx.origin = ctx.origin_host.is_some().then(|| label.clone());
        let mut flags = self.opts.config.build_flags()?;
        let findings = analysis::analyze(&ctx, &mut flags);
        let forwards = detect::forwards(&ctx, &self.opts.config.shared);
        self.out.vetted.push(crate::sha256(&source));
        self.out.layers.push(Layer {
            depth,
            label,
            source,
            findings,
        });
        self.out.needs_shim |= !forwards.is_empty();

        for fwd in forwards {
            match resolve::resolve(&fwd.url, &ctx) {
                Resolved::Literal(url) if self.opts.descend != Descend::Shim => {
                    self.follow(url, depth + 1)?;
                }
                Resolved::Literal(_) => {}
                Resolved::Dynamic(raw) => self.note(&format!(
                    "forward target `{raw}` is computed at run time; the shim will intercept it"
                )),
            }
        }
        Ok(())
    }

    fn follow(&mut self, url: String, depth: usize) -> Result<()> {
        if depth > self.opts.max_depth {
            self.note(&format!(
                "chain deeper than max_depth={}; `{url}` is left to the run-time shim",
                self.opts.max_depth
            ));
            return Ok(());
        }
        if !self.visited.insert(url.clone()) {
            self.note(&format!(
                "cycle: `{url}` was already analyzed in this chain"
            ));
            return Ok(());
        }
        let pre = self.opts.config.interaction.follow_remote.into();
        if pre == crate::interaction::Decision::Ask && !self.prompter.can_prompt() {
            self.note(&format!(
                "no terminal to ask about fetching `{url}`; left to the run-time shim"
            ));
            return Ok(());
        }
        if !self.prompter.decide(
            pre,
            &format!("Fetch and analyze forwarded script {url} ahead of time?"),
            true,
        )? {
            return Ok(());
        }
        let spinner = self
            .prompter
            .spinner(&format!("{} fetching {url}", self.prompter.icons.fetch));
        match net::fetch(&url) {
            Ok(body) => {
                spinner.finish(format!(
                    "{} fetched {url} ({} lines)",
                    self.prompter.icons.fetch,
                    body.lines().count()
                ));
                self.descend(body, url, depth)
            }
            Err(e) => {
                spinner.clear();
                self.note(&format!(
                    "could not fetch `{url}` ({e:#}); left to the run-time shim"
                ));
                Ok(())
            }
        }
    }

    fn note(&mut self, text: &str) {
        self.prompter
            .say(&format!("{} {text}\n", paint(ui::DIM, "chain:")));
    }
}
