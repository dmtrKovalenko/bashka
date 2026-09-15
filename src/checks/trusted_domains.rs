use crate::analysis::Flag;
use crate::config::{Recommended, Shared};
use crate::model::{Detail, Verdict};
use crate::parser::{Assignment, Command, Word};
use crate::register_flag;
use crate::url;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A deliberately strict allowlist: GitHub is the universal code host, everything else is trusted
/// only when it matches the domain the script itself was fetched from (see the origin mechanism).
const PUBLISHER_DOMAINS: &[&str] = &["github.com", "githubusercontent.com"];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrustedDomainsCfg {
    /// Trust the curated list of known installer publishers.
    pub trust_publisher_domains: bool,
    pub additional_domains: Vec<String>,
}

impl Default for TrustedDomainsCfg {
    fn default() -> Self {
        Self {
            trust_publisher_domains: true,
            additional_domains: Vec::new(),
        }
    }
}

impl Recommended for TrustedDomainsCfg {
    fn recommended() -> Self {
        Self::default()
    }
}

pub struct TrustedDomains {
    domains: Vec<String>,
    shared: Shared,
    /// Host the script came from; downloads from the same publisher are trusted too.
    origin_host: Option<String>,
    reported: HashSet<String>,
}

impl TrustedDomains {
    fn new(cfg: TrustedDomainsCfg, shared: &Shared) -> Self {
        let mut domains = cfg.additional_domains;
        if cfg.trust_publisher_domains {
            domains.extend(
                PUBLISHER_DOMAINS
                    .iter()
                    .map(std::string::ToString::to_string),
            );
        }
        Self {
            domains,
            shared: shared.clone(),
            origin_host: None,
            reported: HashSet::new(),
        }
    }
}

impl TrustedDomains {
    fn scan<'a>(&mut self, words: impl Iterator<Item = &'a Word>) -> Verdict {
        for (word, u) in words.flat_map(|w| url::urls_in(&w.text).map(move |u| (w, u))) {
            let Some(host) = url::host(u) else { continue };
            if !url::is_https(u) {
                continue;
            }
            let why = if self.domains.iter().any(|d| url::host_matches(&host, d)) {
                Some(
                    "The host is on the allowlist of known installer publishers and TLS protects the transfer.",
                )
            } else if self
                .origin_host
                .as_deref()
                .is_some_and(|o| url::same_site(&host, o))
            {
                Some(
                    "The download comes from the same publisher domain as the script itself, over TLS.",
                )
            } else {
                None
            };
            if let Some(why) = why.filter(|_| self.reported.insert(host.clone())) {
                return Verdict::Green(
                    Detail::new(
                        format!("downloads from trusted publisher `{host}` over HTTPS"),
                        why,
                    )
                    .at(url::locate(&word.text, word.span.start, u)),
                );
            }
        }
        Verdict::Ignore
    }
}

impl Flag for TrustedDomains {
    fn begin(&mut self, ctx: &crate::parser::Ctx) {
        self.origin_host.clone_from(&ctx.origin_host);
    }

    fn visit_command(&mut self, c: &Command) -> Verdict {
        if !self.shared.downloads(c) {
            return Verdict::Ignore;
        }
        self.scan(c.args.iter())
    }

    /// Installers usually build the download URL in a variable first.
    fn visit_assignment(&mut self, a: &Assignment) -> Verdict {
        self.scan(std::iter::once(&a.value))
    }
}

register_flag! {
    id: "trusted_domains",
    kind: Green,
    category: Domain,
    description: "Downloads come from an allowlisted publisher host over HTTPS",
    config: TrustedDomainsCfg,
    build: |cfg, shared| TrustedDomains::new(cfg, shared),
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn trusts_publishers_over_https_once_per_host() {
        let src = "curl -fsSL https://raw.githubusercontent.com/a/b/i.sh -o x\ncurl https://raw.githubusercontent.com/c/d -o y\ncurl http://github.com/z -o z";
        assert_eq!(
            titles("trusted_domains", src).len(),
            1,
            "one per host, https only"
        );
        assert!(!fires(
            "trusted_domains",
            "echo https://github.com/not-a-download"
        ));
        assert!(!fires(
            "trusted_domains",
            "curl -fsSL https://evil-github.com/x -o y"
        ));
        assert!(fires(
            "trusted_domains",
            "git clone https://github.com/pyenv/pyenv.git"
        ));
        // Vanity publisher domains are NOT on the strict allowlist; only the origin mechanism trusts them.
        assert!(!fires(
            "trusted_domains",
            "curl -o x https://static.rust-lang.org/rustup/x"
        ));
        assert!(!fires(
            "trusted_domains",
            "curl -o x https://releases.openai.com/codex/codex.tgz"
        ));
    }

    #[test]
    fn trusts_the_scripts_own_publisher_domain() {
        use super::super::testing::findings_from;
        // A script served from get.acme.io downloading from acme.io / cdn.acme.io is self-consistent.
        assert_eq!(
            findings_from(
                "trusted_domains",
                "https://get.acme.io/install.sh",
                "curl -o x https://cdn.acme.io/tool.tgz"
            )
            .len(),
            1
        );
        assert_eq!(
            findings_from(
                "trusted_domains",
                "https://get.acme.io/install.sh",
                "curl -o x https://acme.io/tool.tgz"
            )
            .len(),
            1
        );
        // An unrelated host is still not trusted.
        assert_eq!(
            findings_from(
                "trusted_domains",
                "https://get.acme.io/install.sh",
                "curl -o x https://evil.io/tool.tgz"
            )
            .len(),
            0
        );
        // In pipe mode (no origin) only the allowlist applies.
        assert_eq!(
            findings_from(
                "trusted_domains",
                "<stdin>",
                "curl -o x https://cdn.acme.io/tool.tgz"
            )
            .len(),
            0
        );
    }
}
