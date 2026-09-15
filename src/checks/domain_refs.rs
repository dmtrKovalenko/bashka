use crate::analysis::Flag;
use crate::config::{Recommended, Shared};
use crate::model::{Detail, Verdict};
use crate::parser::{Assignment, Command, Word};
use crate::register_flag;
use crate::url;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DomainRefsCfg {
    pub builtin_shorteners: bool,
    pub additional_shorteners: Vec<String>,
}

impl Default for DomainRefsCfg {
    fn default() -> Self {
        Self {
            builtin_shorteners: true,
            additional_shorteners: Vec::new(),
        }
    }
}

impl Recommended for DomainRefsCfg {
    fn recommended() -> Self {
        Self::default()
    }
}

const SHORTENERS: &[&str] = &[
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "tiny.cc",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "t.ly",
];

pub struct DomainRefs {
    shorteners: Vec<String>,
    shared: Shared,
    reported: HashSet<String>,
}

impl DomainRefs {
    fn problem(&self, u: &str) -> Option<(&'static str, &'static str)> {
        let host = url::host(u)?;
        if !url::is_https(u) {
            return Some((
                "plaintext HTTP download",
                "Anyone on the network path can replace the response body.",
            ));
        }
        if url::is_ip_host(&host) {
            return Some((
                "download from a raw IP address",
                "No domain means no accountable owner and no certificate name to check.",
            ));
        }
        if self.shorteners.iter().any(|s| url::host_matches(&host, s)) {
            return Some((
                "download through a URL shortener",
                "The real destination is hidden and can be changed at any time.",
            ));
        }
        None
    }
}

impl DomainRefs {
    fn scan<'a>(&mut self, words: impl Iterator<Item = &'a Word>) -> Verdict {
        for (word, u) in words.flat_map(|w| url::urls_in(&w.text).map(move |u| (w, u))) {
            if let Some((title, why)) = self
                .problem(u)
                .filter(|_| self.reported.insert(u.to_string()))
            {
                return Verdict::Red(Detail::new(format!("{title}: {u}"), why).at(url::locate(
                    &word.text,
                    word.span.start,
                    u,
                )));
            }
        }
        Verdict::Ignore
    }
}

impl Flag for DomainRefs {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if !self.shared.downloads(c) {
            return Verdict::Ignore;
        }
        self.scan(c.args.iter())
    }

    fn visit_assignment(&mut self, a: &Assignment) -> Verdict {
        self.scan(std::iter::once(&a.value))
    }
}

register_flag! {
    id: "domain_refs",
    kind: Red,
    category: Domain,
    description: "Non-HTTPS, raw-IP or URL-shortener download targets",
    config: DomainRefsCfg,
    build: |cfg, shared| DomainRefs {
        shared: shared.clone(),
        shorteners: cfg.additional_shorteners.into_iter()
            .chain(cfg.builtin_shorteners.then(|| SHORTENERS.iter().map(|s| s.to_string())).into_iter().flatten())
            .collect(),
        reported: HashSet::new(),
    },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn http_ip_and_shorteners() {
        assert!(fires("domain_refs", "curl -o x http://x.io/a"));
        assert!(fires("domain_refs", "wget -O x https://10.0.0.1/a"));
        assert!(fires("domain_refs", "curl -o x https://bit.ly/abc"));
        assert!(!fires("domain_refs", "curl -o x https://x.io/a"));
        assert!(!fires("domain_refs", "echo see http://x.io/docs"));
        assert!(fires("domain_refs", "MIRROR=http://mirror.example/x"));
        assert_eq!(
            titles(
                "domain_refs",
                "curl -o x http://x.io/a\ncurl -o y http://x.io/a"
            )
            .len(),
            1
        );
    }
}
