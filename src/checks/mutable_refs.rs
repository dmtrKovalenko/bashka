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
pub struct MutableRefsCfg {
    /// Path segments that mean "whatever is current".
    pub refs: Vec<String>,
}

impl Default for MutableRefsCfg {
    fn default() -> Self {
        Self::recommended()
    }
}

impl Recommended for MutableRefsCfg {
    fn recommended() -> Self {
        Self {
            refs: [
                "master", "main", "HEAD", "trunk", "develop", "latest", "nightly",
            ]
            .map(String::from)
            .to_vec(),
        }
    }
}

pub struct MutableRefs {
    refs: Vec<String>,
    shared: Shared,
    reported: HashSet<String>,
}

impl MutableRefs {
    fn scan<'a>(&mut self, words: impl Iterator<Item = &'a Word>) -> Verdict {
        for (word, u) in words.flat_map(|w| url::urls_in(&w.text).map(move |u| (w, u))) {
            let path = u.split_once("://").map_or("", |(_, rest)| rest);
            let moving = path
                .split('/')
                .skip(1)
                .find(|seg| self.refs.iter().any(|r| r == seg));
            if let Some(r) = moving.filter(|_| self.reported.insert(u.to_string())) {
                return Verdict::Yellow(
                    Detail::new(
                        format!("downloads from a moving ref `{r}`: {u}"),
                        "The content can change at any time, so what you reviewed today is not what runs tomorrow.",
                    )
                    .fix("Prefer URLs that pin a release tag or commit.")
                    .at(url::locate(&word.text, word.span.start, u)),
                );
            }
        }
        Verdict::Ignore
    }
}

impl Flag for MutableRefs {
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
    id: "mutable_refs",
    kind: Yellow,
    category: Remote,
    description: "Downloads from master/main/HEAD/latest instead of a pinned version",
    config: MutableRefsCfg,
    build: |cfg, shared| MutableRefs { refs: cfg.refs, shared: shared.clone(), reported: HashSet::new() },
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;

    #[test]
    fn flags_moving_refs_once_per_url() {
        assert!(fires(
            "mutable_refs",
            "curl -o i https://raw.githubusercontent.com/o/r/master/install.sh"
        ));
        assert!(fires(
            "mutable_refs",
            "URL=https://github.com/o/r/releases/latest/download/t.tgz"
        ));
        assert!(!fires(
            "mutable_refs",
            "curl -o i https://raw.githubusercontent.com/o/r/v1.2.3/install.sh"
        ));
        assert!(
            !fires("mutable_refs", "curl -o i https://main.example.com/x"),
            "host names are not refs"
        );
        assert_eq!(
            titles(
                "mutable_refs",
                "curl -o a https://x.io/main/a\ncurl -o b https://x.io/main/a"
            )
            .len(),
            1
        );
    }
}
