use crate::analysis::Flag;
use crate::config::{Recommended, Shared};
use crate::model::{Detail, Verdict};
use crate::parser::{Assignment, Command, Ctx};
use crate::register_flag;
use crate::url;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManyDownloadsCfg {
    /// Distinct download URLs allowed before a yellow advisory.
    pub yellow_limit: usize,
    /// Distinct download URLs above which the script is treated as critically suspicious.
    pub dead_limit: usize,
}

impl Default for ManyDownloadsCfg {
    fn default() -> Self {
        Self::recommended()
    }
}

impl Recommended for ManyDownloadsCfg {
    fn recommended() -> Self {
        Self {
            yellow_limit: 2,
            dead_limit: 5,
        }
    }
}

pub struct ManyDownloads {
    yellow_limit: usize,
    dead_limit: usize,
    shared: Shared,
    urls: BTreeSet<String>,
}

impl ManyDownloads {
    fn collect(&mut self, words: impl Iterator<Item = String>) {
        self.urls
            .extend(words.flat_map(|t| url::urls_in(&t).map(String::from).collect::<Vec<_>>()));
    }
}

impl Flag for ManyDownloads {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if self.shared.downloads(c) {
            self.collect(c.args.iter().map(|w| w.text.clone()));
        }
        Verdict::Ignore
    }

    fn visit_assignment(&mut self, a: &Assignment) -> Verdict {
        self.collect(std::iter::once(a.value.text.clone()));
        Verdict::Ignore
    }

    fn finalize(&mut self, _ctx: &Ctx) -> Verdict {
        let n = self.urls.len();
        if n > self.dead_limit {
            return Verdict::Dead(
                Detail::new(
                    format!("downloads from {n} distinct URLs (more than {})", self.dead_limit),
                    "That many independent sources is far outside what an installer needs and is a hallmark of a stager pulling many payloads.",
                )
                .fix("Do not run this; review every URL it fetches first."),
            );
        }
        if n > self.yellow_limit {
            return Verdict::Yellow(Detail::new(
                format!(
                    "downloads from {n} distinct URLs (more than {})",
                    self.yellow_limit
                ),
                "Each source is a separate thing to trust; many of them widens the surface and makes the script harder to review.",
            ));
        }
        Verdict::Ignore
    }
}

register_flag! {
    id: "many_downloads",
    kind: Yellow,
    category: Remote,
    description: "Downloads from many distinct URLs: yellow above `yellow_limit` (2), dead above `dead_limit` (5)",
    config: ManyDownloadsCfg,
    build: |cfg, shared| ManyDownloads { yellow_limit: cfg.yellow_limit, dead_limit: cfg.dead_limit, shared: shared.clone(), urls: BTreeSet::new() },
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;

    #[test]
    fn yellow_above_two_dead_above_five() {
        use crate::model::FlagKind;
        assert!(
            !fires(
                "many_downloads",
                "curl -o a https://x.io/a\ncurl -o b https://x.io/b"
            ),
            "two is fine"
        );
        let urls = |n: usize| {
            (1..=n)
                .map(|i| format!("curl -o f https://x.io/{i}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(kind("many_downloads", &urls(3)), Some(FlagKind::Yellow));
        assert_eq!(kind("many_downloads", &urls(5)), Some(FlagKind::Yellow));
        assert_eq!(kind("many_downloads", &urls(6)), Some(FlagKind::Dead));
        // The same URL fetched twice counts once.
        assert!(!fires(
            "many_downloads",
            "curl -o a https://x.io/a\ncurl -o a https://x.io/a\ncurl -o a https://x.io/a"
        ));
        // Non-download URLs (echoed docs) are ignored.
        assert!(!fires(
            "many_downloads",
            "echo https://x.io/1 https://x.io/2 https://x.io/3"
        ));
    }
}
