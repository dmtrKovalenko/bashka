use crate::analysis::Flag;
use crate::config::{NoConfig, Shared};
use crate::model::{Detail, Verdict};
use crate::parser::Ctx;
use crate::register_flag;
use crate::url;
use std::collections::BTreeSet;

pub struct HttpsOnly {
    shared: Shared,
}

impl Flag for HttpsOnly {
    fn finalize(&mut self, ctx: &Ctx) -> Verdict {
        let from_downloads = ctx
            .commands()
            .filter(|c| self.shared.downloads(c))
            .flat_map(|c| c.urls());
        let from_assignments = ctx.assignments().flat_map(|a| url::urls_in(&a.value.text));
        let urls: Vec<&str> = from_downloads.chain(from_assignments).collect();
        if urls.is_empty() || !urls.iter().all(|u| url::is_https(u)) {
            return Verdict::Ignore;
        }
        let hosts: BTreeSet<String> = urls.iter().filter_map(|u| url::host(u)).collect();
        let list = hosts.into_iter().collect::<Vec<_>>().join(", ");
        Verdict::Green(Detail::new(
            format!("all {} download URL(s) use HTTPS ({list})", urls.len()),
            "Nothing is fetched over plaintext HTTP, so a network attacker cannot swap the payload in transit.",
        ))
    }
}

register_flag! {
    id: "https_only",
    kind: Green,
    category: Domain,
    description: "Every download URL in the script uses HTTPS",
    config: NoConfig,
    build: |_cfg, shared| HttpsOnly { shared: shared.clone() },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn requires_every_download_to_be_https() {
        assert!(fires(
            "https_only",
            "curl -o a https://x.io/a\nwget -O b https://y.io/b"
        ));
        assert!(!fires(
            "https_only",
            "curl -o a https://x.io/a\ncurl -o b http://y.io/b"
        ));
        assert!(!fires("https_only", "echo no downloads here"));
        assert!(fires(
            "https_only",
            "URL=\"https://x.io/v${V}/a\"\ncurl -o a \"$URL\""
        ));
        assert!(!fires(
            "https_only",
            "URL=\"http://x.io/a\"\ncurl -o a \"$URL\""
        ));
    }
}
