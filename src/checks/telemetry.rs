use crate::analysis::Flag;
use crate::config::{NoConfig, Shared};
use crate::model::{Detail, Verdict};
use crate::parser::Command;
use crate::register_flag;
use crate::url;

pub struct Telemetry {
    shared: Shared,
    reported: bool,
}

const HINTS: &[&str] = &[
    "telemetry",
    "analytics",
    "metrics",
    "track",
    "beacon",
    "collect",
    "stats",
    "event",
    "ping",
];

fn uploads(c: &Command) -> bool {
    match c.name.as_str() {
        "curl" => c.arg_texts().any(|a| {
            matches!(
                a,
                "-X" | "--request"
                    | "-d"
                    | "--data"
                    | "--data-raw"
                    | "--data-binary"
                    | "-F"
                    | "--form"
            ) || a.starts_with("-d")
        }),
        "wget" => c
            .arg_texts()
            .any(|a| a.starts_with("--post-data") || a.starts_with("--post-file")),
        _ => false,
    }
}

impl Flag for Telemetry {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if self.reported || !self.shared.is_network(&c.name) {
            return Verdict::Ignore;
        }
        let Some(u) = c
            .urls()
            .find(|u| uploads(c) || HINTS.iter().any(|h| u.to_ascii_lowercase().contains(h)))
        else {
            return Verdict::Ignore;
        };
        self.reported = true;
        let host = url::host(u).unwrap_or_else(|| u.to_string());
        Verdict::Yellow(
            Detail::new(
                format!("phones home to `{host}`"),
                "The installer reports something about you or this machine; check what is sent and whether it can be disabled.",
            )
            .at(c.span.clone()),
        )
    }
}

register_flag! {
    id: "telemetry",
    kind: Yellow,
    category: Remote,
    description: "Sends data out (POST/--data, or telemetry/analytics URLs)",
    config: NoConfig,
    build: |_cfg, shared| Telemetry { shared: shared.clone(), reported: false },
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;

    #[test]
    fn detects_uploads_and_analytics_urls() {
        assert!(fires(
            "telemetry",
            "curl -s -X POST -d \"os=$OS\" https://x.io/install-event"
        ));
        assert!(fires(
            "telemetry",
            "curl -fsSL https://analytics.x.io/collect?v=1 -o /dev/null"
        ));
        assert!(!fires(
            "telemetry",
            "curl -fsSL https://x.io/releases/t.tgz -o t.tgz"
        ));
    }
}
