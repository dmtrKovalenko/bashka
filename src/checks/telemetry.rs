use crate::analysis::Flag;
use crate::config::{NoConfig, Shared};
use crate::model::{Detail, Span, Verdict};
use crate::parser::{Assignment, Command, Ctx};
use crate::register_flag;
use crate::url;

struct PhoneHome {
    destination: String,
    span: Span,
    /// Machine details the request carries (`uname`, `hostname`, …).
    facts: Vec<&'static str>,
    /// The variable its guard tests, when that looks like a telemetry switch.
    opt_out: Option<String>,
    /// The argument text, to spot a persistent identifier in it.
    body: String,
}

pub struct Telemetry {
    shared: Shared,
    home: Option<PhoneHome>,
    /// Where a generated identifier went: the file it was written to, or `$NAME` / `${NAME`
    /// for the variable it was assigned to. A request that mentions it is correlated.
    identifier: Vec<String>,
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

const FINGERPRINTS: &[(&str, &str)] = &[
    ("uname", "OS and architecture"),
    ("hostname", "hostname"),
    ("whoami", "user name"),
    ("id -u", "user id"),
    ("sw_vers", "macOS version"),
    ("lsb_release", "distro"),
    ("ifconfig", "network interfaces"),
    ("ip addr", "network interfaces"),
];

/// Fragments of variable names that switch reporting off: `BEND_NO_TELEMETRY`, `DO_NOT_TRACK`.
const OPT_OUT_HINTS: &[&str] = &[
    "TELEMETRY",
    "ANALYTICS",
    "DO_NOT_TRACK",
    "TRACKING",
    "NO_TRACK",
    "OPT_OUT",
    "OPTOUT",
    "NO_STATS",
    "METRICS",
];

/// The guard around the request that looks like a telemetry switch: the request only runs
/// under a condition testing `BEND_NO_TELEMETRY`, `DO_NOT_TRACK`, and the like.
fn opt_out_variable(c: &Command) -> Option<String> {
    c.guards
        .iter()
        .find(|name| {
            let upper = name.to_ascii_uppercase();
            OPT_OUT_HINTS.iter().any(|h| upper.contains(h))
        })
        .cloned()
}

/// Options whose value is the next word, so that word is never the destination.
fn takes_value(tool: &str, opt: &str) -> bool {
    match tool {
        "curl" => matches!(
            opt,
            "-X" | "--request"
                | "-d"
                | "--data"
                | "--data-raw"
                | "--data-binary"
                | "--data-urlencode"
                | "--json"
                | "-F"
                | "--form"
                | "--form-string"
                | "-H"
                | "--header"
                | "-o"
                | "--output"
                | "-A"
                | "--user-agent"
                | "-e"
                | "--referer"
                | "-b"
                | "--cookie"
                | "-c"
                | "--cookie-jar"
                | "-T"
                | "--upload-file"
                | "-w"
                | "--write-out"
                | "-u"
                | "--user"
                | "-x"
                | "--proxy"
                | "-E"
                | "--cert"
                | "--key"
                | "--cacert"
                | "--capath"
                | "--resolve"
                | "--max-time"
                | "--connect-timeout"
                | "--retry"
                | "--retry-delay"
                | "--max-redirs"
        ),
        "wget" => matches!(
            opt,
            "-O" | "--output-document"
                | "-P"
                | "--directory-prefix"
                | "-o"
                | "--output-file"
                | "-a"
                | "--append-output"
                | "-U"
                | "--user-agent"
                | "-T"
                | "--timeout"
                | "-t"
                | "--tries"
                | "--header"
                | "--post-data"
                | "--post-file"
                | "--body-data"
                | "--body-file"
                | "--method"
        ),
        _ => false,
    }
}

/// The request's positional operands: option values (`-d body`, `-H hdr`) are dropped, and an
/// explicit `--url X` counts as one.
fn operands(c: &Command) -> Vec<&str> {
    let tool = crate::config::base_name(&c.name);
    let args: Vec<&str> = c.arg_texts().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a == "--url" || a == "--" {
            if let Some(v) = args.get(i + 1) {
                out.push(*v);
            }
            i += 2;
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            i += if takes_value(tool, a) && args.get(i + 1).is_some() {
                2
            } else {
                1
            };
            continue;
        }
        out.push(a);
        i += 1;
    }
    out
}

/// A writing request: `-d`/`--data*`/`-F`/`--form` (separate or attached, `--data=x`),
/// `-X POST`/`-XPOST`/`--request=PUT`, or wget's `--post-*`/`--method=POST`.
fn uploads(c: &Command) -> bool {
    let args: Vec<&str> = c.arg_texts().collect();
    let writing = |m: &str| matches!(m.to_ascii_uppercase().as_str(), "POST" | "PUT" | "PATCH");
    match crate::config::base_name(&c.name) {
        "curl" => args.iter().enumerate().any(|(i, a)| {
            let (opt, attached) = a.split_once('=').map_or((*a, None), |(o, v)| (o, Some(v)));
            match opt {
                "-d" | "--data" | "--data-raw" | "--data-binary" | "--data-urlencode"
                | "--json" | "-F" | "--form" | "--form-string" => true,
                // `-X HEAD` / `-X GET` probe; only a writing method counts.
                "-X" | "--request" => attached
                    .or_else(|| args.get(i + 1).copied())
                    .is_some_and(writing),
                _ => {
                    (a.starts_with("-d") && !a.starts_with("--"))
                        || (a.starts_with("-X") && !a.starts_with("--") && writing(&a[2..]))
                }
            }
        }),
        "wget" => args.iter().any(|a| {
            a.starts_with("--post-data")
                || a.starts_with("--post-file")
                || a.starts_with("--body-")
                || a.strip_prefix("--method=").is_some_and(writing)
                || (*a == "--method"
                    && args
                        .iter()
                        .skip_while(|x| *x != a)
                        .nth(1)
                        .is_some_and(|m| writing(m)))
        }),
        _ => false,
    }
}

/// `analytics.x.io/collect`, `x.io/install-event`: a hint as a whole host label or path word.
/// Expansions are dropped first so `pkgs.x.com/$TRACK/…` does not read as tracking.
fn looks_like_telemetry(url: &str) -> bool {
    let mut stripped = String::new();
    let mut rest = url;
    while let Some(i) = rest.find('$') {
        stripped.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let len = if after.starts_with('{') {
            after.find('}').map_or(after.len(), |j| j + 1)
        } else {
            after
                .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                .unwrap_or(after.len())
        };
        rest = &after[len..];
    }
    stripped.push_str(rest);
    stripped
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|word| HINTS.contains(&word))
}

/// Where the request goes: the host of the positional URL, else the `$ORIGIN/ping`-style
/// operand. Option values never count, so a URL inside `-d 'callback=https://…'` is ignored.
fn destination(c: &Command) -> Option<String> {
    let sends = uploads(c);
    for operand in operands(c) {
        if let Some(u) = url::urls_in(operand).next() {
            if sends || looks_like_telemetry(u) {
                return Some(url::host(u).unwrap_or_else(|| u.to_string()));
            }
            continue;
        }
        if sends && (operand.contains('$') || operand.contains('/')) {
            return Some(operand.to_string());
        }
    }
    None
}

fn fingerprints(c: &Command) -> Vec<&'static str> {
    let mut out = Vec::new();
    for w in &c.args {
        for (probe, what) in FINGERPRINTS {
            let sub = format!("$({probe}");
            let tick = format!("`{probe}");
            if (w.text.contains(&sub) || w.text.contains(&tick)) && !out.contains(what) {
                out.push(*what);
            }
        }
    }
    out
}

/// `uuidgen`, `cat /proc/sys/kernel/random/uuid`: an installer has no other reason to mint a UUID.
fn mints_identifier(c: &Command) -> bool {
    match crate::config::base_name(&c.name) {
        "uuidgen" => true,
        "cat" | "head" => c
            .arg_texts()
            .any(|a| a.ends_with("/proc/sys/kernel/random/uuid")),
        _ => false,
    }
}

/// The file a minted identifier is redirected into (`uuidgen > "$B/id"`, group redirects included).
fn identifier_store(c: &Command) -> Option<String> {
    if !mints_identifier(c) || c.captured {
        return None;
    }
    c.redirects
        .iter()
        .map(|w| w.text.clone())
        .find(|t| !t.is_empty() && t != "/dev/null" && !t.starts_with('&'))
}

impl Flag for Telemetry {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if let Some(path) = identifier_store(c) {
            self.identifier.push(path);
        }
        if self.home.is_none()
            && self.shared.is_network(&c.name)
            && let Some(dest) = destination(c)
        {
            self.home = Some(PhoneHome {
                destination: dest,
                span: c.span.clone(),
                facts: fingerprints(c),
                opt_out: opt_out_variable(c),
                body: c.arg_texts().collect::<Vec<_>>().join(" "),
            });
        }
        Verdict::Ignore
    }

    /// `id=$(uuidgen)`, `ID=$(cat /proc/sys/kernel/random/uuid)`: the identifier lives in `$id`.
    fn visit_assignment(&mut self, a: &Assignment) -> Verdict {
        let v = &a.value.text;
        if v.contains("uuidgen") || v.contains("/proc/sys/kernel/random/uuid") {
            self.identifier.push(format!("${}", a.name));
            self.identifier.push(format!("${{{}", a.name));
        }
        Verdict::Ignore
    }

    fn finalize(&mut self, _ctx: &Ctx) -> Verdict {
        let Some(PhoneHome {
            destination: dest,
            span,
            facts,
            opt_out,
            body,
        }) = self.home.take()
        else {
            return Verdict::Ignore;
        };
        let identified = self.identifier.iter().any(|id| body.contains(id.as_str()));
        let mut title = format!("phones home to `{dest}`");
        if !facts.is_empty() {
            title.push_str(" with your ");
            title.push_str(&facts.join(", "));
        }
        let mut explanation = String::from(
            "The installer reports something about you or this machine, check what is sent and whether it can be disabled.",
        );
        if identified {
            title.push_str(" under a persistent identifier");
            explanation.push_str(
                " A generated id is written to disk, so every later report from this machine can be linked together.",
            );
        }
        let fix = match &opt_out {
            Some(var) => {
                title.push_str(" (gated by `");
                title.push_str(var);
                title.push_str("`)");
                format!(
                    "Sending is conditional on `{var}`. Read that test to see which value turns it off, then give it to the script through bashka: `curl … | {var}=… bashka`, or `export {var}=…` first. Setting it on `curl` alone does nothing."
                )
            }
            None => {
                "Nothing guards this request, so the report is sent unconditionally.".to_string()
            }
        };
        Verdict::Red(Detail::new(title, explanation).fix(fix).at(span))
    }
}

register_flag! {
    id: "telemetry",
    kind: Red,
    category: Remote,
    description: "Sends data out (POST/--data, or telemetry/analytics URLs), fingerprints the machine, or saves a tracking id",
    config: NoConfig,
    build: |_cfg, shared| Telemetry { shared: shared.clone(), home: None, identifier: Vec::new() },
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

    #[test]
    fn keywords_must_be_whole_words_outside_expansions() {
        assert!(!fires(
            "telemetry",
            "curl -fsSL \"https://pkgs.tailscale.com/$TRACK/$OS/$VERSION/tailscale.repo\" > /etc/yum.repos.d/tailscale.repo"
        ));
        assert!(!fires(
            "telemetry",
            "curl -fsSL https://x.io/tracker-tool/latest.tgz -o t.tgz"
        ));
        assert!(fires(
            "telemetry",
            "curl -fsSL \"https://x.io/ping?v=$VERSION\""
        ));
    }

    #[test]
    fn sees_through_variable_destinations() {
        let t = titles(
            "telemetry",
            "O=${ORIGIN:-https://x.io}\ncurl -s --max-time 3 -H 'Content-Type: application/json' \"$O/ping\" -d \"{\\\"os\\\":\\\"$(uname -s)\\\",\\\"arch\\\":\\\"$(uname -m)\\\"}\"",
        );
        assert_eq!(
            t,
            ["phones home to `$O/ping` with your OS and architecture"]
        );
        assert!(!fires(
            "telemetry",
            "curl -fsSL \"$BASE/$VERSION/tool.tgz\" -o t.tgz"
        ));
        assert!(
            !fires("telemetry", "curl -o /dev/null -fsLI -X HEAD \"$1\""),
            "a HEAD probe sends nothing"
        );
    }

    #[test]
    fn names_the_opt_out_variable() {
        let f = findings(
            "telemetry",
            "[ -n \"${BEND_NO_TELEMETRY:-}\" ] || curl -d \"os=$(uname -s)\" https://x.io/ping",
        );
        assert_eq!(
            f[0].detail.title,
            "phones home to `x.io` with your OS and architecture (gated by `BEND_NO_TELEMETRY`)"
        );
        assert!(
            f[0].detail
                .fix
                .as_deref()
                .unwrap()
                .contains("| BEND_NO_TELEMETRY=… bashka")
        );
        let f = findings("telemetry", "curl -d \"os=$OS\" https://x.io/ping");
        assert!(
            f[0].detail
                .fix
                .as_deref()
                .unwrap()
                .contains("Nothing guards")
        );
        let f = findings(
            "telemetry",
            "NO_TELEMETRY=${NO_TELEMETRY:-0}\ncurl -d \"os=$OS\" https://x.io/ping",
        );
        assert!(
            f[0].detail
                .fix
                .as_deref()
                .unwrap()
                .contains("Nothing guards"),
            "a variable that is mentioned but never tested around the request is no opt-out"
        );
        let f = findings("telemetry", "curl -d x \"$TELEMETRY_URL/ping\"");
        assert!(
            !f[0].detail.title.contains("gated by"),
            "a variable that only picks the destination is no opt-out"
        );
        let f = findings(
            "telemetry",
            "[ \"$SEND_TELEMETRY\" = 1 ] && curl -d x https://x.io/ping",
        );
        assert!(f[0].detail.title.contains("(gated by `SEND_TELEMETRY`)"));
        assert!(
            !f[0].detail.fix.as_deref().unwrap().contains("=1"),
            "polarity is not inferred from the name"
        );
    }

    #[test]
    fn attached_option_values_count_as_uploads() {
        for script in [
            "curl --data=os=linux https://x.io/i",
            "curl --data-raw='{}' https://x.io/i",
            "curl --form=f=1 https://x.io/i",
            "curl --request=POST https://x.io/i",
            "curl -XPOST https://x.io/i",
            "wget --method=POST --body-data=x https://x.io/i",
        ] {
            assert!(fires("telemetry", script), "{script}");
        }
        assert!(!fires("telemetry", "curl -XGET https://x.io/i"));
        assert!(!fires("telemetry", "curl --request=HEAD https://x.io/i"));
    }

    #[test]
    fn destination_is_the_positional_url_not_the_payload() {
        assert_eq!(
            titles(
                "telemetry",
                "curl -d 'callback=https://user.example/x' https://api.example/ping"
            ),
            ["phones home to `api.example`"]
        );
        assert_eq!(
            titles(
                "telemetry",
                "curl -H 'X-Site: https://analytics.example' -o out https://cdn.example/tool.tgz"
            ),
            Vec::<String>::new(),
            "a hint inside a header value is not the destination"
        );
        assert_eq!(
            titles("telemetry", "curl -d x --url https://x.io/ping"),
            ["phones home to `x.io`"]
        );
    }

    #[test]
    fn notes_a_persistent_identifier() {
        let t = titles(
            "telemetry",
            "{ cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen; } > \"$B/id\"\ncurl -d \"id=$(cat \"$B/id\")\" https://x.io/ping",
        );
        assert_eq!(t, ["phones home to `x.io` under a persistent identifier"]);
        assert!(
            !fires("telemetry", "uuidgen > \"$B/id\""),
            "an id that is never sent is not telemetry"
        );
        let t = titles(
            "telemetry",
            "uuidgen > build-id\ncurl -d x https://analytics.example/ping",
        );
        assert_eq!(
            t,
            ["phones home to `analytics.example`"],
            "an id the request never mentions is unrelated"
        );
        let t = titles(
            "telemetry",
            "ID=$(cat /proc/sys/kernel/random/uuid)\ncurl -d \"id=${ID}\" https://x.io/ping",
        );
        assert_eq!(t, ["phones home to `x.io` under a persistent identifier"]);
        let t = titles(
            "telemetry",
            "{ cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen; } > \"$B/id\"\ncurl -d \"id=$(cat \"$B/id\")\" https://x.io/ping",
        );
        assert_eq!(t, ["phones home to `x.io` under a persistent identifier"]);
    }
}
