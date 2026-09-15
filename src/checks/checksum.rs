use crate::analysis::Flag;
use crate::config::{NoConfig, Shared};
use crate::model::{Detail, Verdict};
use crate::parser::{Command, Ctx};
use crate::register_flag;

pub struct Checksum {
    shared: Shared,
    reported: bool,
    signed: bool,
}

/// `sha256sum -c SUMS`, or `got=$(sha256sum file)` whose output is compared by the script.
fn checks_digest(c: &Command) -> bool {
    match c.name.as_str() {
        "sha256sum" | "gsha256sum" | "sha512sum" | "shasum" | "b2sum" => {
            c.has_arg("-c") || c.has_arg("--check") || c.captured
        }
        "openssl" => c.has_arg("dgst") && c.captured,
        _ => false,
    }
}

impl Flag for Checksum {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        self.signed |= super::verify::verifies(c).is_some();
        if self.reported || !checks_digest(c) {
            return Verdict::Ignore;
        }
        self.reported = true;
        Verdict::Green(Detail::new(
            format!("checks a download digest with `{}`", c.name),
            "The downloaded artifact is hashed and compared against a published checksum before use.",
        ))
    }

    fn finalize(&mut self, ctx: &Ctx) -> Verdict {
        let downloads_files = ctx
            .commands()
            .any(|c| self.shared.is_network(&c.name) && !c.captured && c.urls().next().is_some());
        if self.reported || self.signed || !downloads_files {
            return Verdict::Ignore;
        }
        Verdict::Yellow(
            Detail::new(
                "downloads are never checksum- or signature-verified",
                "Whatever the server (or anyone between you and it) returns is used as-is.",
            )
            .fix("Publishers can ship a SHA256SUMS file next to releases and compare against it."),
        )
    }
}

register_flag! {
    id: "checksum",
    kind: Green,
    category: Remote,
    description: "Green: compares a checksum of downloads (sha256sum -c, $(shasum …)); yellow: downloads are unverified",
    config: NoConfig,
    build: |_cfg, shared| Checksum { shared: shared.clone(), reported: false, signed: false },
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;

    #[test]
    fn detects_checksum_checks() {
        assert!(fires("checksum", "sha256sum -c SHA256SUMS"));
        assert!(fires(
            "checksum",
            "got=$(shasum -a 256 \"$f\" | cut -d' ' -f1)"
        ));
        assert!(fires("checksum", "hash=$(openssl dgst -sha256 \"$f\")"));
        assert!(
            !fires("checksum", "sha256sum tool.tar.gz"),
            "printing a digest is not checking it"
        );
        assert!(!fires("checksum", "gpg --verify x.sig x"));
    }

    #[test]
    fn yellow_when_downloads_are_unverified() {
        use crate::model::FlagKind;
        assert_eq!(
            kind(
                "checksum",
                "curl -fsSL https://x.io/t.tgz -o t.tgz\ntar xzf t.tgz"
            ),
            Some(FlagKind::Yellow)
        );
        assert_eq!(
            kind(
                "checksum",
                "curl -fsSL https://x.io/t.tgz -o t.tgz\nsha256sum -c SUMS"
            ),
            Some(FlagKind::Green)
        );
        assert_eq!(
            kind(
                "checksum",
                "curl -fsSL https://x.io/t.tgz -o t.tgz\ngpg --verify t.sig t.tgz"
            ),
            None,
            "signed is fine"
        );
        assert_eq!(kind("checksum", "echo no downloads"), None);
    }
}
