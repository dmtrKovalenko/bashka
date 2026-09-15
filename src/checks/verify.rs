use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::Command;
use crate::register_flag;

pub struct Verify {
    reported: bool,
}

pub(super) fn verifies(c: &Command) -> Option<&'static str> {
    let has = |a: &str| c.has_arg(a);
    match c.name.as_str() {
        "gpg" | "gpg2" | "gpgv" if has("--verify") || c.name == "gpgv" => Some("GPG"),
        "cosign" if has("verify") || has("verify-blob") => Some("cosign"),
        "minisign" if c.short_flags().any(|f| f == 'V') => Some("minisign"),
        "openssl" if has("dgst") && has("-verify") => Some("OpenSSL"),
        _ => None,
    }
}

impl Flag for Verify {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        let Some(tool) = verifies(c).filter(|_| !self.reported) else {
            return Verdict::Ignore;
        };
        self.reported = true;
        Verdict::Green(Detail::new(
            format!("verifies a {tool} signature"),
            "Downloaded artifacts are checked against the publisher's signing key, which a digest from the same server cannot prove.",
        ))
    }
}

register_flag! {
    id: "verify",
    kind: Green,
    category: Remote,
    description: "Verifies signatures with gpg --verify, cosign, minisign or openssl dgst -verify",
    config: NoConfig,
    build: |_cfg, _shared| Verify { reported: false },
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;

    #[test]
    fn detects_signature_checks() {
        assert!(fires("verify", "gpg --verify tool.tar.gz.sig tool.tar.gz"));
        assert!(fires("verify", "cosign verify-blob --signature s tool"));
        assert!(fires("verify", "minisign -Vm tool -P key"));
        assert!(
            !fires("verify", "sha256sum -c SHA256SUMS"),
            "digests belong to `checksum`"
        );
    }
}
