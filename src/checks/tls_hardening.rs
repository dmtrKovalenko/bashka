use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::Command;
use crate::register_flag;

pub struct TlsHardening {
    reported: bool,
}

impl Flag for TlsHardening {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        let hardened = c.name == "curl"
            && c.arg_texts()
                .any(|a| a == "=https" || a == "--proto=https" || a == "--proto==https")
            && c.arg_texts()
                .any(|a| a.starts_with("--tlsv1.2") || a.starts_with("--tlsv1.3"));
        if self.reported || !hardened {
            return Verdict::Ignore;
        }
        self.reported = true;
        // Underline the actual hardening flag, not the whole `$(curl …)` word.
        let span = c
            .args
            .iter()
            .find(|w| w.text == "=https" || w.text.starts_with("--proto"))
            .map_or_else(|| c.span.clone(), |w| w.span.clone());
        Verdict::Green(
            Detail::new(
                "hardened TLS for downloads (`--proto '=https' --tlsv1.2`)",
                "curl refuses redirects to plaintext HTTP and old TLS versions, closing the usual downgrade tricks.",
            )
            .at(span),
        )
    }
}

register_flag! {
    id: "tls_hardening",
    kind: Green,
    category: Domain,
    description: "curl pins HTTPS-only and TLS 1.2+ (`--proto '=https' --tlsv1.2`)",
    config: NoConfig,
    build: |_cfg, _shared| TlsHardening { reported: false },
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;

    #[test]
    fn detects_hardened_curl() {
        assert!(fires(
            "tls_hardening",
            "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustup.sh"
        ));
        assert!(!fires(
            "tls_hardening",
            "curl --tlsv1.2 -sSf https://x.io -o x"
        ));
        assert!(!fires("tls_hardening", "curl -fsSL https://x.io -o x"));
    }
}
