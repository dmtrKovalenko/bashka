use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::{Assignment, Command};
use crate::register_flag;

pub struct InsecureTls;

fn disables_verification(c: &Command) -> Option<&'static str> {
    match c.name.as_str() {
        "curl" if c.short_flags().any(|f| f == 'k') || c.has_arg("--insecure") => {
            Some("curl --insecure")
        }
        "wget" if c.has_arg("--no-check-certificate") => Some("wget --no-check-certificate"),
        "pip" | "pip3" if c.arg_texts().any(|a| a.starts_with("--trusted-host")) => {
            Some("pip --trusted-host")
        }
        "git" if c.arg_texts().any(|a| a.contains("sslVerify=false")) => {
            Some("git sslVerify=false")
        }
        _ => None,
    }
}

fn red(what: &str, span: crate::model::Span) -> Verdict {
    Verdict::Red(
        Detail::new(
            format!("TLS certificate verification disabled ({what})"),
            "Any machine on the network path can impersonate the download server and hand you a different file.",
        )
        .at(span),
    )
}

impl Flag for InsecureTls {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        disables_verification(c).map_or(Verdict::Ignore, |what| red(what, c.span.clone()))
    }

    fn visit_assignment(&mut self, a: &Assignment) -> Verdict {
        let off = matches!(
            a.name.as_str(),
            "GIT_SSL_NO_VERIFY"
                | "NODE_TLS_REJECT_UNAUTHORIZED"
                | "PYTHONHTTPSVERIFY"
                | "CURL_INSECURE"
        ) && matches!(a.value.text.as_str(), "1" | "true" | "0" | "yes");
        if off {
            red(&format!("{}={}", a.name, a.value.text), a.span.clone())
        } else {
            Verdict::Ignore
        }
    }
}

register_flag! {
    id: "insecure_tls",
    kind: Red,
    category: Domain,
    description: "curl -k, wget --no-check-certificate, GIT_SSL_NO_VERIFY and friends",
    weight: 2,
    config: NoConfig,
    build: |_cfg, _shared| InsecureTls,
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;

    #[test]
    fn detects_disabled_verification() {
        assert!(fires("insecure_tls", "curl -fsSLk https://x.io/i -o i"));
        assert!(fires(
            "insecure_tls",
            "wget --no-check-certificate https://x.io/i"
        ));
        assert!(fires("insecure_tls", "export GIT_SSL_NO_VERIFY=true"));
        assert!(!fires("insecure_tls", "curl -fsSL https://x.io/i -o i"));
    }
}
