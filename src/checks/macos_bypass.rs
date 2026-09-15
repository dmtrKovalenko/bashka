//! Red/Dead: macOS-specific defenses bypass and password phishing.

use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::Command;
use crate::register_flag;

fn base(name: &str) -> &str {
    crate::config::base_name(name)
}

pub struct MacosBypass {
    reported: bool,
}

impl Flag for MacosBypass {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if self.reported {
            return Verdict::Ignore;
        }
        let name = base(&c.name);
        let joined = c.arg_texts().collect::<Vec<_>>().join(" ");

        // osascript password phishing: a dialog with a hidden-answer field harvesting the login password.
        if name == "osascript" {
            let lower = joined.to_ascii_lowercase();
            if lower.contains("hidden answer") {
                self.reported = true;
                return Verdict::Dead(
                    Detail::new(
                        "shows a password dialog (`osascript … hidden answer`)",
                        "This is the standard macOS stealer trick: a fake system prompt that captures your login password.",
                    )
                    .fix("Do not run this. No installer needs to collect your password through a dialog box.")
                    .at(c.span.clone()),
                );
            }
            if lower.contains("with administrator privileges") {
                self.reported = true;
                return red(
                    "requests administrator privileges via osascript",
                    c.span.clone(),
                );
            }
        }
        // Gatekeeper quarantine strip on a downloaded file.
        let clears_all = c.has_arg("-c") || c.short_flags().any(|f| f == 'c');
        if name == "xattr"
            && (c.has_arg("-d") || c.short_flags().any(|f| f == 'd') || clears_all)
            && (joined.contains("com.apple.quarantine") || clears_all)
        {
            self.reported = true;
            return red(
                "strips the Gatekeeper quarantine flag (`xattr … com.apple.quarantine`)",
                c.span.clone(),
            );
        }
        // TCC privacy database tampering / reset.
        if (name == "sqlite3" && joined.contains("TCC.db"))
            || (name == "tccutil" && c.has_arg("reset"))
        {
            self.reported = true;
            return red("tampers with the TCC privacy database", c.span.clone());
        }
        // defaults write LSQuarantine off.
        if name == "defaults" && joined.contains("LSQuarantine") {
            self.reported = true;
            return red(
                "disables download quarantine (`defaults write … LSQuarantine`)",
                c.span.clone(),
            );
        }
        Verdict::Ignore
    }
}

fn red(what: &str, span: crate::model::Span) -> Verdict {
    Verdict::Red(
        Detail::new(
            what.to_string(),
            "Bypassing Gatekeeper, quarantine, or the privacy database lets downloaded code run without the checks macOS normally enforces.",
        )
        .fix("An installer distributed properly is notarized and does not need to strip these protections.")
        .at(span),
    )
}

register_flag! {
    id: "macos_bypass",
    kind: Red,
    category: Sensitive,
    description: "macOS: xattr quarantine strip, osascript admin/password dialog (dead), TCC.db/LSQuarantine tampering",
    config: NoConfig,
    build: |_cfg, _shared| MacosBypass { reported: false },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;
    use crate::model::FlagKind;

    #[test]
    fn flags_macos_bypasses() {
        assert_eq!(
            kind(
                "macos_bypass",
                "osascript -e 'display dialog \"Password:\" with hidden answer default answer \"\"'"
            ),
            Some(FlagKind::Dead)
        );
        assert!(fires(
            "macos_bypass",
            "xattr -d com.apple.quarantine /tmp/app"
        ));
        assert!(fires("macos_bypass", "xattr -rc /Applications/App.app"));
        assert!(fires(
            "macos_bypass",
            "osascript -e 'do shell script \"x\" with administrator privileges'"
        ));
        assert!(fires(
            "macos_bypass",
            "sqlite3 ~/Library/Application\\ Support/com.apple.TCC/TCC.db 'insert ...'"
        ));
    }

    #[test]
    fn ignores_benign() {
        assert!(!fires(
            "macos_bypass",
            "osascript -e 'display notification \"done\"'"
        ));
        assert!(!fires("macos_bypass", "xattr -l /tmp/x"));
    }
}
