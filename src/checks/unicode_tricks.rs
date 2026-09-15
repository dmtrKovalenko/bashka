//! Red: command names or URLs that hide their true identity with invisible or look-alike characters.

use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::{Command, Ctx};
use crate::register_flag;

/// Bidi overrides and zero-width/format characters that never belong in a command or URL.
fn invisible_or_bidi(ch: char) -> bool {
    matches!(ch,
        '\u{200B}'..='\u{200F}' // zero-width space/joiners, LRM/RLM
        | '\u{202A}'..='\u{202E}' // bidi embeddings/overrides
        | '\u{2066}'..='\u{2069}' // bidi isolates
        | '\u{FEFF}'              // zero-width no-break space / BOM
        | '\u{00AD}'              // soft hyphen
        | '\u{2060}'              // word joiner
    )
}

/// A non-ASCII letter that has a confusable ASCII look-alike (Cyrillic/Greek homoglyphs).
fn confusable(ch: char) -> bool {
    matches!(ch,
        '\u{0430}'..='\u{044F}' // Cyrillic lowercase (а е о с р …)
        | '\u{0391}'..='\u{03C9}' // Greek letters
    )
}

pub struct UnicodeTricks {
    reported: bool,
}

impl UnicodeTricks {
    fn suspicious(text: &str) -> Option<&'static str> {
        if text.chars().any(invisible_or_bidi) {
            return Some("contains invisible or bidirectional-override characters");
        }
        if text.chars().any(confusable) {
            return Some("contains look-alike (homoglyph) characters");
        }
        None
    }
}

impl Flag for UnicodeTricks {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if self.reported {
            return Verdict::Ignore;
        }
        if let Some(why) = Self::suspicious(&c.name) {
            self.reported = true;
            return red(&c.name, why, c.span.clone());
        }
        for w in &c.args {
            if w.text.contains("://")
                && let Some(why) = Self::suspicious(&w.text)
            {
                self.reported = true;
                return red(&w.text, why, w.span.clone());
            }
        }
        Verdict::Ignore
    }

    fn finalize(&mut self, ctx: &Ctx) -> Verdict {
        if self.reported {
            return Verdict::Ignore;
        }
        // Punycode host in any URL is worth a look even outside a fetch.
        for u in ctx
            .commands()
            .flat_map(|c| c.args.iter())
            .chain(ctx.assignments().map(|a| &a.value))
        {
            for url in crate::url::urls_in(&u.text) {
                if let Some(h) = crate::url::host(url)
                    && h.split('.').any(|label| label.starts_with("xn--"))
                {
                    self.reported = true;
                    return Verdict::Red(
                        Detail::new(
                            format!("punycode (internationalized) domain in a URL: {url}"),
                            "Punycode hosts (`xn--…`) are how look-alike domains impersonate real ones.",
                        )
                        .fix("Decode the host and confirm it is the domain you expect.")
                        .at(u.span.clone()),
                    );
                }
            }
        }
        Verdict::Ignore
    }
}

fn red(text: &str, why: &'static str, span: crate::model::Span) -> Verdict {
    Verdict::Red(
        Detail::new(
            format!("`{text}` {why}"),
            "Invisible or look-alike characters make a command or URL read as something it is not, so review sees `curl github.com` while the shell runs something else.",
        )
        .fix("Do not run this; retype any command or URL you intend.")
        .at(span),
    )
}

register_flag! {
    id: "unicode_tricks",
    kind: Red,
    category: Obfuscation,
    description: "Invisible/bidi/homoglyph characters in a command name or URL, or a punycode host",
    config: NoConfig,
    build: |_cfg, _shared| UnicodeTricks { reported: false },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn flags_hidden_characters() {
        // Cyrillic 'с' (U+0441) instead of ASCII 'c'.
        assert!(fires(
            "unicode_tricks",
            "\u{0441}url https://github.com/o/r"
        ));
        // Zero-width space inside a URL.
        assert!(fires(
            "unicode_tricks",
            "curl https://git\u{200B}hub.com/o/r"
        ));
        assert!(fires(
            "unicode_tricks",
            "curl https://xn--80ak6aa92e.com/i.sh"
        ));
    }

    #[test]
    fn ignores_plain_ascii() {
        assert!(!fires(
            "unicode_tricks",
            "curl https://github.com/o/r | bash"
        ));
        assert!(
            !fires("unicode_tricks", "echo 'héllo world'"),
            "non-ascii in plain text args is fine"
        );
    }
}
