use crate::parser::{Ctx, Word};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    Literal(String),
    /// Could not be determined statically; the raw text is kept for reporting.
    Dynamic(String),
}

pub fn resolve(word: &Word, ctx: &Ctx) -> Resolved {
    let text = if word.literal {
        word.text.clone()
    } else {
        fold(&word.text, &literal_vars(ctx))
    };
    if text.starts_with("https://") || text.starts_with("http://") {
        if text.contains('$') || text.contains('`') {
            Resolved::Dynamic(word.text.clone())
        } else {
            Resolved::Literal(text)
        }
    } else {
        Resolved::Dynamic(word.text.clone())
    }
}

/// Variables assigned exactly once to a value that folds to a static string
/// (`ROOT="${ROOT:-https://a.io}"` counts; `URL=$(compute)` and reassigned names do not).
pub(crate) fn literal_vars(ctx: &Ctx) -> HashMap<&str, Option<String>> {
    let mut vars: HashMap<&str, Option<String>> = HashMap::new();
    for a in ctx.assignments() {
        let folded = fold(&a.value.text, &vars);
        let value = (!folded.contains('$') && !folded.contains('`')).then_some(folded);
        vars.entry(a.name.as_str())
            .and_modify(|v| *v = None)
            .or_insert(value);
    }
    vars
}

/// Substitutes `$NAME` / `${NAME}` when `NAME` is known; leaves the rest untouched.
pub(crate) fn fold(text: &str, vars: &HashMap<&str, Option<String>>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find('$') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let (name, consumed) = if let Some(inner) = after.strip_prefix('{') {
            match inner.find('}') {
                Some(end) if inner[..end].chars().all(is_ident) => (&inner[..end], end + 2),
                // `${VAR:-default}` with VAR unset in the script folds to the default.
                Some(end) if inner[..end].contains(":-") => {
                    let (var, default) = inner[..end].split_once(":-").unwrap();
                    if var.chars().all(is_ident) && !vars.contains_key(var) {
                        out.push_str(&fold(default, vars));
                        rest = &rest[i + 1 + end + 2..];
                        continue;
                    }
                    ("", 0)
                }
                _ => ("", 0),
            }
        } else {
            let end = after.find(|c: char| !is_ident(c)).unwrap_or(after.len());
            (&after[..end], end)
        };
        match vars.get(name).and_then(|v| v.as_deref()) {
            Some(v) if !name.is_empty() => out.push_str(v),
            _ => out.push_str(&rest[i..i + 1 + consumed]),
        }
        rest = &rest[i + 1 + consumed..];
    }
    out.push_str(rest);
    out
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::detect::forwards;
    use crate::config::Shared;
    use crate::parser::parse;

    fn resolve_first(src: &str) -> Resolved {
        let ctx = parse(src).unwrap();
        let f = &forwards(&ctx, &Shared::default())[0];
        resolve(&f.url, &ctx)
    }

    #[test]
    fn folds_single_literal_assignments() {
        assert_eq!(
            resolve_first("BASE=https://a.io\nVER=v1\ncurl -s \"${BASE}/$VER/i.sh\" | bash"),
            Resolved::Literal("https://a.io/v1/i.sh".into())
        );
    }

    #[test]
    fn folds_default_expansions_for_unset_vars() {
        assert_eq!(
            resolve_first("ROOT=\"${INSTALL_ROOT:-https://a.io/x}\"\ncurl -s \"$ROOT/i.sh\" | sh"),
            Resolved::Literal("https://a.io/x/i.sh".into())
        );
        assert!(matches!(
            resolve_first("V=1\ncurl -s \"${V:-https://a.io}/i.sh\" | sh"),
            Resolved::Dynamic(_)
        ));
    }

    #[test]
    fn reassigned_or_computed_is_dynamic() {
        assert!(matches!(
            resolve_first("U=https://a.io\nU=https://b.io\ncurl -s $U | sh"),
            Resolved::Dynamic(_)
        ));
        assert!(matches!(
            resolve_first("U=$(get_url)\ncurl -s $U | sh"),
            Resolved::Dynamic(_)
        ));
        assert!(matches!(
            resolve_first("curl -s https://a.io/$(uname)/i | sh"),
            Resolved::Dynamic(_)
        ));
    }
}
