use crate::analysis::registry;
use crate::config;
use crate::model::FlagKind;
use crate::ui::{self, paint};
use std::fmt::Write;

pub fn list_flags() -> String {
    let mut out = String::new();
    for reg in registry::all() {
        let kind = match reg.kind {
            FlagKind::Dead => paint(ui::RED, "dead  "),
            FlagKind::Red => paint(ui::RED, "red   "),
            FlagKind::Yellow => paint(ui::YELLOW, "yellow"),
            FlagKind::Green => paint(ui::GREEN, "green "),
        };
        let _ = writeln!(
            out,
            "{kind} {:<18} {:<12} default={:<5} weight={}",
            paint(ui::BOLD, reg.id),
            reg.category.name(),
            if reg.default_enabled { "on" } else { "off" },
            reg.weight
        );
        let _ = writeln!(out, "      {}", reg.description);
        let options = inline(&(reg.recommended)());
        if options != "{}" {
            let _ = writeln!(out, "      options: {}", paint(ui::DIM, &options));
        }
    }
    out
}

pub fn config_init() -> String {
    let mut out = config::DEFAULTS.trim_end().to_string();
    out.push_str("\n# Every flag: `true` (recommended options), `false` (off), or a table.\n");
    out.push_str(
        "# A partial table keeps `Default` for omitted fields, not the recommended values.\n",
    );
    for reg in registry::all() {
        let _ = writeln!(out, "\n# {}", reg.description);
        let options = inline(&(reg.recommended)());
        if options == "{}" {
            let _ = writeln!(out, "{} = true", reg.id);
        } else {
            let _ = writeln!(out, "{} = true\n# {} = {options}", reg.id, reg.id);
        }
    }
    out
}

/// Renders a TOML value as a single-line inline table.
fn inline(v: &toml::Value) -> String {
    match v {
        toml::Value::Table(t) => {
            let fields: Vec<String> = t
                .iter()
                .map(|(k, v)| format!("{k} = {}", inline(v)))
                .collect();
            if fields.is_empty() {
                "{}".into()
            } else {
                format!("{{ {} }}", fields.join(", "))
            }
        }
        toml::Value::Array(a) => {
            format!("[{}]", a.iter().map(inline).collect::<Vec<_>>().join(", "))
        }
        toml::Value::String(s) => format!("{s:?}"),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn generated_config_parses_and_is_complete() {
        let text = super::config_init();
        let cfg: crate::config::Config = toml::from_str(&text).unwrap();
        for reg in super::registry::all() {
            assert!(
                cfg.flags.contains_key(reg.id),
                "{} missing from config init",
                reg.id
            );
        }
        assert!(cfg.unknown_flags().is_empty());
        // Every commented example must itself be valid for its flag.
        for line in text
            .lines()
            .filter(|l| l.starts_with("# ") && l.contains(" = {"))
        {
            let table: toml::Table =
                toml::from_str(&line[2..]).unwrap_or_else(|e| panic!("{line}: {e}"));
            let (id, value) = table.into_iter().next().unwrap();
            let reg = super::registry::find(&id).unwrap();
            (reg.build)(Some(&value), &crate::config::Shared::default())
                .unwrap_or_else(|e| panic!("{id}: {e}"));
        }
    }
}
