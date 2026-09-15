use crate::config::{Shared, Toggle};
use crate::model::{Category, FlagKind, Verdict};
use crate::parser::{Assignment, Command, Ctx, Pipeline};
use anyhow::Result;

/// A stateful visitor over one lowered script.
pub trait Flag {
    /// Called once before the walk; lets a flag read the script's origin from `Ctx`.
    fn begin(&mut self, _ctx: &Ctx) {}
    fn visit_command(&mut self, _c: &Command) -> Verdict {
        Verdict::Ignore
    }
    fn visit_pipeline(&mut self, _p: &Pipeline) -> Verdict {
        Verdict::Ignore
    }
    fn visit_assignment(&mut self, _a: &Assignment) -> Verdict {
        Verdict::Ignore
    }
    /// Called once after the walk; for accumulators.
    fn finalize(&mut self, _ctx: &Ctx) -> Verdict {
        Verdict::Ignore
    }
}

pub type BuildFn = fn(Option<&toml::Value>, &Shared) -> Result<Option<Box<dyn Flag>>>;

pub struct FlagRegistration {
    pub id: &'static str,
    pub kind: FlagKind,
    pub category: Category,
    pub description: &'static str,
    pub default_enabled: bool,
    pub weight: u8,
    /// Resolves this flag's `[flags.<id>]` value and builds it, or `None` when disabled.
    pub build: BuildFn,
    /// The recommended options as TOML, for `config init` and `flags`.
    pub recommended: fn() -> toml::Value,
}

inventory::collect!(FlagRegistration);

/// All registered flags, sorted by id.
pub fn all() -> Vec<&'static FlagRegistration> {
    let mut regs: Vec<_> = inventory::iter::<FlagRegistration>.into_iter().collect();
    regs.sort_by_key(|r| r.id);
    regs
}

pub fn find(id: &str) -> Option<&'static FlagRegistration> {
    inventory::iter::<FlagRegistration>
        .into_iter()
        .find(|r| r.id == id)
}

/// Generic body of a `build` fn: absent ⇒ recommended/off per `default_enabled`,
/// `true` ⇒ recommended, `false` ⇒ off, table ⇒ custom.
pub fn resolve_toggle<C>(raw: Option<&toml::Value>, default_enabled: bool) -> Result<Option<C>>
where
    C: crate::config::Recommended + serde::de::DeserializeOwned,
{
    Ok(match raw {
        None if default_enabled => Some(C::recommended()),
        None => None,
        Some(v) => v.clone().try_into::<Toggle<C>>()?.into_option(),
    })
}

/// Registers a flag. Usage:
/// ```ignore
/// register_flag! {
///     id: "max_commands", kind: Red, category: Complexity,
///     description: "…",
///     config: MaxCommandsCfg,
///     build: |cfg, shared| MaxCommands::new(cfg, shared),
/// }
/// ```
/// Optional keys: `default_enabled: bool` (default `true`), `weight: u8` (default `1`).
#[macro_export]
macro_rules! register_flag {
    (
        id: $id:literal,
        kind: $kind:ident,
        category: $cat:ident,
        description: $desc:literal,
        $(default_enabled: $enabled:literal,)?
        $(weight: $weight:literal,)?
        config: $cfg:ty,
        build: |$cfg_arg:ident, $shared_arg:ident| $build:expr $(,)?
    ) => {
        inventory::submit! {
            $crate::analysis::FlagRegistration {
                id: $id,
                kind: $crate::model::FlagKind::$kind,
                category: $crate::model::Category::$cat,
                description: $desc,
                default_enabled: $crate::register_flag!(@or true $(, $enabled)?),
                weight: $crate::register_flag!(@or 1 $(, $weight)?),
                build: |raw, $shared_arg| {
                    let enabled = $crate::register_flag!(@or true $(, $enabled)?);
                    let cfg: Option<$cfg> = $crate::analysis::registry::resolve_toggle(raw, enabled)
                        .map_err(|e| anyhow::anyhow!("flag `{}`: {e}", $id))?;
                    Ok(cfg.map(|$cfg_arg| Box::new($build) as Box<dyn $crate::analysis::Flag>))
                },
                recommended: || toml::Value::try_from(
                    <$cfg as $crate::config::Recommended>::recommended()
                ).expect("recommended config serializes"),
            }
        }
    };
    (@or $default:expr) => { $default };
    (@or $default:expr, $given:expr) => { $given };
}
