use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use std::fmt;
use std::marker::PhantomData;

/// Batteries-included options, what `= true` and absence expand to.
/// Distinct from `Default`, which fills omitted fields of an explicit partial table.
pub trait Recommended {
    fn recommended() -> Self;
}

#[derive(Debug, Clone, PartialEq)]
pub enum Toggle<T> {
    Off,
    On(T),
}

impl<T> Toggle<T> {
    pub fn into_option(self) -> Option<T> {
        match self {
            Toggle::Off => None,
            Toggle::On(t) => Some(t),
        }
    }
}

impl<'de, T> Deserialize<'de> for Toggle<T>
where
    T: Recommended + Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(ToggleVisitor(PhantomData))
    }
}

struct ToggleVisitor<T>(PhantomData<T>);

impl<'de, T> Visitor<'de> for ToggleVisitor<T>
where
    T: Recommended + Deserialize<'de>,
{
    type Value = Toggle<T>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("`true`, `false`, or a table of options")
    }

    fn visit_bool<E: de::Error>(self, on: bool) -> Result<Self::Value, E> {
        Ok(if on {
            Toggle::On(T::recommended())
        } else {
            Toggle::Off
        })
    }

    fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
        T::deserialize(de::value::MapAccessDeserializer::new(map)).map(Toggle::On)
    }
}

/// For flags without options.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct NoConfig {}

impl Recommended for NoConfig {
    fn recommended() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Deserialize)]
    #[serde(default, deny_unknown_fields)]
    struct Cfg {
        limit: u32,
        names: Vec<String>,
    }
    impl Default for Cfg {
        fn default() -> Self {
            Cfg {
                limit: 1,
                names: vec![],
            }
        }
    }
    impl Recommended for Cfg {
        fn recommended() -> Self {
            Cfg {
                limit: 10,
                names: vec!["curated".into()],
            }
        }
    }

    fn parse(s: &str) -> Result<Toggle<Cfg>, toml::de::Error> {
        toml::from_str::<toml::Table>(s)
            .unwrap()
            .remove("f")
            .unwrap()
            .try_into()
    }

    #[test]
    fn bool_and_table_forms() {
        assert_eq!(parse("f = true").unwrap(), Toggle::On(Cfg::recommended()));
        assert_eq!(parse("f = false").unwrap(), Toggle::Off);
        // Partial table: `Default` fills the rest, not `Recommended`.
        assert_eq!(
            parse("f = { limit = 3 }").unwrap(),
            Toggle::On(Cfg {
                limit: 3,
                names: vec![]
            })
        );
    }

    #[test]
    fn rejects_typos_and_wrong_types() {
        assert!(
            parse("f = { limt = 3 }")
                .unwrap_err()
                .to_string()
                .contains("limt")
        );
        assert!(
            parse("f = 3")
                .unwrap_err()
                .to_string()
                .contains("table of options")
        );
    }
}
