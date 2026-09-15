use crate::analysis::Flag;
use crate::config::Recommended;
use crate::model::{Detail, Verdict};
use crate::parser::Assignment;
use crate::register_flag;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PathSuspiciousCfg {
    /// Directory prefixes that must never appear in PATH.
    pub writable_dirs: Vec<String>,
}

impl Default for PathSuspiciousCfg {
    fn default() -> Self {
        Self::recommended()
    }
}

impl Recommended for PathSuspiciousCfg {
    fn recommended() -> Self {
        Self {
            writable_dirs: ["/tmp", "/var/tmp", "/dev/shm", "$TMPDIR", "${TMPDIR}"]
                .map(String::from)
                .to_vec(),
        }
    }
}

pub struct PathSuspicious {
    cfg: PathSuspiciousCfg,
}

impl PathSuspicious {
    fn offending(&self, segment: &str) -> Option<&'static str> {
        if segment.is_empty()
            || segment == "."
            || segment.starts_with("./")
            || segment.starts_with("$PWD")
        {
            return Some("current directory");
        }
        self.cfg
            .writable_dirs
            .iter()
            .any(|d| segment == d || segment.starts_with(&format!("{d}/")))
            .then_some("temporary or world-writable directory")
    }
}

impl Flag for PathSuspicious {
    fn visit_assignment(&mut self, a: &Assignment) -> Verdict {
        if a.name != "PATH" {
            return Verdict::Ignore;
        }
        let Some((segment, why)) = a
            .value
            .text
            .split(':')
            .find_map(|s| self.offending(s).map(|w| (s, w)))
        else {
            return Verdict::Ignore;
        };
        Verdict::Red(
            Detail::new(
                format!("PATH includes a {why}: `{segment}`"),
                "Any file dropped there shadows real commands for the rest of the script (and your shell, if exported to rc files).",
            )
            .at(a.span.clone()),
        )
    }
}

register_flag! {
    id: "path_suspicious",
    kind: Red,
    category: Path,
    description: "PATH prepended with temp, relative or world-writable directories",
    config: PathSuspiciousCfg,
    build: |cfg, _shared| PathSuspicious { cfg },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn temp_and_relative_path_entries() {
        assert!(fires("path_suspicious", "export PATH=/tmp/bin:$PATH"));
        assert!(fires("path_suspicious", "PATH=.:$PATH"));
        assert!(fires("path_suspicious", "PATH=\"$PATH:\""));
        assert!(!fires(
            "path_suspicious",
            "export PATH=\"$HOME/.local/bin:$PATH\""
        ));
    }
}
