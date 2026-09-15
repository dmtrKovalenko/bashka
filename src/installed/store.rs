use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const FORMAT_VERSION: u32 = 1;
/// Recorded when no version flag of the installed binary answers.
pub const UNKNOWN_VERSION: &str = "0.0.0-unknown";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Lockfile {
    pub version: u32,
    #[serde(rename = "package")]
    pub packages: Vec<Package>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Package {
    pub name: String,
    pub source: String,
    pub command: String,
    /// RFC 3339, UTC.
    pub installed_at: String,
    pub updated_at: Option<String>,
    /// What `<binary> --version` reported after the install, or `0.0.0-unknown`.
    pub version: String,
    pub script_sha256: String,
    pub bashka_opts: Vec<String>,
    pub shell_args: Vec<String>,
    pub binaries: Vec<PathBuf>,
    pub dirs: Vec<PathBuf>,
}

impl Default for Package {
    fn default() -> Self {
        Self {
            name: String::new(),
            source: "<stdin>".into(),
            command: String::new(),
            installed_at: String::new(),
            updated_at: None,
            version: UNKNOWN_VERSION.into(),
            script_sha256: String::new(),
            bashka_opts: vec![],
            shell_args: vec![],
            binaries: vec![],
            dirs: vec![],
        }
    }
}

impl Package {
    pub fn url(&self) -> Option<&str> {
        (self.source.starts_with("https://") || self.source.starts_with("http://"))
            .then_some(self.source.as_str())
    }

    /// Every path `remove` would delete.
    pub fn paths(&self) -> impl Iterator<Item = &Path> {
        self.binaries
            .iter()
            .chain(self.dirs.iter())
            .map(PathBuf::as_path)
    }
}

impl Lockfile {
    pub fn get(&self, name: &str) -> Option<&Package> {
        self.packages.iter().find(|p| p.name == name)
    }

    /// Replaces the package with the same name, or appends. Keeps the list sorted by name.
    pub fn upsert(&mut self, pkg: Package) {
        self.packages.retain(|p| p.name != pkg.name);
        self.packages.push(pkg);
        self.packages.sort_by(|a, b| a.name.cmp(&b.name));
    }

    pub fn remove(&mut self, name: &str) -> Option<Package> {
        let at = self.packages.iter().position(|p| p.name == name)?;
        Some(self.packages.remove(at))
    }
}

/// `$XDG_DATA_HOME/bashka/installed.toml` (`~/.local/share/bashka/installed.toml`).
pub fn path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("BASHKA_LOCKFILE") {
        return Ok(PathBuf::from(p));
    }
    dirs::data_dir()
        .map(|d| d.join("bashka").join("installed.toml"))
        .context("no data directory (HOME unset?)")
}

pub fn load() -> Result<Lockfile> {
    load_from(&path()?)
}

pub fn load_from(path: &Path) -> Result<Lockfile> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Lockfile::default()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let lock: Lockfile =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    if lock.version > FORMAT_VERSION {
        anyhow::bail!(
            "{} was written by a newer bashka (format {}); this build reads format {FORMAT_VERSION}",
            path.display(),
            lock.version
        );
    }
    Ok(lock)
}

pub fn save(lock: &Lockfile) -> Result<()> {
    save_to(&path()?, lock)
}

/// Atomic write: a temp file in the same directory, then rename.
pub fn save_to(path: &Path, lock: &Lockfile) -> Result<()> {
    let dir = path.parent().context("lock file has no parent directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut lock = lock.clone();
    lock.version = FORMAT_VERSION;
    let mut text = String::from(
        "# Software installed through bashka. Managed by `bashka list|update|remove`.\n",
    );
    text.push_str(&toml::to_string_pretty(&lock).context("serializing lock file")?);
    let mut tmp = tempfile::Builder::new()
        .prefix(".installed-")
        .suffix(".toml.tmp")
        .tempfile_in(dir)?;
    tmp.write_all(text.as_bytes())?;
    tmp.flush()?;
    tmp.persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Current time as RFC 3339 in UTC, second precision (no chrono dependency).
pub fn now() -> String {
    rfc3339(std::time::SystemTime::now())
}

/// `t` as RFC 3339 in UTC, second precision.
pub fn rfc3339(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let (h, m, s) = ((secs % 86_400) / 3600, (secs % 3600) / 60, secs % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Howard Hinnant's algorithm: days since 1970-01-01 -> (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("installed.toml");
        assert!(load_from(&path).unwrap().packages.is_empty());
        let mut lock = Lockfile::default();
        lock.upsert(Package {
            name: "mise".into(),
            source: "https://mise.run".into(),
            command: "curl https://mise.run | bashka".into(),
            installed_at: now(),
            binaries: vec!["/home/t/.local/bin/mise".into()],
            ..Default::default()
        });
        lock.upsert(Package {
            name: "abc".into(),
            ..Default::default()
        });
        save_to(&path, &lock).unwrap();
        let back = load_from(&path).unwrap();
        assert_eq!(back.version, FORMAT_VERSION);
        assert_eq!(
            back.packages
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            ["abc", "mise"]
        );
        assert_eq!(back.get("mise").unwrap().binaries.len(), 1);
        assert_eq!(back.get("mise").unwrap().url(), Some("https://mise.run"));
    }

    #[test]
    fn dates_are_civil() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert!(now().ends_with('Z') && now().len() == 20);
    }
}
