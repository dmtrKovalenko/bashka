use crate::install_paths;
use crate::parser;
use crate::report::Layer;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const MAX_DEPTH: usize = 4;
const MAX_ENTRIES: usize = 50_000;
const SKIP_DIRS: &[&str] = &[".git", "node_modules", ".cache", "__pycache__"];

#[derive(Debug, Default)]
pub struct Watch {
    pub flat: BTreeSet<PathBuf>,
    pub roots: BTreeSet<PathBuf>,
    pub home: Option<PathBuf>,
    pub unresolved: Vec<String>,
}

impl Watch {
    /// PATH dirs, conventional user bin dirs, and every literal destination found in `layers`.
    pub fn for_layers(layers: &[Layer], path_env: &str, home: Option<PathBuf>) -> Self {
        let mut w = Self {
            home,
            ..Self::default()
        };
        for dir in path_env.split(':').filter(|d| !d.is_empty()) {
            w.flat.insert(PathBuf::from(dir));
        }
        if let Some(home) = &w.home {
            for rel in [".local/bin", "bin", ".cargo/bin"] {
                w.flat.insert(home.join(rel));
            }
        }
        w.flat.insert(PathBuf::from("/usr/local/bin"));
        for layer in layers {
            let Ok(ctx) = parser::parse(&layer.source) else {
                continue;
            };
            for dest in install_paths::destinations(&ctx, w.home.as_deref()) {
                match dest.watch_root() {
                    Some(root) => w.add_root(root),
                    None if !w.unresolved.contains(&dest.raw) => w.unresolved.push(dest.raw),
                    None => {}
                }
            }
        }
        w
    }

    fn add_root(&mut self, root: &Path) {
        if !root.is_absolute() || self.is_broad(root) {
            return;
        }
        self.roots.insert(root.to_path_buf());
        // The destination may be a file: its directory is where siblings land.
        if let Some(parent) = root.parent().filter(|p| !self.is_broad(p)) {
            self.flat.insert(parent.to_path_buf());
        }
    }

    fn is_broad(&self, p: &Path) -> bool {
        is_broad(p, self.home.as_deref())
    }
}

/// Directories shared by many programs: never an install root, never deleted by `remove`.
const SHARED_IN_HOME: &[&str] = &[
    ".local",
    ".local/bin",
    ".local/share",
    ".local/lib",
    ".local/state",
    ".local/share/man",
    ".config",
    ".cache",
    "bin",
    ".ssh",
    ".bashrc.d",
    "go",
    "go/bin",
];
const SHARED_ABSOLUTE: &[&str] = &[
    "/",
    "/usr",
    "/home",
    "/opt",
    "/etc",
    "/var",
    "/tmp",
    "/bin",
    "/lib",
    "/usr/local",
    "/usr/local/bin",
    "/usr/local/lib",
    "/usr/local/share",
    "/usr/share",
    "/usr/bin",
    "/usr/lib",
];

pub fn is_broad(p: &Path, home: Option<&Path>) -> bool {
    if SHARED_ABSOLUTE.iter().any(|b| Path::new(b) == p) {
        return true;
    }
    match home {
        Some(h) => h == p || SHARED_IN_HOME.iter().any(|rel| h.join(rel) == p),
        None => false,
    }
}

/// `$HOME`, when set and non-empty.
pub fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    mtime_ns: u128,
    len: u64,
    ino: u64,
}

#[derive(Debug, Default)]
pub struct Snapshot {
    executables: HashMap<PathBuf, Stamp>,
    /// Every watched root and each of its ancestors that existed at snapshot time.
    existing: HashSet<PathBuf>,
}

impl Snapshot {
    pub fn take(watch: &Watch) -> Self {
        let mut snap = Self::default();
        let mut budget = MAX_ENTRIES;
        for dir in &watch.flat {
            scan(dir, 0, false, &mut snap.executables, &mut budget);
        }
        for root in &watch.roots {
            if root.is_file() {
                if let Some(stamp) = stamp_executable(root) {
                    snap.executables.insert(root.clone(), stamp);
                }
            } else {
                scan(root, 0, true, &mut snap.executables, &mut budget);
            }
            for p in std::iter::successors(Some(root.as_path()), |p| p.parent()) {
                if p.exists() {
                    snap.existing.insert(p.to_path_buf());
                }
            }
        }
        snap
    }
}

/// Executables and install roots that exist in `after` and not (or not identically) in `before`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub binaries: Vec<PathBuf>,
    pub created_dirs: Vec<PathBuf>,
}

pub fn diff(before: &Snapshot, after: &Snapshot, watch: &Watch) -> Changes {
    let mut binaries: Vec<PathBuf> = after
        .executables
        .iter()
        .filter(|(p, stamp)| before.executables.get(*p) != Some(*stamp))
        .map(|(p, _)| p.clone())
        .collect();
    binaries.sort();

    let mut created: BTreeSet<PathBuf> = BTreeSet::new();
    for root in &watch.roots {
        if !after.existing.contains(root)
            || before.existing.contains(root)
            || !root.is_dir()
            || watch.is_broad(root)
        {
            continue;
        }
        // Climb to the topmost ancestor the installer created (`~/.foo/bin` -> `~/.foo`).
        let mut top = root.as_path();
        while let Some(parent) = top.parent() {
            if before.existing.contains(parent) || watch.is_broad(parent) || !parent.is_dir() {
                break;
            }
            top = parent;
        }
        created.insert(top.to_path_buf());
    }
    // Drop dirs nested inside another created dir.
    let created_dirs: Vec<PathBuf> = created
        .iter()
        .filter(|d| !created.iter().any(|o| o != *d && d.starts_with(o)))
        .cloned()
        .collect();
    Changes {
        binaries,
        created_dirs,
    }
}

fn scan(
    dir: &Path,
    depth: usize,
    recursive: bool,
    out: &mut HashMap<PathBuf, Stamp>,
    budget: &mut usize,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    // In a recursive walk only `bin`-like directories (and the root itself) hold binaries.
    let bin_like = depth == 0
        || dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| matches!(n, "bin" | "sbin" | "libexec"));
    for entry in entries.flatten() {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let path = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_dir() {
            let name = entry.file_name();
            let skip = name.to_str().is_some_and(|n| SKIP_DIRS.contains(&n));
            if recursive && depth < MAX_DEPTH && !skip && !meta.file_type().is_symlink() {
                scan(&path, depth + 1, true, out, budget);
            }
            continue;
        }
        if !bin_like {
            continue;
        }
        if let Some(stamp) = stamp_executable(&path) {
            out.insert(path, stamp);
        }
    }
}

/// A stamp for `path` when it is (or links to) an executable regular file.
fn stamp_executable(path: &Path) -> Option<Stamp> {
    use std::os::unix::fs::MetadataExt;
    let target = std::fs::metadata(path).ok()?;
    if !target.is_file() || target.permissions().mode() & 0o111 == 0 {
        return None;
    }
    // Stamp the entry itself so a re-pointed symlink counts as a change.
    let own = std::fs::symlink_metadata(path).ok()?;
    let mtime = own
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos());

    Some(Stamp {
        mtime_ns: mtime,
        len: target.len(),
        ino: own.ino(),
    })
}
