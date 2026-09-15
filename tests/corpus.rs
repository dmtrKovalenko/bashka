use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn fixtures(sub: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(sub)
}

/// Runs `bashka --check` with the script on stdin and an isolated HOME; returns the exit code.
fn check(script: &Path) -> i32 {
    check_with(script, &[]).0
}

/// Like `check`, also returning the report so tests can see which flags fired.
fn check_with(script: &Path, args: &[&str]) -> (i32, String) {
    let home = tempfile::tempdir().unwrap();
    let source = std::fs::read(script).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_bashka"))
        .arg("--check")
        .args(args)
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_DATA_HOME", home.path().join("data"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&source).unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Red flag ids in a report (`🚩 [id]`).
fn red_flags(report: &str) -> Vec<String> {
    report
        .lines()
        .filter(|l| l.contains("\u{1f6a9} ["))
        .filter_map(|l| {
            let start = l.find('[')? + 1;
            let end = l[start..].find(']')? + start;
            Some(l[start..end].to_string())
        })
        .collect()
}

fn scripts_in(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "sh"))
        .collect();
    out.sort();
    assert!(!out.is_empty(), "no fixtures in {}", dir.display());
    out
}

#[test]
fn benign_scripts_are_never_flagged_red_or_critical() {
    let mut bad = Vec::new();
    for script in scripts_in(&fixtures("benign")) {
        let (code, report) = check_with(&script, &[]);
        // Real installers that stage a downloaded binary (rustup, rye) are red by design: that
        // single flag is the intended verdict, not a false positive.
        let only_staged = red_flags(&report).iter().all(|id| id == "staged_installer");
        if code == 2 && only_staged {
            continue;
        }
        if code >= 2 {
            bad.push(format!(
                "{} -> exit {code}",
                script.file_name().unwrap().to_string_lossy()
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "benign scripts wrongly flagged:\n{}",
        bad.join("\n")
    );
}

#[test]
fn malicious_scripts_are_always_flagged() {
    let mut missed = Vec::new();
    for script in scripts_in(&fixtures("malicious")) {
        let code = check(&script);
        if code < 2 {
            missed.push(format!(
                "{} -> exit {code}",
                script.file_name().unwrap().to_string_lossy()
            ));
        }
    }
    assert!(
        missed.is_empty(),
        "malicious scripts NOT flagged:\n{}",
        missed.join("\n")
    );
}

/// The unambiguously destructive samples must reach the critical (dead-flag) gate.
#[test]
fn critical_samples_hit_the_dead_gate() {
    for name in [
        "reverse_shell_devtcp",
        "env_exfil_webhook",
        "ssh_key_exfil",
        "keychain_dump",
    ] {
        let path = fixtures("malicious").join(format!("{name}.sh"));
        assert_eq!(check(&path), 4, "{name} should be critical (exit 4)");
    }
}

/// bashka's own installer (`install.sh` at the repo root) must be a model citizen: GREEN with
/// no red or yellow flag, since it is the script people run before they have bashka.
#[test]
fn own_installer_is_green() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh");
    let (code, report) = check_with(&script, &[]);
    assert_eq!(code, 0, "install.sh is not GREEN:\n{report}");
    assert!(
        !report.contains("\u{1f7e1} [") && red_flags(&report).is_empty(),
        "install.sh has a yellow or red flag:\n{report}"
    );
}
