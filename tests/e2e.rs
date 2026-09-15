use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn bashka(script: &str, args: &[&str], env: &[(&str, &str)]) -> Run {
    let home = tempfile::tempdir().unwrap();
    bashka_in(home.path(), script, args, env)
}

/// Runs bashka with `home` as HOME (so the install registry and dotfiles live there).
fn bashka_in(home: &Path, script: &str, args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bashka"));
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    isolate(&mut cmd, home);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let Output {
        status,
        stdout,
        stderr,
    } = child.wait_with_output().unwrap();
    Run {
        code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout).into(),
        stderr: strip_ansi(&String::from_utf8_lossy(&stderr)),
    }
}

/// Isolate HOME so no script (even a fixture) can touch real dotfiles, never read the real
/// config, and keep the install registry inside the temp HOME.
fn isolate(cmd: &mut Command, home: &Path) {
    cmd.env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env_remove("BASHKA_LOCKFILE");
}

/// `sh -c "curl … | bashka …"`: the real pipeline, so origin discovery via `ps` is exercised.
fn piped(home: &Path, url: &str, bashka_args: &str) -> Run {
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(format!(
            "curl -fsSL {url} | {} {bashka_args}",
            env!("CARGO_BIN_EXE_bashka")
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    isolate(&mut cmd, home);
    let Output {
        status,
        stdout,
        stderr,
    } = cmd.output().unwrap();
    Run {
        code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout).into(),
        stderr: strip_ansi(&String::from_utf8_lossy(&stderr)),
    }
}

fn lockfile(home: &Path) -> String {
    std::fs::read_to_string(home.join("data/bashka/installed.toml")).unwrap_or_default()
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixtures().join(name)).unwrap()
}

/// Serves `tests/fixtures/<path>` over HTTP on a random port; returns `host:port`.
fn serve_fixtures() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let target = request.split_whitespace().nth(1).unwrap_or("/");
            let (path, query) = target.split_once('?').unwrap_or((target, ""));
            let path = path.trim_start_matches('/').to_string();
            // `?slow` keeps curl alive a moment so origin discovery can still see it.
            let linger = query.contains("slow");
            let response = match std::fs::read(fixtures().join(&path)) {
                Ok(body) => [
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .into_bytes(),
                    body,
                ]
                .concat(),
                Err(_) => {
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_vec()
                }
            };
            if linger {
                // Hold back the last byte so the fetcher stays alive for a moment.
                let _ = stream.write_all(&response[..response.len() - 1]);
                std::thread::sleep(std::time::Duration::from_millis(700));
                let _ = stream.write_all(&response[response.len() - 1..]);
            } else {
                let _ = stream.write_all(&response);
            }
        }
    });
    addr.to_string()
}

fn config(body: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(body.as_bytes()).unwrap();
    f
}

#[test]
fn green_script_runs_without_prompting() {
    let run = bashka(
        &fixture("benign/_benign_minimal.sh"),
        &["--non-interactive"],
        &[],
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stderr.contains("INSTALLING | looks like a good script"),
        "{}",
        run.stderr
    );
    assert!(run.stdout.contains("benign: installed into"));
}

#[test]
fn red_script_is_blocked_without_a_terminal() {
    let run = bashka(&fixture("malicious.sh"), &[], &[]);
    assert_eq!(run.code, 1);
    assert!(run.stdout.is_empty(), "nothing must execute");
    for id in [
        "banned_commands",
        "remote_exec",
        "obfuscation",
        "path_suspicious",
        "sensitive_write",
        "domain_refs",
    ] {
        assert!(
            run.stderr.contains(&format!("[{id}]")),
            "missing {id} in:\n{}",
            run.stderr
        );
    }
    assert!(run.stderr.contains("RED | multiple red flags"));
    assert!(
        run.stderr.contains("--force"),
        "abort hint mentions --force:\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("no terminal to ask about fetching"),
        "{}",
        run.stderr
    );
}

#[test]
fn yes_does_not_bypass_the_strong_gate_but_force_does() {
    // Three reds that are inert when executed: HOME is a temp dir, the port is closed, the dir is missing.
    let script = "echo hi >> ~/.bashrc\ncurl -s http://127.0.0.1:9/x | sh\nchmod -R 777 /nonexistent-dir-for-test || true\necho ran\n";
    let run = bashka(script, &["--yes"], &[]);
    assert_eq!(run.code, 1);
    assert!(run.stdout.is_empty());
    let cfg = config("[interaction]\nfollow_remote = \"never\"\n");
    let run = bashka(
        script,
        &["--yes", "--force", "--config", cfg.path().to_str().unwrap()],
        &[],
    );
    assert!(run.stdout.contains("ran"), "{}", run.stderr);
}

#[test]
fn report_snapshot() {
    let run = bashka(&fixture("malicious.sh"), &["--non-interactive"], &[]);
    insta::assert_snapshot!(run.stderr);
}

#[test]
fn fetch_ahead_analyzes_every_layer_before_running() {
    let host = serve_fixtures();
    let script =
        fixture("forwarder.sh").replace("\"$INNER_URL\"", &format!("http://{host}/inner.sh"));
    let cfg = config("[interaction]\nfollow_remote = \"always\"\non_red = \"proceed\"\n");
    let run = bashka(&script, &["--config", cfg.path().to_str().unwrap()], &[]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stderr.contains(&format!("↳ 📜 http://{host}/inner.sh")),
        "{}",
        run.stderr
    );
    assert!(run.stderr.contains("across 2 layers"));
    let report_end = run.stderr.find(" | ").unwrap();
    assert!(run.stdout.contains("inner: ran with --from-forwarder"));
    assert!(run.stderr[..report_end].contains("[remote_exec]"));
}

#[test]
fn declining_a_forward_aborts_safely_without_a_terminal() {
    let host = serve_fixtures();
    let script =
        fixture("forwarder.sh").replace("\"$INNER_URL\"", &format!("http://{host}/inner.sh"));
    let run = bashka(&script, &["--non-interactive"], &[]);
    assert_eq!(run.code, 1);
    assert!(run.stdout.is_empty());
    assert!(!run.stderr.contains("across 2 layers"), "{}", run.stderr);
}

#[test]
fn dynamic_forward_is_intercepted_by_the_shim() {
    let host = serve_fixtures();
    let cfg = config("[interaction]\non_red = \"proceed\"\non_neutral = \"proceed\"\n");
    let run = bashka(
        &fixture("dynamic_forwarder.sh"),
        &["--config", cfg.path().to_str().unwrap()],
        &[("INNER_HOST", &host)],
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stderr.contains("computed at run time"),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("intercepted `bash` at chain depth 1"),
        "{}",
        run.stderr
    );
    assert!(run.stdout.contains("inner: ran with --dynamic"));
    assert!(run.stdout.contains("dynamic: top done"));
}

#[test]
fn shim_stops_cycles_and_respects_max_depth() {
    let host = serve_fixtures();
    let cfg = config("[interaction]\non_red = \"proceed\"\non_neutral = \"proceed\"\n");
    let run = bashka(
        &fixture("self_forwarder.sh"),
        &["--config", cfg.path().to_str().unwrap()],
        &[("INNER_HOST", &host)],
    );
    assert!(run.stderr.contains("cycle detected"), "{}", run.stderr);
    assert_eq!(run.stdout.matches("self: layer").count(), 1);

    let run = bashka(
        &fixture("dynamic_forwarder.sh"),
        &["--config", cfg.path().to_str().unwrap(), "--max-depth", "0"],
        &[("INNER_HOST", &host)],
    );
    assert!(run.stderr.contains("exceeds max_depth=0"), "{}", run.stderr);
    assert!(!run.stdout.contains("inner: ran"));
}

#[test]
fn shell_args_are_forwarded_and_exit_code_propagates() {
    let run = bashka(
        "set -euo pipefail\nTMP=$(mktemp -d); trap 'rm -rf $TMP' EXIT\necho \"args: $*\"\nexit 7\n",
        &["--yes", "--", "one", "two"],
        &[],
    );
    assert_eq!(run.code, 7, "{}", run.stderr);
    assert!(run.stdout.contains("args: one two"));
}

#[test]
fn dead_flag_blocks_critical_scripts() {
    let run = bashka(&fixture("dead.sh"), &["--yes", "--force"], &[]);
    assert_eq!(
        run.code, 1,
        "even --yes --force must not run a critical script"
    );
    assert!(run.stdout.is_empty(), "nothing executes");
    for id in ["exfiltration", "credential_theft", "reverse_shell"] {
        assert!(
            run.stderr.contains(&format!("[{id}]")),
            "missing {id}:\n{}",
            run.stderr
        );
    }
    assert!(
        run.stderr.contains("DANGER | critically malicious"),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("\u{1f480}"),
        "dead skull icon shown: {}",
        run.stderr
    );
    assert_eq!(bashka(&fixture("dead.sh"), &["--check"], &[]).code, 4);
}

#[test]
fn check_mode_never_runs_and_encodes_the_verdict() {
    let run = bashka(&fixture("benign/_benign_minimal.sh"), &["--check"], &[]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stdout.is_empty(),
        "green script must not run under --check"
    );
    assert!(
        run.stderr.contains("GREEN | looks like a good script"),
        "{}",
        run.stderr
    );
    assert_eq!(bashka("echo hi", &["--check"], &[]).code, 1);
    assert_eq!(
        bashka(
            "curl -s https://x.io/i -o i; echo x >> ~/.bashrc",
            &["--check"],
            &[]
        )
        .code,
        2
    );
    assert_eq!(bashka(&fixture("malicious.sh"), &["--check"], &[]).code, 3);
}

/// Whether `expect` (needed to drive a pty) is available.
fn have_expect() -> bool {
    Command::new("expect")
        .arg("-v")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn ai_agent_launches_from_the_action_menu() {
    if !have_expect() {
        eprintln!("skipping ai_agent_launches_from_the_action_menu: `expect` not installed");
        return;
    }
    let bin = env!("CARGO_BIN_EXE_bashka");
    let fake_dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let marker = fake_dir.path().join("codex_was_called.txt");
    // A fake `codex` that records the prompt it was launched with (its 2nd arg, after `exec`).
    let fake = fake_dir.path().join("codex");
    std::fs::write(
        &fake,
        format!(
            "#!/bin/sh\nprintf '%s' \"$2\" > {}\necho FAKE_CODEX_RAN\n",
            marker.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let script = fixtures().join("malicious/reverse_shell_devtcp.sh"); // critical, no forward prompt
    let path = format!("{}:/usr/bin:/bin", fake_dir.path().display());
    // Drive the menu: choose [a] analyze, then [1] the first agent (Codex), then [q] abort.
    let exp = format!(
        "set timeout 20\n\
         spawn sh -c {{env PATH={path} BASHFLAGS_REAL_PATH={path} HOME={home} {bin} < {script}}}\n\
         expect {{caught the behavior}} {{ send \"a\\r\" }}\n\
         expect {{which agent}} {{ send \"1\\r\" }}\n\
         expect -re {{What now|caught the behavior}} {{ send \"q\\r\" }}\n\
         expect eof\n",
        home = home.path().display(),
        script = script.display(),
    );
    let exp_file = fake_dir.path().join("drive.exp");
    std::fs::write(&exp_file, exp).unwrap();
    let out = Command::new("expect").arg(&exp_file).output().unwrap();
    let transcript = String::from_utf8_lossy(&out.stdout);
    assert!(
        transcript.contains("Analyze with which agent") || transcript.contains("FAKE_CODEX_RAN"),
        "menu/agent not reached:\n{transcript}"
    );
    let recorded = std::fs::read_to_string(&marker).unwrap_or_default();
    assert!(
        recorded.contains("bashka findings"),
        "codex was not launched with the review prompt (marker: {recorded:?})"
    );
    assert!(
        recorded.contains("reverse_shell"),
        "prompt should carry the findings; got: {recorded:?}"
    );
}

#[test]
fn action_menu_run_anyway_executes() {
    if !have_expect() {
        eprintln!("skipping action_menu_run_anyway_executes: `expect` not installed");
        return;
    }
    let bin = env!("CARGO_BIN_EXE_bashka");
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    // A red (not critical) script that is inert to run.
    let script = dir.path().join("red.sh");
    std::fs::write(
        &script,
        "chmod -R 777 /nonexistent-xyz-corpus || true\necho RAN_ANYWAY_MARKER\n",
    )
    .unwrap();
    let exp = format!(
        "set timeout 20\n\
         spawn sh -c {{env HOME={home} {bin} < {script}}}\n\
         expect {{caught the behavior}} {{ send \"x\\r\" }}\n\
         expect eof\n",
        home = home.path().display(),
        script = script.display()
    );
    let f = dir.path().join("run.exp");
    std::fs::write(&f, exp).unwrap();
    let out = Command::new("expect").arg(&f).output().unwrap();
    let t = String::from_utf8_lossy(&out.stdout);
    assert!(t.contains("running the installer"), "no launch line:\n{t}");
    assert!(t.contains("RAN_ANYWAY_MARKER"), "script did not run:\n{t}");
}

#[test]
fn action_menu_read_then_abort() {
    if !have_expect() {
        eprintln!("skipping action_menu_read_then_abort: `expect` not installed");
        return;
    }
    let bin = env!("CARGO_BIN_EXE_bashka");
    let home = tempfile::tempdir().unwrap();
    let script = fixtures().join("malicious/cryptominer.sh");
    // [r] open the pager, [q] quit it, then [q] abort at the run/abort prompt.
    let exp = format!(
        "set timeout 20\n\
         spawn sh -c {{env HOME={home} {bin} < {script}}}\n\
         expect {{caught the behavior}} {{ send \"r\\r\" }}\n\
         sleep 1\n\
         send \"q\"\n\
         expect {{Run the script now}} {{ send \"q\\r\" }}\n\
         expect eof\n",
        home = home.path().display(),
        script = script.display()
    );
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("read.exp");
    std::fs::write(&f, exp).unwrap();
    let out = Command::new("expect").arg(&f).output().unwrap();
    let t = String::from_utf8_lossy(&out.stdout);
    assert!(
        t.contains("Run the script now"),
        "pager did not return to run/abort:\n{t}"
    );
    assert!(t.contains("ABORTED"), "did not abort:\n{t}");
}

#[test]
fn flags_and_config_init_subcommands() {
    let run = bashka("", &["flags"], &[]);
    assert_eq!(run.code, 0);
    for id in ["banned_commands", "trusted_domains", "max_commands"] {
        assert!(run.stdout.contains(id));
    }
    let run = bashka("", &["config", "init"], &[]);
    assert_eq!(run.code, 0);
    assert!(run.stdout.contains("max_commands = true"));
    assert!(run.stdout.contains("# max_commands = { limit = 1000 }"));
}

#[test]
fn config_errors_fail_fast() {
    let cfg = config("[flags]\nmax_commands = { limt = 3 }\n");
    let run = bashka("echo hi", &["--config", cfg.path().to_str().unwrap()], &[]);
    assert_eq!(run.code, 1);
    assert!(
        run.stderr.contains("max_commands") && run.stderr.contains("limt"),
        "{}",
        run.stderr
    );
    assert!(run.stdout.is_empty());

    let cfg = config("[flags]\nmax_commmands = true\n");
    let run = bashka(
        "echo hi",
        &[
            "--non-interactive",
            "--config",
            cfg.path().to_str().unwrap(),
        ],
        &[],
    );
    assert!(
        run.stderr.contains("unknown flag `max_commmands`"),
        "{}",
        run.stderr
    );
}

#[test]
fn disabled_and_customized_flags() {
    let cfg = config("[flags]\nmax_commands = { limit = 1 }\nstrict_mode = false\n");
    let run = bashka(
        "set -euo pipefail\necho a\necho b\n",
        &[
            "--non-interactive",
            "--config",
            cfg.path().to_str().unwrap(),
        ],
        &[],
    );
    assert!(run.stderr.contains("[max_commands]:"), "{}", run.stderr);
    assert!(!run.stderr.contains("[strict_mode]:"));
}

#[test]
fn install_target_flag_is_red_for_opaque_installers() {
    let run = bashka(
        "curl -fsSL https://x.io/t.tgz | tar xz\necho done\n",
        &["--check"],
        &[],
    );
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(run.stderr.contains("[install_target]"), "{}", run.stderr);
    assert!(
        run.stderr
            .contains("cannot tell where the installer writes files"),
        "{}",
        run.stderr
    );
    let run = bashka(&fixture("installer.sh"), &["--check"], &[]);
    assert!(!run.stderr.contains("[install_target]"), "{}", run.stderr);
}

#[test]
fn registry_records_lists_and_removes() {
    let home = tempfile::tempdir().unwrap();
    let run = bashka_in(
        home.path(),
        &fixture("installer.sh"),
        &["--yes", "--name", "Demo Tool", "--", "one"],
        &[],
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.contains("demo: installed into"));
    assert!(
        run.stderr
            .contains("recorded demo-tool demo in the install registry"),
        "{}",
        run.stderr
    );
    assert!(run.stderr.contains("+ ~/.local/bin/demo"), "{}", run.stderr);
    assert!(run.stderr.contains("+ ~/.demo/"), "{}", run.stderr);

    let lock = lockfile(home.path());
    assert!(lock.contains("name = \"demo-tool\""), "{lock}");
    assert!(lock.contains("source = \"<stdin>\""), "{lock}");
    // `demo --version` prints "demo" and exits 0: that output is the recorded version.
    assert!(lock.contains("version = \"demo\""), "{lock}");
    assert!(lock.contains("shell_args = [\"one\"]"), "{lock}");
    assert!(lock.contains("bashka_opts = [\"--yes\"]"), "{lock}");
    assert!(lock.contains("/.local/bin/demo\""), "{lock}");
    assert!(lock.contains("/.demo\""), "{lock}");
    assert!(
        !lock.contains("/.local\""),
        "shared dirs are never recorded: {lock}"
    );
    assert!(home.path().join(".local/bin/demo").is_file());

    let run = bashka_in(home.path(), "", &["list"], &[]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let out = strip_ansi(&run.stdout);
    let header = out.lines().next().unwrap();
    assert!(
        header.starts_with("NAME") && header.contains("VERSION") && header.contains("SOURCE"),
        "{out}"
    );
    let row = out.lines().nth(1).unwrap();
    assert!(row.starts_with("demo-tool"), "{out}");
    assert!(row.contains("  2  "), "one binary + one dir: {out}");
    assert!(row.contains("<stdin>"), "{out}");

    let run = bashka_in(home.path(), "", &["info", "demo-tool"], &[]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let out = strip_ansi(&run.stdout);
    assert!(out.contains("Name            : demo-tool"), "{out}");
    assert!(out.contains("Binaries        : ~/.local/bin/demo"), "{out}");
    assert!(out.contains("Directories     : ~/.demo/"), "{out}");
    assert!(out.contains("| bashka --yes -- one"), "{out}");
    assert!(out.contains("Shell Args      : one"), "{out}");
    let long = strip_ansi(&bashka_in(home.path(), "", &["list", "--long"], &[]).stdout);
    assert_eq!(long, out, "list --long is info for every package");

    let run = bashka_in(home.path(), "", &["remove", "demo-tool", "--dry-run"], &[]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(strip_ansi(&run.stdout).contains("would remove ~/.local/bin/demo"));
    assert!(
        home.path().join(".local/bin/demo").is_file(),
        "dry run removes nothing"
    );

    let run = bashka_in(home.path(), "", &["remove", "demo-tool"], &[]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        !run.stderr.contains("no files were tracked"),
        "{}",
        run.stderr
    );
    assert!(!home.path().join(".local/bin/demo").exists());
    assert!(!home.path().join(".demo").exists());
    assert!(
        home.path().join(".local/bin").is_dir(),
        "pre-existing dirs stay"
    );
    assert!(!lockfile(home.path()).contains("demo-tool"));

    let run = bashka_in(home.path(), "", &["list"], &[]);
    assert!(strip_ansi(&run.stdout).contains("nothing installed through bashka yet"));
    let run = bashka_in(home.path(), "", &["remove", "demo-tool"], &[]);
    assert_ne!(run.code, 0);
    assert!(
        run.stderr.contains("not in the install registry"),
        "{}",
        run.stderr
    );
}

#[test]
fn nameless_installers_are_flagged_and_not_recorded() {
    // The download is never executed (guarded by `false`) but is visible to the analysis.
    let script = "if false; then curl -fsSL https://x.io/i -o /dev/null; fi\necho ran\n";
    let run = bashka(script, &["--check"], &[]);
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(run.stderr.contains("[install_name]"), "{}", run.stderr);
    assert!(
        run.stderr
            .contains("cannot tell what software this installs"),
        "{}",
        run.stderr
    );
    // `--name` answers the question, so the flag is gone.
    let run = bashka(script, &["--check", "--name", "thing"], &[]);
    assert!(!run.stderr.contains("[install_name]"), "{}", run.stderr);

    // Forced through without a name: it runs, but nothing is recorded.
    let home = tempfile::tempdir().unwrap();
    let cfg = config("[interaction]\non_red = \"proceed\"\n");
    let run = bashka_in(
        home.path(),
        script,
        &["--config", cfg.path().to_str().unwrap()],
        &[],
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.contains("ran"));
    assert!(
        run.stderr.contains("could not name what it installed"),
        "{}",
        run.stderr
    );
    assert_eq!(lockfile(home.path()), "");
}

#[test]
fn removing_a_package_without_tracked_files_only_drops_the_entry() {
    let home = tempfile::tempdir().unwrap();
    // Downloads (so it is an installer) and names itself, but writes nothing bashka can see.
    let script = "if false; then curl -fsSL https://x.io/i -o /dev/null; fi\nAPP=ghost\necho ran\n";
    let run = bashka_in(home.path(), script, &["--yes"], &[]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stderr.contains("recorded ghost"), "{}", run.stderr);
    let run = bashka_in(home.path(), "", &["remove", "ghost"], &[]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stderr.contains("no files were tracked"),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("only removes the registry entry"),
        "{}",
        run.stderr
    );
    assert!(
        strip_ansi(&run.stdout).contains("ghost removed"),
        "{}",
        run.stdout
    );
    assert!(!lockfile(home.path()).contains("ghost"));
}

#[test]
fn failed_installs_are_not_recorded() {
    let home = tempfile::tempdir().unwrap();
    let run = bashka_in(home.path(), "echo boom\nexit 3\n", &["--yes"], &[]);
    assert_eq!(run.code, 3);
    assert!(run.stderr.contains("not recorded"), "{}", run.stderr);
    assert_eq!(lockfile(home.path()), "");
}

#[test]
fn piped_install_captures_origin_and_update_reruns_it() {
    let host = serve_fixtures();
    let home = tempfile::tempdir().unwrap();
    let url = format!("http://{host}/installer.sh?slow");
    let run = piped(home.path(), &url, "--yes --name demo");
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stderr.contains("recorded demo"), "{}", run.stderr);
    let lock = lockfile(home.path());
    assert!(lock.contains(&format!("source = \"{url}\"")), "{lock}");
    assert!(
        lock.contains(&format!("command = \"curl -fsSL {url} | bashka --yes\"")),
        "{lock}"
    );
    assert!(!lock.contains("updated_at"), "{lock}");

    // Make the binary stale, then update: the same installer is fetched and run again.
    std::fs::write(home.path().join(".local/bin/demo"), "stale").unwrap();
    let run = bashka_in(home.path(), "", &["update", "demo"], &[]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stderr.contains(&format!("fetching {url}")),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("unchanged since the last run"),
        "{}",
        run.stderr
    );
    assert!(
        run.stdout.contains("demo: installed into"),
        "{}",
        run.stdout
    );
    assert!(run.stderr.contains("recorded demo"), "{}", run.stderr);
    assert!(
        std::fs::read_to_string(home.path().join(".local/bin/demo"))
            .unwrap()
            .contains("echo demo")
    );
    let lock = lockfile(home.path());
    assert!(lock.contains("updated_at = "), "{lock}");
    assert_eq!(lock.matches("name = \"demo\"").count(), 1, "{lock}");

    let run = bashka_in(home.path(), "", &["update", "nope"], &[]);
    assert_ne!(run.code, 0);
}

/// A copy of bashka living in ~/.local/bin is its own default registry entry, and removing it
/// also deletes the configuration and the registry file.
#[test]
fn bashka_tracks_and_removes_itself() {
    let home = tempfile::tempdir().unwrap();
    let bin_dir = home.path().join(".local/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let me = bin_dir.join("bashka");
    std::fs::copy(env!("CARGO_BIN_EXE_bashka"), &me).unwrap();
    let config = home.path().join("config/bashka/config.toml");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, "[ui]\nanimations = false\n").unwrap();

    let run_me = |args: &[&str]| {
        let mut cmd = Command::new(&me);
        cmd.args(args).stdin(Stdio::null());
        isolate(&mut cmd, home.path());
        let out = cmd.output().unwrap();
        (
            out.status.code().unwrap_or(-1),
            strip_ansi(&String::from_utf8_lossy(&out.stdout)),
            strip_ansi(&String::from_utf8_lossy(&out.stderr)),
        )
    };

    let (code, out, err) = run_me(&["list"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("bashka"), "{out}");
    assert!(
        out.contains("raw.githubusercontent.com/dmtrKovalenko/bashka/main/install.sh"),
        "{out}"
    );
    let (code, out, _) = run_me(&["info", "bashka"]);
    assert_eq!(code, 0);
    assert!(out.contains("~/.local/bin/bashka"), "{out}");
    // Synthesized, never written: the lock file does not exist yet.
    assert_eq!(lockfile(home.path()), "");

    // The development binary is not an install, so it has no self entry.
    let plain = bashka_in(home.path(), "", &["list"], &[]);
    assert!(
        plain.stdout.contains("nothing installed"),
        "{}",
        plain.stdout
    );

    let (code, out, _) = run_me(&["remove", "bashka", "--dry-run"]);
    assert_eq!(code, 0);
    assert!(out.contains("would remove ~/.local/bin/bashka"), "{out}");
    assert!(
        out.contains("would remove ~/config/bashka/config.toml"),
        "{out}"
    );
    assert!(me.exists() && config.exists());

    let (code, out, err) = run_me(&["remove", "bashka"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("bye-bye!"), "{out}");
    assert!(out.contains("| bash"), "reinstall hint\n{out}");
    assert!(!me.exists(), "binary removed");
    assert!(!config.exists(), "config removed");
    assert!(
        !config.parent().unwrap().exists(),
        "empty config dir removed"
    );
    assert!(
        !home.path().join("data/bashka").exists(),
        "registry dir removed"
    );
}
