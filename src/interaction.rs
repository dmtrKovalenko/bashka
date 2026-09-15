use crate::config::{FollowRemote, OnRed};
use crate::ui::{self, Icons, Spinner, Ui};
use anyhow::{Context, Result, bail};
use indicatif::ProgressDrawTarget;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::time::Duration;

/// The pager to view a script with: `bat` (syntax-highlighted) if present, else `less`, else `cat`.
fn pager_for() -> (String, Vec<String>) {
    if crate::agents::in_path("bat") {
        (
            "bat".into(),
            vec![
                "--style=numbers,header".into(),
                "--color=always".into(),
                "--language=bash".into(),
                "--paging=always".into(),
            ],
        )
    } else if crate::agents::in_path("less") {
        ("less".into(), vec!["-R".into(), "-N".into()])
    } else {
        ("cat".into(), vec![])
    }
}

/// `<stdin>` is what the pipe delivered; forwarded layers are named by URL.
fn describe(label: &str) -> String {
    if label.starts_with('<') {
        "the installer".to_string()
    } else {
        label.to_string()
    }
}

/// A pre-answer for a decision point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Ask,
    Yes,
    No,
}

impl From<OnRed> for Decision {
    fn from(v: OnRed) -> Self {
        match v {
            OnRed::Ask => Decision::Ask,
            OnRed::Proceed => Decision::Yes,
            OnRed::Abort => Decision::No,
        }
    }
}

impl From<FollowRemote> for Decision {
    fn from(v: FollowRemote) -> Self {
        match v {
            FollowRemote::Ask => Decision::Ask,
            FollowRemote::Always => Decision::Yes,
            FollowRemote::Never => Decision::No,
        }
    }
}

/// How `Ask` is resolved when the CLI forbids prompting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auto {
    /// Prompt on the terminal.
    Prompt,
    /// `--yes`: answer yes.
    Yes,
    /// `--non-interactive`: answer no (safe abort).
    No,
}

pub struct Prompter {
    auto: Auto,
    tty: Option<Tty>,
    ui: Ui,
    pub icons: Icons,
}

struct Tty {
    input: BufReader<File>,
    output: File,
}

impl Prompter {
    pub fn new(auto: Auto, ui: Ui) -> Self {
        let tty = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()
            .map(|f| Tty {
                input: BufReader::new(f.try_clone().expect("dup tty")),
                output: f,
            });
        Self {
            auto,
            tty,
            icons: ui.icons.icons(),
            ui,
        }
    }

    /// Whether an `Ask` can be put to a person.
    pub fn can_prompt(&self) -> bool {
        self.auto != Auto::Prompt || self.tty.is_some()
    }

    /// A real person is at a terminal (so we can show an interactive menu).
    pub fn is_interactive(&self) -> bool {
        self.auto == Auto::Prompt && self.tty.is_some()
    }

    /// Presents a single-key menu; returns the chosen key (lower-cased) or `default` on bare Enter.
    pub fn menu(&mut self, header: &str, options: &[(char, &str)], default: char) -> Result<char> {
        let Some(tty) = &mut self.tty else {
            return Ok(default);
        };
        writeln!(tty.output, "\n{header}")?;
        for (key, label) in options {
            let marker = if *key == default { "*" } else { " " };
            writeln!(
                tty.output,
                "  {marker} [{}] {label}",
                ui::paint(ui::CYAN, key)
            )?;
        }
        write!(tty.output, "{} choice: ", ui::paint(ui::CYAN, "?"))?;
        tty.output.flush()?;
        let mut line = String::new();
        if tty.input.read_line(&mut line)? == 0 {
            return Ok(default);
        }
        Ok(line
            .trim()
            .chars()
            .next()
            .map_or(default, |c| c.to_ascii_lowercase()))
    }

    /// Opens the script in a pager (bat with syntax highlighting when available, else less).
    pub fn page(&mut self, source: &str) {
        if self.tty.is_none() {
            self.say(source);
            return;
        }
        let mut tmp = match tempfile::Builder::new()
            .prefix("bashka-")
            .suffix(".sh")
            .tempfile()
        {
            Ok(t) => t,
            Err(e) => return self.say(&format!("cannot open pager: {e}\n")),
        };
        let _ = tmp.write_all(source.as_bytes());
        let path = tmp.path().to_string_lossy().into_owned();
        let (bin, mut args) = pager_for();
        args.push(path);
        Self::on_tty(&bin, &args);
    }

    /// Runs an AI agent with the review prompt, on the terminal.
    pub fn run_agent(&mut self, agent: &crate::agents::Agent, prompt: &str) {
        self.say(&format!(
            "{} launching {} …\n",
            self.icons.launch, agent.name
        ));
        if !Self::on_tty(agent.bin, &(agent.args)(prompt)) {
            self.say(&format!(
                "{} could not launch {}\n",
                self.icons.fail, agent.name
            ));
        }
    }

    /// Runs a child with the terminal as its stdin/stdout (our stdin is the pipe). Returns success.
    fn on_tty(bin: &str, args: &[String]) -> bool {
        let (Ok(tin), Ok(tout)) = (
            OpenOptions::new().read(true).open("/dev/tty"),
            OpenOptions::new().write(true).open("/dev/tty"),
        ) else {
            return false;
        };
        std::process::Command::new(bin)
            .args(args)
            .stdin(tin)
            .stdout(tout)
            .stderr(std::process::Stdio::inherit())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Resolves a decision point. `default` is the answer for a bare Enter.
    /// `Ask` with no terminal available is a safe abort, never a silent proceed.
    pub fn decide(&mut self, pre: Decision, question: &str, default: bool) -> Result<bool> {
        match (pre, self.auto) {
            (Decision::Yes, _) | (Decision::Ask, Auto::Yes) => Ok(true),
            (Decision::No, _) | (Decision::Ask, Auto::No) => Ok(false),
            (Decision::Ask, Auto::Prompt) => self.prompt(question, default),
        }
    }

    /// Prints to the terminal when one is available (stdout may be the script's).
    pub fn say(&mut self, text: &str) {
        match &mut self.tty {
            Some(t) => {
                let _ = t.output.write_all(text.as_bytes());
            }
            None => anstream::eprint!("{text}"),
        }
    }

    /// A spinner on the terminal; without one (or with animations off) the message is printed once.
    pub fn spinner(&mut self, message: &str) -> Spinner {
        let target = match &self.tty {
            Some(t) if self.ui.animations => match (t.output.try_clone(), t.output.try_clone()) {
                (Ok(r), Ok(w)) => {
                    ProgressDrawTarget::term(console::Term::read_write_pair(r, w), 15)
                }
                _ => ProgressDrawTarget::hidden(),
            },
            _ => ProgressDrawTarget::hidden(),
        };
        let spinner = Spinner::start(target, message.to_owned());
        if spinner.is_hidden() {
            self.say(&format!("{message}\n"));
        }
        spinner
    }

    /// A short animated hand-off so it is visible that review ended and the installer starts.
    pub fn launch(&mut self, label: &str, shell: &str) {
        let what = describe(label);
        let spinner = self.spinner(&format!(
            "{} starting {what} with {shell}",
            self.icons.launch
        ));
        if !spinner.is_hidden() {
            std::thread::sleep(Duration::from_millis(900));
        }
        spinner.finish(format!(
            "{} {}",
            self.icons.launch,
            ui::paint(ui::BOLD, format!("running {what} with {shell}"))
        ));
        self.say(&format!("{}\n", ui::paint(ui::DIM, "─".repeat(60))));
    }

    pub fn finished(&mut self, label: &str, code: i32) {
        let what = describe(label);
        let line = match code {
            0 => format!(
                "{} {}",
                self.icons.ok,
                ui::paint(ui::GREEN, format!("{what} finished"))
            ),
            n => format!(
                "{} {}",
                self.icons.fail,
                ui::paint(ui::RED, format!("{what} exited with code {n}"))
            ),
        };
        self.say(&format!("{}\n{line}\n", ui::paint(ui::DIM, "─".repeat(60))));
    }

    fn prompt(&mut self, question: &str, default: bool) -> Result<bool> {
        let Some(tty) = &mut self.tty else {
            bail!(
                "{question}: no terminal available to ask; aborting (set [interaction] or pass --yes)"
            );
        };
        let hint = if default { "[Y/n]" } else { "[y/N]" };
        write!(
            tty.output,
            "{} {question} {hint} ",
            ui::paint(ui::CYAN, "?")
        )
        .context("writing to /dev/tty")?;
        tty.output.flush()?;
        let mut line = String::new();
        if tty.input.read_line(&mut line).context("reading /dev/tty")? == 0 {
            bail!("{question}: terminal closed; aborting");
        }
        Ok(match line.trim().to_ascii_lowercase().as_str() {
            "" => default,
            "y" | "yes" => true,
            _ => false,
        })
    }
}
