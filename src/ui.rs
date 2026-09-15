use anstyle::{AnsiColor, Style};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IconSet {
    Emoji,
    /// Nerd Font glyphs (needs a patched font).
    Nerd,
    Ascii,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ui {
    pub icons: IconSet,
    /// Spinners while fetching forwarded scripts and when handing off to the shell.
    pub animations: bool,
}

impl Default for Ui {
    fn default() -> Self {
        Self {
            icons: IconSet::Emoji,
            animations: true,
        }
    }
}

pub struct Icons {
    pub dead: &'static str,
    pub red: &'static str,
    pub yellow: &'static str,
    pub green: &'static str,
    pub forward: &'static str,
    pub fetch: &'static str,
    pub launch: &'static str,
    pub ok: &'static str,
    pub fail: &'static str,
    pub blocked: &'static str,
}

impl IconSet {
    pub fn icons(self) -> Icons {
        match self {
            IconSet::Emoji => Icons {
                dead: "💀",
                red: "🚩",
                yellow: "🟡",
                green: "✅",
                forward: "↳ 📜",
                fetch: "🌐",
                launch: "🚀",
                ok: "✅",
                fail: "❌",
                blocked: "⛔",
            },
            IconSet::Nerd => Icons {
                dead: "\u{f0f8}",
                red: "\u{f024}",
                yellow: "\u{f071}",
                green: "\u{f058}",
                forward: "\u{f149} \u{f15c}",
                fetch: "\u{f0ac}",
                launch: "\u{f04b}",
                ok: "\u{f00c}",
                fail: "\u{f00d}",
                blocked: "\u{f05e}",
            },
            IconSet::Ascii => Icons {
                dead: "[DEAD]",
                red: "[RED]",
                yellow: "[YELLOW]",
                green: "[GREEN]",
                forward: "->",
                fetch: "~",
                launch: ">>",
                ok: "ok",
                fail: "x",
                blocked: "!!",
            },
        }
    }
}

pub const RED: Style = AnsiColor::Red.on_default().bold();
pub const GREEN: Style = AnsiColor::Green.on_default().bold();
pub const YELLOW: Style = AnsiColor::Yellow.on_default().bold();
pub const CYAN: Style = AnsiColor::Cyan.on_default().bold();
pub const BOLD: Style = Style::new().bold();
pub const DIM: Style = Style::new().dimmed();

pub fn paint(style: Style, text: impl std::fmt::Display) -> String {
    format!("{style}{text}{style:#}")
}

/// A spinner line; `hidden` targets produce no output at all.
pub struct Spinner(ProgressBar);

impl Spinner {
    pub fn start(target: ProgressDrawTarget, message: String) -> Self {
        let bar = ProgressBar::with_draw_target(None, target);
        let style = ProgressStyle::with_template("{spinner:.cyan.bold} {msg}")
            .expect("static template")
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", " "]);
        bar.set_style(style);
        bar.set_message(message);
        bar.enable_steady_tick(Duration::from_millis(80));
        Self(bar)
    }

    /// Replaces the spinner with a final line.
    pub fn finish(self, message: String) {
        self.0.finish_with_message(message);
    }

    pub fn clear(self) {
        self.0.finish_and_clear();
    }

    pub fn is_hidden(&self) -> bool {
        self.0.is_hidden()
    }
}
