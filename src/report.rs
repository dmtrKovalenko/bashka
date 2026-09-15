use crate::model::{Finding, FlagKind};
use crate::policy::{self, Outcome, Score};
use crate::ui::{self, Icons, paint};
use annotate_snippets::{AnnotationKind, Group, Level, Renderer, Snippet};
use std::fmt::Write;

/// One analyzed script in the chain.
pub struct Layer {
    pub depth: usize,
    /// `<stdin>` or the forwarded URL.
    pub label: String,
    pub source: String,
    pub findings: Vec<Finding>,
}

/// Least to most severe, so findings render green, then yellow, red, dead. Scrolling up from the
/// verdict line at the bottom, the reader meets the most serious findings first.
fn severity_rank(kind: FlagKind) -> u8 {
    match kind {
        FlagKind::Green => 0,
        FlagKind::Yellow => 1,
        FlagKind::Red => 2,
        FlagKind::Dead => 3,
    }
}

/// A width wide enough that annotate-snippets never truncates a source line with `...`: we always
/// show the full line. Long lines soft-wrap in the terminal; the underline is kept short (see
/// `cap`) so it still reads clearly.
fn term_width() -> usize {
    10_000
}

pub fn render(layers: &[Layer], icons: &Icons) -> String {
    let width = term_width();
    let mk = |r: Renderer| r.term_width(width);
    let dead_renderer = mk(Renderer::styled().error(ui::RED));
    let red_renderer = mk(Renderer::styled().error(ui::RED));
    let yellow_renderer = mk(Renderer::styled().warning(ui::YELLOW).context(ui::YELLOW));
    let green_renderer = mk(Renderer::styled().info(ui::GREEN).context(ui::GREEN));
    let mut out = String::new();
    for layer in layers {
        let indent = "  ".repeat(layer.depth);
        // Name the layer's source: forwarded layers always, the top layer when its URL was detected.
        if layer.depth > 0 {
            let _ = writeln!(
                out,
                "{indent}{} {}\n",
                icons.forward,
                paint(ui::BOLD, &layer.label)
            );
        } else if layer.label != "<stdin>" {
            let _ = writeln!(
                out,
                "{} source: {}\n",
                icons.fetch,
                paint(ui::BOLD, &layer.label)
            );
        }
        let mut ordered: Vec<&Finding> = layer.findings.iter().collect();
        ordered.sort_by_key(|f| severity_rank(f.kind)); // stable: source order kept within a kind
        for finding in ordered {
            let renderer = match finding.kind {
                FlagKind::Dead => &dead_renderer,
                FlagKind::Red => &red_renderer,
                FlagKind::Yellow => &yellow_renderer,
                FlagKind::Green => &green_renderer,
            };
            let text = renderer.render(&[group(layer, finding, icons)]);
            for line in text.lines() {
                let _ = writeln!(out, "{indent}{line}");
            }
            out.push('\n');
        }
    }
    out
}

/// The closing line: counts, then the verdict. A green verdict reads as the action about to
/// happen unless `check_only`. E.g. `✅ 4  🚩 0  INSTALLING | looks like a good script`.
pub fn verdict(layers: &[Layer], outcome: Outcome, check_only: bool, icons: &Icons) -> String {
    let all: Vec<Finding> = layers
        .iter()
        .flat_map(|l| l.findings.iter().cloned())
        .collect();
    let Score {
        deaths,
        reds,
        yellows,
        greens,
    } = policy::tally(&all);
    let text = match outcome {
        Outcome::Critical => paint(ui::RED, "DANGER | critically malicious, do not run"),
        Outcome::Green if check_only => paint(ui::GREEN, "GREEN | looks like a good script"),
        Outcome::Green => paint(ui::GREEN, "INSTALLING | looks like a good script"),
        Outcome::Neutral => paint(
            ui::YELLOW,
            "NEUTRAL | nothing alarming, little to vouch for it",
        ),
        Outcome::Red => paint(ui::RED, "RED | review the findings above"),
        Outcome::StrongGate => paint(
            ui::RED,
            "RED | multiple red flags, explicit confirmation required",
        ),
    };
    let layers_note = if layers.len() > 1 {
        format!(
            "  {}",
            paint(ui::DIM, format!("across {} layers", layers.len()))
        )
    } else {
        String::new()
    };
    let dead = if deaths > 0 {
        format!("{} {}  ", icons.dead, paint(ui::RED, deaths))
    } else {
        String::new()
    };
    format!(
        "{dead}{} {}  {} {}  {} {}  {text}{layers_note}\n",
        icons.green,
        paint(ui::GREEN, greens),
        icons.yellow,
        paint(ui::YELLOW, yellows),
        icons.red,
        paint(ui::RED, reds)
    )
}

fn group<'a>(layer: &'a Layer, f: &'a Finding, icons: &Icons) -> Group<'a> {
    let (level, tag) = match f.kind {
        FlagKind::Dead => (
            Level::ERROR.with_name(format!("{} ", icons.dead)),
            AnnotationKind::Primary,
        ),
        FlagKind::Red => (
            Level::ERROR.with_name(format!("{} ", icons.red)),
            AnnotationKind::Primary,
        ),
        FlagKind::Yellow => (
            Level::WARNING.with_name(format!("{} ", icons.yellow)),
            AnnotationKind::Context,
        ),
        FlagKind::Green => (
            Level::INFO.with_name(format!("{} ", icons.green)),
            AnnotationKind::Context,
        ),
    };
    let mut g = Group::with_title(level.primary_title(f.detail.title.as_str()).id(f.rule_id));
    if let Some(span) = &f.detail.span {
        g = g.element(
            Snippet::source(layer.source.as_str())
                .path(layer.label.as_str())
                .fold(true)
                .annotation(
                    tag.span(cap(
                        clamp(span.clone(), layer.source.len()),
                        layer.source.as_str(),
                    ))
                    .label(f.category.name()),
                ),
        );
    }
    g = g.element(Level::NOTE.message(f.detail.explanation.as_str()));
    if let Some(fix) = &f.detail.fix {
        g = g.element(Level::HELP.message(fix.as_str()));
    }
    g
}

fn clamp(span: std::ops::Range<usize>, len: usize) -> std::ops::Range<usize> {
    let start = span.start.min(len);
    start..span.end.clamp(start, len)
}

fn cap(span: std::ops::Range<usize>, src: &str) -> std::ops::Range<usize> {
    const MAX: usize = 40;
    if span.end - span.start <= MAX {
        return span;
    }
    let mut end = (span.start + MAX).min(src.len());
    while end > span.start && !src.is_char_boundary(end) {
        end -= 1; // never split a multibyte character
    }
    span.start..end
}
