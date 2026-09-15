pub type Span = std::ops::Range<usize>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagKind {
    /// Critically malicious: exfiltration, backdoors, credential theft. Forces a blocking gate.
    Dead,
    Red,
    /// Advisory: shown and counted, never changes the verdict.
    Yellow,
    Green,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Domain,
    Exec,
    Path,
    Obfuscation,
    Sensitive,
    Complexity,
    Remote,
}

impl Category {
    pub fn name(self) -> &'static str {
        match self {
            Category::Domain => "domain",
            Category::Exec => "exec",
            Category::Path => "path",
            Category::Obfuscation => "obfuscation",
            Category::Sensitive => "sensitive",
            Category::Complexity => "complexity",
            Category::Remote => "remote",
        }
    }
}

/// What a flag reports about one place in the script.
#[derive(Debug, Clone)]
pub struct Detail {
    pub title: String,
    pub explanation: String,
    pub fix: Option<String>,
    /// Byte range in the layer's source. The driver fills the visited node's span when a
    /// visit leaves it `None`; findings from `finalize` stay script-wide (`None`).
    pub span: Option<Span>,
}

impl Detail {
    pub fn new(title: impl Into<String>, explanation: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            explanation: explanation.into(),
            fix: None,
            span: None,
        }
    }

    pub fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }

    pub fn at(mut self, span: Span) -> Self {
        self.span = Some(span);
        self
    }
}

#[derive(Debug, Clone)]
pub enum Verdict {
    Ignore,
    Dead(Detail),
    Red(Detail),
    Yellow(Detail),
    Green(Detail),
}

/// A `Detail` stamped by the driver with its origin.
#[derive(Debug, Clone)]
pub struct Finding {
    pub kind: FlagKind,
    pub rule_id: &'static str,
    pub category: Category,
    pub detail: Detail,
    pub weight: u8,
}
