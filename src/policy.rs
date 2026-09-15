pub use crate::config::Policy;
use crate::model::{Finding, FlagKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Critical,
    Green,
    Neutral,
    Red,
    StrongGate,
}
#[derive(Debug, Clone, Copy, Default)]
pub struct Score {
    pub deaths: u32,
    pub reds: u32,
    pub yellows: u32,
    pub greens: u32,
}

pub fn tally(findings: &[Finding]) -> Score {
    findings.iter().fold(Score::default(), |mut s, f| {
        match f.kind {
            FlagKind::Dead => s.deaths += 1,
            FlagKind::Red => s.reds += 1,
            FlagKind::Yellow => s.yellows += 1,
            FlagKind::Green => s.greens += 1,
        }
        s
    })
}

pub fn score(findings: &[Finding]) -> Score {
    findings.iter().fold(Score::default(), |mut s, f| {
        match f.kind {
            FlagKind::Dead => s.deaths += u32::from(f.weight),
            FlagKind::Red => s.reds += u32::from(f.weight),
            FlagKind::Yellow => s.yellows += u32::from(f.weight),
            FlagKind::Green => s.greens += u32::from(f.weight),
        }
        s
    })
}

impl Policy {
    /// Yellows are advisory and do not move the outcome; any death is Critical.
    pub fn judge(&self, findings: &[Finding]) -> Outcome {
        let Score {
            deaths,
            reds,
            greens,
            ..
        } = score(findings);
        if deaths > 0 {
            return Outcome::Critical;
        }
        match reds {
            0 if greens >= self.green_min => Outcome::Green,
            0 => Outcome::Neutral,
            r if r >= self.strong_gate_reds => Outcome::StrongGate,
            _ => Outcome::Red,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Detail};

    fn f(kind: FlagKind) -> Finding {
        Finding {
            kind,
            rule_id: "t",
            category: Category::Exec,
            detail: Detail::new("t", "e"),
            weight: 1,
        }
    }

    #[test]
    fn thresholds() {
        let p = Policy::default();
        assert_eq!(
            p.judge(&[f(FlagKind::Green), f(FlagKind::Green), f(FlagKind::Green)]),
            Outcome::Green
        );
        assert_eq!(p.judge(&[f(FlagKind::Green)]), Outcome::Neutral);
        assert_eq!(
            p.judge(&[f(FlagKind::Red), f(FlagKind::Green)]),
            Outcome::Red
        );
        assert_eq!(
            p.judge(&[f(FlagKind::Red), f(FlagKind::Red), f(FlagKind::Red)]),
            Outcome::StrongGate
        );
        assert_eq!(
            p.judge(&[
                f(FlagKind::Green),
                f(FlagKind::Green),
                f(FlagKind::Green),
                f(FlagKind::Yellow)
            ]),
            Outcome::Green
        );
        assert_eq!(
            p.judge(&[
                f(FlagKind::Dead),
                f(FlagKind::Green),
                f(FlagKind::Green),
                f(FlagKind::Green)
            ]),
            Outcome::Critical
        );
    }
}
