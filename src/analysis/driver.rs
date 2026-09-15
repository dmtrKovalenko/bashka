use crate::analysis::registry::{Flag, FlagRegistration};
use crate::model::{Finding, FlagKind, Span, Verdict};
use crate::parser::{Ctx, Node};

pub type BuiltFlag = (&'static FlagRegistration, Box<dyn Flag>);

pub fn analyze(ctx: &Ctx, flags: &mut [BuiltFlag]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (_reg, flag) in flags.iter_mut() {
        flag.begin(ctx);
    }
    for node in &ctx.nodes {
        for (reg, flag) in flags.iter_mut() {
            let verdict = match node {
                Node::Command(c) => flag.visit_command(c),
                Node::Pipeline(p) => flag.visit_pipeline(p),
                Node::Assignment(a) => flag.visit_assignment(a),
            };
            stamp(&mut out, reg, verdict, Some(node.span().clone()));
        }
    }
    for (reg, flag) in flags.iter_mut() {
        let verdict = flag.finalize(ctx);
        stamp(&mut out, reg, verdict, None);
    }
    out
}

fn stamp(
    out: &mut Vec<Finding>,
    reg: &'static FlagRegistration,
    verdict: Verdict,
    fallback: Option<Span>,
) {
    let (kind, mut detail) = match verdict {
        Verdict::Ignore => return,
        Verdict::Dead(d) => (FlagKind::Dead, d),
        Verdict::Red(d) => (FlagKind::Red, d),
        Verdict::Yellow(d) => (FlagKind::Yellow, d),
        Verdict::Green(d) => (FlagKind::Green, d),
    };
    detail.span = detail.span.take().or(fallback);
    out.push(Finding {
        kind,
        rule_id: reg.id,
        category: reg.category,
        detail,
        weight: reg.weight,
    });
}
