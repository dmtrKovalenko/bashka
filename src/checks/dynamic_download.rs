use crate::analysis::Flag;
use crate::config::{NoConfig, Shared};
use crate::model::{Detail, Verdict};
use crate::parser::Command;
use crate::register_flag;

pub struct DynamicDownload {
    shared: Shared,
    reported: bool,
}

/// Options whose next word is a value, never the URL / repository.
fn takes_value(c: &Command, opt: &str) -> bool {
    if crate::config::base_name(&c.name) == "git" {
        return matches!(
            opt,
            "-b" | "--branch"
                | "--depth"
                | "-c"
                | "--config"
                | "-o"
                | "--origin"
                | "-u"
                | "--upload-pack"
                | "--template"
                | "--reference"
                | "--separate-git-dir"
                | "-j"
                | "--jobs"
                | "--filter"
        );
    }
    matches!(
        opt,
        "-o" | "--output"
            | "-O"
            | "-H"
            | "--header"
            | "-d"
            | "--data"
            | "-A"
            | "--user-agent"
            | "--max-time"
            | "--connect-timeout"
            | "--retry"
            | "-u"
            | "--user"
            | "-P"
            | "--directory-prefix"
    )
}

/// The URL operand is nothing but a command substitution: `curl -o f "$(get url)"`,
/// `git clone "$(get repo)"`. A quoted `'$(…)'` is literal text and does not count.
fn substituted_url(c: &Command) -> Option<&crate::parser::Word> {
    let args: Vec<&crate::parser::Word> = c.args.iter().collect();
    let mut skip = false;
    for (i, w) in args.iter().enumerate() {
        if skip {
            skip = false;
            continue;
        }
        let t = w.text.as_str();
        if t.starts_with('-') {
            skip = takes_value(c, t) && args.get(i + 1).is_some();
            continue;
        }
        if t == "clone" {
            continue;
        }
        let whole =
            (t.starts_with("$(") && t.ends_with(')')) || (t.starts_with('`') && t.ends_with('`'));
        if !w.literal && whole && !t.contains("://") {
            return Some(w);
        }
    }
    None
}

impl Flag for DynamicDownload {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if self.reported || !self.shared.downloads(c) {
            return Verdict::Ignore;
        }
        let Some(w) = substituted_url(c) else {
            return Verdict::Ignore;
        };

        let url_expression = &w.text;
        self.reported = true;
        Verdict::Red(
            Detail::new(
                format!("fetches a url that is constructed from the io at runtime, impossible to inspect: `{url_expression}`"),
                "The URL is not written in the script, not even as a template like \
                 `$BASE/releases/download/$VERSION/tool.tgz`; it is the output of another command, \
                 typically a field parsed out of a reply the server gave earlier.",
            )
            .fix(
                "Find the command that produces the URL. If it reads a server reply, treat the \
                 download as untrusted; a release URL that the script names itself, even with \
                 `$VERSION` filled in, would not be flagged.",
            )
            .at(w.span.clone()),
        )
    }
}

register_flag! {
    id: "dynamic_download",
    kind: Red,
    category: Remote,
    description: "Download URL is entirely another command's output, e.g. a field from a server reply (`curl \"$(get url)\"`); templated URLs like `$BASE/$VERSION/x` are fine",
    config: NoConfig,
    build: |_cfg, shared| DynamicDownload { shared: shared.clone(), reported: false },
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;

    #[test]
    fn fires_on_substituted_urls() {
        assert!(fires(
            "dynamic_download",
            "curl -fsL --max-time 120 -o \"$tmp.tgz\" \"$(get url)\""
        ));
        assert!(fires(
            "dynamic_download",
            "wget -O t.tgz \"$(jq -r .url rep.json)\""
        ));
        assert!(fires(
            "dynamic_download",
            "git clone --depth 1 -b \"$(get branch)\" \"$(get repo)\" \"$dir\""
        ));
    }

    #[test]
    fn literal_substitution_text_is_not_a_substitution() {
        assert!(!fires("dynamic_download", "curl -o f '$(get url)'"));
        assert!(!fires("dynamic_download", "curl -o f \\$(get url)"));
        assert!(!fires(
            "dynamic_download",
            "git clone --depth 1 -b \"$(get branch)\" https://x.io/r.git"
        ));
    }

    #[test]
    fn ignores_interpolated_and_literal_urls() {
        assert!(!fires(
            "dynamic_download",
            "curl -fsSL \"$BASE/$VERSION/tool.tgz\" -o t.tgz"
        ));
        assert!(!fires(
            "dynamic_download",
            "curl -fsSL \"https://x.io/$(uname -m)/tool.tgz\" -o t.tgz"
        ));
        assert!(!fires(
            "dynamic_download",
            "curl -fsSL https://x.io/t.tgz -o \"$(mktemp)\""
        ));
        assert!(!fires(
            "dynamic_download",
            "V=$(curl -s https://x.io/latest)"
        ));
    }
}
