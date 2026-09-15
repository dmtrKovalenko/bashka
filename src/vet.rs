use crate::agents;
use crate::chain;
use crate::cli::Options;
use crate::config::Config;
use crate::interaction::{Auto, Prompter};
use crate::policy::Outcome;
use crate::report;
use crate::runner::{Inherit, Runner};
use crate::ui::{self, paint};
use anyhow::Result;

pub struct Session {
    pub config: Config,
    pub opts: Options,
    pub prompter: Prompter,
}

pub struct Approval {
    pub vetted: Vec<String>,
    pub needs_shim: bool,
    /// Every layer analyzed ahead of time (the install registry watches their destinations).
    pub layers: Vec<crate::report::Layer>,
}

impl Session {
    pub fn new(opts: Options) -> Result<Self> {
        let config = crate::config::load(opts.config.as_deref())?;
        for unknown in config.unknown_flags() {
            anstream::eprintln!(
                "{} unknown flag `{unknown}` in [flags] (typo?)",
                paint(ui::YELLOW, "warning:")
            );
        }
        config.build_flags()?; // eager validation
        let auto = if opts.yes {
            Auto::Yes
        } else if opts.non_interactive {
            Auto::No
        } else {
            Auto::Prompt
        };
        let prompter = Prompter::new(auto, config.ui.clone());
        Ok(Self {
            config,
            opts,
            prompter,
        })
    }

    /// Analyzes `source` and everything it forwards to, renders the report, and returns the verdict.
    pub fn check(&mut self, source: String, label: String, depth: usize) -> Result<Outcome> {
        self.analyze(source, label, depth)
            .map(|(outcome, _)| outcome)
    }

    fn analyze(
        &mut self,
        source: String,
        label: String,
        depth: usize,
    ) -> Result<(Outcome, chain::Analysis)> {
        let chain_opts = chain::Options {
            config: &self.config,
            descend: self.opts.descend.unwrap_or(self.config.interaction.descend),
            max_depth: self
                .opts
                .max_depth
                .unwrap_or(self.config.interaction.max_depth),
        };
        let mut analysis = chain::analyze(source, label, depth, &chain_opts, &mut self.prompter)?;
        if self.opts.name.is_some() {
            // The user named the software; the missing-name flag has nothing to add.
            for layer in &mut analysis.layers {
                layer.findings.retain(|f| f.rule_id != "install_name");
            }
        }
        let all: Vec<_> = analysis
            .layers
            .iter()
            .flat_map(|l| l.findings.iter().cloned())
            .collect();
        let outcome = self.config.policy.judge(&all);
        let text = report::render(&analysis.layers, &self.prompter.icons);
        self.prompter.say(&text);
        let verdict = report::verdict(
            &analysis.layers,
            outcome,
            self.opts.check,
            &self.prompter.icons,
        );
        self.prompter.say(&verdict);
        Ok((outcome, analysis))
    }

    /// Analyzes, reports, and resolves the decision points; `Ok(None)` means the user (or config) declined.
    pub fn vet(&mut self, source: &str, label: String, depth: usize) -> Result<Option<Approval>> {
        let (outcome, analysis) = self.analyze(source.to_owned(), label, depth)?;
        let dangerous = matches!(
            outcome,
            Outcome::Red | Outcome::StrongGate | Outcome::Critical
        );
        let approved = if dangerous && self.prompter.is_interactive() {
            // Interactive terminal: offer the read / analyze / run action menu.
            self.action_menu(source, &analysis, outcome)?
        } else {
            self.programmatic_decision(outcome)?
        };
        if !approved {
            let hint = match outcome {
                Outcome::Critical => "  (critical findings cannot be bypassed with --force)",
                Outcome::StrongGate if !self.prompter.is_interactive() => {
                    "  (pass --force to run it anyway, or run interactively to review)"
                }
                _ => "",
            };
            let line = format!(
                "{} {}{}\n",
                self.prompter.icons.blocked,
                paint(ui::RED, "ABORTED | not running the script"),
                paint(ui::DIM, hint)
            );
            self.prompter.say(&line);
            return Ok(None);
        }
        Ok(Some(Approval {
            vetted: analysis.vetted,
            needs_shim: analysis.needs_shim,
            layers: analysis.layers,
        }))
    }

    /// Non-interactive resolution (config pre-answers, `--yes`/`--force`, safe abort).
    fn programmatic_decision(&mut self, outcome: Outcome) -> Result<bool> {
        let interaction = &self.config.interaction;
        Ok(match outcome {
            Outcome::Green => true,
            Outcome::Neutral => {
                self.prompter
                    .decide(interaction.on_neutral.into(), "Run the script?", true)?
            }
            Outcome::Red => self.prompter.decide(
                interaction.on_red.into(),
                "Red flags found. Run it anyway?",
                false,
            )?,
            // --force can push a strong gate through, but never a critical (dead-flag) verdict.
            Outcome::StrongGate if self.opts.force => true,
            Outcome::StrongGate | Outcome::Critical => false,
        })
    }

    /// The interactive menu shown when dangerous findings are caught on a terminal.
    fn action_menu(
        &mut self,
        source: &str,
        analysis: &chain::Analysis,
        outcome: Outcome,
    ) -> Result<bool> {
        let findings: Vec<_> = analysis
            .layers
            .iter()
            .flat_map(|l| l.findings.iter())
            .collect();
        let summary = findings
            .iter()
            .map(|f| format!("- [{}] {}", f.rule_id, f.detail.title))
            .collect::<Vec<_>>()
            .join("\n");
        let icons = &self.prompter.icons;
        let icon = if outcome == Outcome::Critical {
            icons.dead
        } else {
            icons.red
        };

        let header = format!("{icon} bashka caught the behavior above. What now?");
        loop {
            let choice = self.prompter.menu(
                &header,
                &[
                    ('r', "Read the script then decide"),
                    ('a', "Analyze it with an AI agent"),
                    ('x', "Run it anyway"),
                    ('q', "Abort"),
                ],
                'q',
            )?;
            match choice {
                'r' => {
                    self.prompter.page(source);
                    // After reading, the run/abort answer is final (does not loop back to the menu).
                    return Ok(self.prompter.menu(
                        &format!("{} Run the script now?", self.prompter.icons.launch),
                        &[('x', "Run it"), ('q', "Abort")],
                        'q',
                    )? == 'x');
                }
                'a' => self.analyze_with_agent(&summary, source)?,
                'x' => return Ok(true),
                _ => return Ok(false),
            }
        }
    }

    /// Sub-menu: pick an installed AI agent, or copy the review prompt.
    fn analyze_with_agent(&mut self, summary: &str, source: &str) -> Result<()> {
        let prompt = agents::review_prompt(summary, source);
        let available = agents::available();
        let mut options: Vec<(char, String)> = available
            .iter()
            .enumerate()
            .map(|(i, a)| {
                (
                    char::from(b'1' + u8::try_from(i).unwrap_or(8)),
                    a.name.to_string(),
                )
            })
            .collect();

        options.push(('c', "Copy the review prompt to the clipboard".to_string()));
        options.push(('b', "Back".to_string()));
        let opt_refs: Vec<(char, &str)> = options.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let header = if available.is_empty() {
            let known = agents::AGENTS
                .iter()
                .map(|a| a.bin)
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "{} No AI agent found on PATH (looked for {known}).",
                self.prompter.icons.yellow
            )
        } else {
            format!("{} Analyze with which agent?", self.prompter.icons.fetch)
        };

        let choice = self.prompter.menu(&header, &opt_refs, 'b')?;
        if choice == 'c' {
            if let Some(tool) = agents::copy_to_clipboard(&prompt) {
                self.prompter.say(&format!(
                    "{} review prompt copied to clipboard via {tool}\n",
                    self.prompter.icons.ok
                ));
            } else {
                self.prompter
                    .say("no clipboard tool found; the prompt follows:\n\n");
                self.prompter.say(&prompt);
                self.prompter.say("\n");
            }
            return Ok(());
        }
        if let Some(idx) = choice.to_digit(10).map(|d| d as usize).filter(|d| *d >= 1)
            && let Some(agent) = available.get(idx - 1)
        {
            self.prompter.run_agent(agent, &prompt);
        }
        Ok(())
    }

    /// Hands an approved layer to the shell with a visible launch and epilogue.
    pub fn run(
        &mut self,
        label: &str,
        shell: &str,
        source: &str,
        shell_args: &[String],
        inherit: &Inherit,
        with_shim: bool,
    ) -> Result<i32> {
        self.prompter.launch(label, shell);
        let code = Runner::new(with_shim)?.run(shell, source, shell_args, inherit)?;
        self.prompter.finished(label, code);
        Ok(code)
    }
}
