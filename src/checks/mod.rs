mod anti_forensics;
mod banned_commands;
mod checksum;
mod cleanup_artifacts;
mod credential_theft;
mod domain_refs;
mod env_hijack;
mod exfil_destination;
mod exfiltration;
mod git_hooks;
mod https_only;
mod insecure_tls;
mod install_dir;
mod install_name;
mod install_target;
mod macos_bypass;
mod many_downloads;
mod max_commands;
mod mutable_refs;
mod not_a_script;
mod obfuscation;
mod package_managers;
mod package_repos;
mod path_suspicious;
mod persistence;
mod privilege_escalation;
mod remote_exec;
mod reverse_shell;
mod scheduled_tasks;
mod security_tampering;
mod self_extract;
mod sensitive_write;
mod staged_installer;
mod strict_mode;
mod telemetry;
mod tls_hardening;
mod trusted_domains;
mod unicode_tricks;
mod unsafe_rm;
mod upload_exfil;
mod verify;

#[cfg(test)]
pub(crate) mod testing {
    use crate::analysis::{self, registry};
    use crate::config::Shared;
    use crate::model::Finding;
    use crate::parser;

    /// Runs only flag `id` (recommended config) over `src`.
    pub fn findings(id: &str, src: &str) -> Vec<Finding> {
        let reg = registry::find(id).unwrap_or_else(|| panic!("no flag `{id}`"));
        let flag = (reg.build)(None, &Shared::default())
            .unwrap()
            .expect("enabled by default");
        analysis::analyze(&parser::parse(src).unwrap(), &mut [(reg, flag)])
    }

    pub fn titles(id: &str, src: &str) -> Vec<String> {
        findings(id, src)
            .into_iter()
            .map(|f| f.detail.title)
            .collect()
    }

    pub fn fires(id: &str, src: &str) -> bool {
        !findings(id, src).is_empty()
    }

    pub fn kind(id: &str, src: &str) -> Option<crate::model::FlagKind> {
        findings(id, src).first().map(|f| f.kind)
    }

    /// Like `findings`, but the script is treated as having come from `origin`.
    pub fn findings_from(id: &str, origin: &str, src: &str) -> Vec<Finding> {
        let reg = registry::find(id).unwrap();
        let flag = (reg.build)(None, &Shared::default()).unwrap().unwrap();
        let mut ctx = parser::parse(src).unwrap();
        ctx.origin_host = crate::url::host(origin);
        ctx.origin = Some(origin.to_string());
        analysis::analyze(&ctx, &mut [(reg, flag)])
    }
}
