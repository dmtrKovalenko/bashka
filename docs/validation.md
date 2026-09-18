# Corpus validation (2026-09-18)

`bashka --check` (verdict taken from the exit code) over every installer in `installers.toml`, with `follow_remote = "always"`; nothing is executed.

The harness feeds each script on stdin without a real `curl`, so origin-based trust is not exercised: installers served from a vanity domain show NEUTRAL here but are GREEN under real `curl <url> | bashka` use.

Verdicts: DEAD 2, RED 16, NEUTRAL 13, GREEN 30.

| installer | verdict | layers | findings | notes |
|---|---|---|---|---|
| k3s | DEAD | 1 | checksum, cleanup_artifacts, https_only, install_dir, many_downloads, mutable_refs, obfuscation, persistence, privilege_escalation, staged_installer, trusted_domains×2 |  |
| pulumi | DEAD | 1 | cleanup_artifacts, https_only, many_downloads, privilege_escalation, trusted_domains×2 |  |
| atuin | RED | 1 | https_only, mutable_refs, privilege_escalation, sensitive_write×2, tls_hardening, trusted_domains |  |
| bun | RED | 1 | https_only, privilege_escalation, staged_installer, strict_mode, trusted_domains |  |
| cargo-binstall | RED | 1 | https_only, mutable_refs, privilege_escalation, staged_installer, strict_mode, tls_hardening, trusted_domains |  |
| clickhouse | RED | 1 | https_only, many_downloads, not_a_script |  |
| croc | RED | 1 | https_only, not_a_script |  |
| deno | RED | 1 | https_only, privilege_escalation, staged_installer |  |
| fermyon-spin | RED | 1 | https_only, privilege_escalation, staged_installer, strict_mode, trusted_domains |  |
| flux | RED | 1 | cleanup_artifacts, https_only, install_dir, obfuscation, privilege_escalation, trusted_domains×2 |  |
| infisical | RED | 1 | checksum, cleanup_artifacts, https_only, obfuscation×2, package_repos, privilege_escalation |  |
| n | RED | 1 | https_only, package_managers, privilege_escalation |  |
| pnpm | RED | 1 | checksum, cleanup_artifacts, https_only, privilege_escalation, staged_installer, trusted_domains, verify |  |
| pyenv | RED | 2 | checksum, https_only×2, mutable_refs, privilege_escalation×2, remote_exec, trusted_domains×2 |  |
| rustup | RED | 1 | https_only, privilege_escalation, staged_installer, tls_hardening |  |
| rye | RED | 1 | cleanup_artifacts, https_only, privilege_escalation, staged_installer, strict_mode, trusted_domains |  |
| uv | RED | 1 | checksum, https_only, privilege_escalation, staged_installer, trusted_domains |  |
| wasmer | RED | 1 | https_only, obfuscation×5, privilege_escalation, trusted_domains×2 |  |
| docker | NEUTRAL | 1 | https_only, many_downloads |  |
| duckdb | NEUTRAL | 1 | https_only, many_downloads, privilege_escalation |  |
| fisher | NEUTRAL | 1 |  |  |
| flyctl | NEUTRAL | 1 | https_only, privilege_escalation |  |
| heroku | NEUTRAL | 1 | https_only, install_dir, privilege_escalation |  |
| jabba | NEUTRAL | 1 | https_only, mutable_refs, trusted_domains |  |
| oh-my-fish | NEUTRAL | 1 |  | <stdin>: shebang `fish` is not a bash dialect; findings may be incomplete |
| oh-my-zsh | NEUTRAL | 1 | https_only, privilege_escalation, trusted_domains |  |
| tailscale | NEUTRAL | 1 | checksum, https_only, many_downloads, package_repos, persistence, privilege_escalation |  |
| tilt | NEUTRAL | 1 | cleanup_artifacts, install_dir, privilege_escalation |  |
| volta | NEUTRAL | 1 | checksum, https_only, privilege_escalation |  |
| zoxide | NEUTRAL | 1 | https_only, mutable_refs, privilege_escalation, trusted_domains |  |
| zplug | NEUTRAL | 1 |  |  |
| bob | GREEN | 1 | https_only, install_dir, mutable_refs, privilege_escalation, trusted_domains |  |
| chezmoi | GREEN | 1 | checksum, cleanup_artifacts, https_only, privilege_escalation, trusted_domains |  |
| dagger | GREEN | 1 | checksum, cleanup_artifacts, https_only, privilege_escalation, trusted_domains |  |
| devbox | GREEN | 1 | https_only, install_dir, many_downloads, privilege_escalation, strict_mode, trusted_domains |  |
| eget | GREEN | 1 | checksum, https_only, mutable_refs, privilege_escalation, trusted_domains |  |
| fnm | GREEN | 1 | https_only, mutable_refs, privilege_escalation, trusted_domains |  |
| grype | GREEN | 1 | checksum, cleanup_artifacts, https_only, many_downloads, privilege_escalation, trusted_domains×2 |  |
| gvm | GREEN | 1 | https_only, privilege_escalation, trusted_domains |  |
| helm | GREEN | 1 | cleanup_artifacts, https_only, many_downloads, mutable_refs×2, privilege_escalation, trusted_domains×2, verify |  |
| homebrew | GREEN | 1 | cleanup_artifacts, https_only, privilege_escalation, trusted_domains |  |
| just | GREEN | 1 | cleanup_artifacts, https_only, mutable_refs, privilege_escalation, strict_mode, tls_hardening, trusted_domains×2 |  |
| k3d | GREEN | 1 | checksum, cleanup_artifacts, https_only, privilege_escalation, tls_hardening, trusted_domains |  |
| kustomize | GREEN | 1 | cleanup_artifacts, https_only, privilege_escalation, trusted_domains |  |
| mcfly | GREEN | 1 | cleanup_artifacts, https_only, install_name, mutable_refs, privilege_escalation, trusted_domains×2 |  |
| meilisearch | GREEN | 1 | cleanup_artifacts, https_only, privilege_escalation, trusted_domains×2 |  |
| mise | GREEN | 1 | cleanup_artifacts, https_only, privilege_escalation, trusted_domains |  |
| nix | GREEN | 1 | checksum, cleanup_artifacts, https_only, privilege_escalation |  |
| nvm | GREEN | 1 | https_only, privilege_escalation, trusted_domains×2 |  |
| ollama | GREEN | 1 | checksum, cleanup_artifacts, https_only, install_dir, many_downloads, package_repos, persistence, privilege_escalation |  |
| railway | GREEN | 1 | cleanup_artifacts, https_only, mutable_refs, privilege_escalation, trusted_domains×2 |  |
| rke2 | GREEN | 1 | checksum, cleanup_artifacts, https_only, many_downloads, persistence, privilege_escalation, trusted_domains |  |
| sdkman | GREEN | 1 | cleanup_artifacts, https_only, privilege_escalation |  |
| sentry-cli | GREEN | 1 | cleanup_artifacts, https_only, install_dir, privilege_escalation |  |
| starship | GREEN | 1 | https_only, install_dir, privilege_escalation, trusted_domains |  |
| surrealdb | GREEN | 1 | https_only, install_dir, privilege_escalation |  |
| syft | GREEN | 1 | checksum, cleanup_artifacts, https_only, many_downloads, privilege_escalation, trusted_domains×2 |  |
| trivy | GREEN | 1 | checksum, cleanup_artifacts, https_only, privilege_escalation, trusted_domains |  |
| wasmedge | GREEN | 1 | https_only, mutable_refs, privilege_escalation, trusted_domains |  |
| wasmtime | GREEN | 1 | checksum, https_only, mutable_refs, privilege_escalation, trusted_domains |  |
| zinit | GREEN | 1 | cleanup_artifacts, https_only, privilege_escalation, trusted_domains |  |
