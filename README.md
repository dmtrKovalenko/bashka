# bashka

A drop-in safety guard for the `curl … | bash` install pattern. Bashka parses the incoming script, scores it against many different checks, follows forwarded scripts so every layer is analyzed and if it found some unsafety it gives you an easy way to read a script or analyze using your AI agent.

Useage is simple as adding **ka** after the standard installation script

```sh
curl -fsSL https://pyenv.run | bashka
```

## Install

Install via bash. One last time.

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/dmtrKovalenko/bashka/main/install.sh | bash
```

> We guarantee absolute safety of this script! [Read it yourself](https://raw.githubusercontent.com/dmtrKovalenko/bashka/main/install.sh)

## Flags

Findings come in four kinds: 💀 **💀** (critically malicious, blocks hard), 🚩 **red** (dangerous),
🟡 **yellow** (advisory, never changes the verdict), ✅ **green** (good-citizen signal).

| kind   | id                     | what it looks for                                                                                                                                                       |
| ------ | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 💀   | `exfil_destination`    | sends data to webhook.site/Discord/Telegram/ngrok/paste sites, the cloud-metadata IP, or a raw IP (Codecov, Shai-Hulud)                                                 |
| 💀   | `credential_theft`     | reads SSH keys, cloud credentials, `.netrc`, the keychain                                                                                                               |
| 💀   | `exfiltration`         | environment or secrets sent to the network (`env \| curl`, `curl -d "$TOKEN"`)                                                                                          |
| 💀   | `reverse_shell`        | backdoors: `/dev/tcp`, `nc -e`, `socat EXEC`, `mkfifo` pipe-to-shell                                                                                                    |
| 🟢  | `checksum`             | download digest checked: `sha256sum -c`, `$(shasum …)` compared, `openssl dgst`                                                                                         |
| 🟢  | `cleanup_artifacts`    | `trap … EXIT`, or `rm` of a `mktemp` path                                                                                                                               |
| 🟢  | `https_only`           | every download URL uses HTTPS                                                                                                                                           |
| 🟢  | `install_dir`          | installs into `/usr/local/bin` or `~/.local/bin`                                                                                                                        |
| 🟢  | `privilege_escalation` | (🟢) never escalates; (yellow) uses `sudo`/`doas`                                                                                                                    |
| 🟢  | `strict_mode`          | `set -euo pipefail`                                                                                                                                                     |
| 🟢  | `tls_hardening`        | curl pins HTTPS-only and TLS 1.2+ (`--proto '=https' --tlsv1.2`)                                                                                                        |
| 🟢  | `trusted_domains`      | HTTPS downloads from GitHub, or the same domain the script was fetched from                                                                                             |
| 🟢  | `verify`               | signature verified: `gpg --verify`, `cosign`, `minisign`, `openssl dgst -verify`                                                                                        |
| 🔴    | `anti_forensics`       | hides tracks: `HISTFILE=/dev/null`, `history -c`, log truncation, `journalctl --vacuum`, killing EDR/audit agents                                                       |
| 🔴    | `banned_commands`      | `rm -rf /`, `dd of=/dev/*`, `mkfs`, fork bomb, `chmod -R 777`                                                                                                           |
| 🔴    | `domain_refs`          | plaintext HTTP, raw-IP hosts, URL shorteners                                                                                                                            |
| 🔴    | `env_hijack`           | hijacks auto-run hooks: `BASH_ENV`/`PROMPT_COMMAND`/`LD_PRELOAD`/`NODE_OPTIONS --require`, `sitecustomize.py`; `/etc/ld.so.preload` is 💀                             |
| 🔴    | `git_hooks`            | repoints git execution: `core.hooksPath`, `core.fsmonitor`, `alias.x '!cmd'`, or writes into `.git/hooks`                                                               |
| 🔴    | `insecure_tls`         | certificate checks off: `curl -k`, `--no-check-certificate`, `GIT_SSL_NO_VERIFY`                                                                                        |
| 🔴    | `install_name`         | downloads files but nothing names the software (no URL hint, product variable, GitHub repo or bin target); yellow when the script takes the project from its arguments  |
| 🔴    | `install_target`       | downloads files but never names where they are installed                                                                                                                |
| 🔴    | `macos_bypass`         | strips Gatekeeper quarantine (`xattr … com.apple.quarantine`), tampers with TCC; `osascript … hidden answer` password phish is 💀                                     |
| 🔴    | `max_commands`         | more commands than `limit` (stateful example)                                                                                                                           |
| 🔴    | `not_a_script`         | the body is an HTTP redirect stub, an HTML/JSON page, or has no recognizable command (fetch with `curl -fsSL`)                                                          |
| 🔴    | `obfuscation`          | `eval` of opaque code (`eval "$CMD"`, `eval $(…)`), decode-then-execute pipelines                                                                                       |
| 🔴    | `package_managers`     | pulls code from npm/npx/pip/cargo/go/gem/brew/docker or editor extensions; 🔴 on URL/git/mutable ref/foreign registry/`--privileged`, yellow on a plain global install |
| 🔴    | `path_suspicious`      | `PATH` gains a temp, relative or world-writable directory                                                                                                               |
| 🔴    | `remote_exec`          | fetch->exec forward sinks (drives chain following)                                                                                                                      |
| 🔴    | `scheduled_tasks`      | schedules code via cron, `at`, systemd timers, autostart or rc.local                                                                                                    |
| 🔴    | `security_tampering`   | disables firewall/SELinux/AppArmor/Gatekeeper/SIP                                                                                                                       |
| 🔴    | `self_extract`         | reads its own bytes (`$0`) with sed/tail/dd/base64 and pipes the result into a shell                                                                                    |
| 🔴    | `sensitive_write`      | writes to shell rc files, `~/.ssh`, `/etc/sudoers`, crontab                                                                                                             |
| 🔴    | `staged_installer`     | downloads a program and runs it to do the install; the second stage is opaque to review                                                                                 |
| 🔴    | `unicode_tricks`       | invisible, bidi, or homoglyph characters in a command name or URL, or a punycode host                                                                                   |
| 🔴    | `unsafe_rm`            | `rm -rf "$VAR/"` where the variable may be empty and there is no guard or `set -u`                                                                                      |
| 🔴    | `upload_exfil`         | uploads files (`curl -T`, `-F @file`, `--data @file`), copies out via scp/rsync, or DNS-exfil via `dig $(…)`                                                            |
| 🟡 | `checksum`             | green if checks a digest, yellow if downloads are unverified                                                                                                              |
| 🟡 | `many_downloads`       | fetches from more than `limit` distinct URLs (default 2)                                                                                                                |
| 🟡 | `mutable_refs`         | downloads from `master`/`main`/`HEAD`/`latest` instead of a pinned version                                                                                              |
| 🟡 | `package_repos`        | adds apt/yum/zypper repositories or signing keys                                                                                                                        |
| 🟡 | `persistence`          | installs systemd/launchd services or init scripts                                                                                                                       |
| 🟡 | `telemetry`            | sends data out (`POST`/`--data`, or analytics URLs)                                                                                                                     |

## CLI

Some of the additional commands

```
bashka list [--long]                 # table of software installed through bashka
bashka info <name>                   # everything recorded about one package
bashka update <name>                 # re-fetch the recorded installer and run it again
bashka remove <name> [--dry-run]     # delete every recorded binary and created directory, forget the package
bashka flags                         # list every registered flag with its options
bashka config init                   # print default configuration
```


## Install registry

bashka writes a lock file of everything it installed to `$XDG_DATA_HOME/bashka/installed.toml`
(`~/.local/share/bashka/installed.toml`; `BASHKA_LOCKFILE` overrides the path). er that exits
non-zero leaves no record.

`bashka list` prints package list, inspired by `pacman -Q`:

```
NAME  VERSION        INSTALLED   UPDATED     FILES          SOURCE
mise  2026..1       2026-0-15  -           1              https://mise.run
uv    0.9.2          2026-09-01  2026-09-15  2              https://astral.sh/uv/install.sh
demo  0.0.0-unknown  2026-09-15  -           2 (1 missing)  <stdin>
```

`bashka info <name>` (or `bashka list --long` for all) shows the full record in `pacman -Qi` style, with each binary and created directory on its own line and missing paths marked.

`bashka remove <name>` deletes the recorded binaries and created directories, then drops the entry. There is a possibility that bashka couldn't track where the file is installed (which is a red flag) but after your approval it will still be tracked but during the uninstall the binary files wouldn't be deleted.

`bashka update <name>` fetches the recorded URL again and runs it through the full review with the recorded options and shell arguments.

## Configuration

`~/.config/bashka/config.toml` is deep-merged over the embedded [`data/defaults.toml`](./data/defaults.toml).

```toml
[flags]
strict_mode     = false
max_commands    = { limit = 200 }
trusted_domains = { additional_domains = ["get.example.com"] }

[interaction]
on_red        = "ask"      # ask | abort | proceed
follow_remote = "always"   # ask | always | never
descend       = "hybrid"   # hybrid | fetch_ahead | shim
max_depth     = 5

[ui]
icons      = "emoji"       # emoji | nerd | ascii
animations = true          # spinners while fetching forwards and on hand-off
```

## Limitations

- Bash is Turing-complete. Even though we try to detect obfuscation it can evade static analysis.
- The shim intercepts `bash`/`sh` resolved through `PATH` but `/bin/bash` bypasses it.
- `trusted_domains` keeps a deliberately strict allowlist (GitHub only). Everything else is
  trusted only when it matches the domain the script was fetched from. Trusted domains can be modified via cofig using `trusted_domains = { additional_domains = ["get.acme.io"] }`.
- A server may serve different bytes at run time than at fetch-ahead.
- The install registry only sees executables that land in the watched directories. If bashka couldn't detect where the binaries went, but you still approved it - we won't be able to manage and uninstall the binary

## License

MIT and opensource. Support my work at https://github.com/sponsors/dmtrKovalenko
