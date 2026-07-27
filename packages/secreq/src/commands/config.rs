//! Authoring and inspecting `wraps.json5`: `secreq wrap` / `unwrap` /
//! `wraps` / `edit` / `check` / `doctor`, plus the serializer every one of
//! those (and `ssh add`, and `init`) writes the file through.
//!
//! [`write_config`] is the single writer. It round-trips the serialized
//! text back through the parser before touching the file, so a config we
//! cannot re-read is never the one on disk.

use std::collections::BTreeMap;
use std::io::IsTerminal as _;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::path_setup;
use crate::provider;
use crate::reference::Reference;
use crate::shim;
use crate::wraps::{self, Wrap, WrapsConfig};

use super::binaries::first_on_path;
use super::{prompt, resolve_config_path, which_on_path};

/// Args for `secreq wrap`.
#[derive(Debug, Clone, Default)]
pub struct WrapArgs {
    pub binary: String,
    pub reason: Option<String>,
    pub envs: Vec<String>, // each: "ENV_NAME=secret://provider/locator"
}

/// `secreq wrap <BINARY>` — add (or update) a wrap entry and install the
/// shim. Interactive when `envs` is empty; non-interactive otherwise.
pub fn wrap(args: WrapArgs, config_path: Option<&Path>) -> Result<i32> {
    let config_path = resolve_config_path(config_path)?;
    let mut config = if config_path.is_file() {
        WrapsConfig::load(&config_path)?
    } else {
        WrapsConfig::default()
    };
    // Overlay the built-ins so the interactive picker can offer them even
    // when the user has no `providers` block. `write_config` filters
    // built-ins back out, so the file on disk doesn't get them baked in.
    config.merge_builtin_providers();

    if args.binary.starts_with('-') || args.binary.contains('/') {
        bail!(
            "`{}` is not a plain binary name; the wrap name is the executable filename only",
            args.binary
        );
    }

    let shim_dir = config
        .shim_dir
        .clone()
        .context("no $shim_dir configured; run `secreq init` first")?;

    // Interactive flow gets a banner; non-interactive (flags supplied, or
    // no terminal to prompt on) stays quiet so it composes cleanly with
    // scripts.
    let interactive = args.envs.is_empty() && std::io::stdin().is_terminal();
    if interactive {
        crate::term::soft_reset();
        cliclack::intro(format!("Wrap `{}`", args.binary))?;
    }

    // Build the env map. Three paths:
    //  - `--env` flags supplied → parse them (non-interactive).
    //  - interactive terminal   → ask gate-only vs inject-secrets.
    //  - no flags, no terminal  → gate-only. There's nothing to inject and
    //    nothing to prompt on, so absence of `--env` means "just gate it".
    // An empty env map is a *gate-only* wrap: consent is still required,
    // but nothing is resolved or injected. Used to gate tools like `op`.
    let env: BTreeMap<String, String> = if !args.envs.is_empty() {
        parse_env_assignments(&args.envs)?
    } else if interactive {
        if prompt::wrap_is_gate_only()? {
            BTreeMap::new()
        } else {
            // Suggest secrets already referenced by other wraps — computed
            // before the new wrap is inserted, so it only offers prior work.
            let known = config.known_secret_refs();
            prompt::interactive_wrap_envs(&config.providers, &known)?
        }
    } else {
        BTreeMap::new()
    };

    let reason = args.reason.or_else(|| {
        if interactive {
            prompt::optional_read("Reason (shown in consent prompt)")
                .ok()
                .flatten()
        } else {
            None
        }
    });
    let wrap = Wrap {
        name: args.binary.clone(),
        reason,
        env,
    };
    // An empty env means we created a gate-only wrap. Read off `wrap` here,
    // before the insert takes it — reading it back out of the map afterwards
    // meant re-establishing that the key we just wrote is still there.
    let gate_only = wrap.env.is_empty();
    config.wraps.insert(args.binary.clone(), wrap);

    // Validate by round-tripping through the parser before writing.
    write_config(&config_path, &config)?;

    // Drop the shim.
    let shim_path = shim::install(&shim_dir, &args.binary)?;

    let kind = if gate_only {
        " (gate-only — consent required, nothing injected)"
    } else {
        ""
    };
    let summary = format!(
        "config: {}\n  shim: {}",
        crate::daemon::ui::abbreviate_home(&config_path.display().to_string()),
        crate::daemon::ui::abbreviate_home(&shim_path.display().to_string())
    );
    if interactive {
        // Only the headline goes through the wrapper. The two `summary` rows
        // are an indented label-and-path layout, and both paths are already
        // abbreviated — reflowing them would buy nothing and could strand the
        // indent. `println!` needs no wrapping at all: stdout is not a
        // cliclack surface, and the terminal reflows it correctly.
        cliclack::outro(format!(
            "{}\n  {summary}",
            crate::term::wrap_log_text(&format!("Wrapped `{}`{kind}.", args.binary))
        ))?;
    } else {
        println!("Wrapped `{}`{kind}.\n  {summary}", args.binary);
    }

    if !path_setup::path_includes(&shim_dir) {
        cliclack::log::warning(crate::term::wrap_log_text(&format!(
            "{} isn't on your current PATH. The shim is installed but new shells won't find it until you source your shell config (or open a new terminal). Run `secreq init` to wire up PATH.",
            crate::daemon::ui::abbreviate_home(&shim_dir.display().to_string())
        )))?;
    }
    Ok(0)
}

/// `secreq unwrap <BINARY>` — remove the wrap entry and the shim.
pub fn unwrap_cmd(binary: &str, config_path: Option<&Path>) -> Result<i32> {
    let config_path = resolve_config_path(config_path)?;
    if !config_path.is_file() {
        bail!("no config at {}", config_path.display());
    }
    let mut config = WrapsConfig::load(&config_path)?;
    let removed = config.wraps.remove(binary).is_some();
    let shim_removed = if let Some(shim_dir) = &config.shim_dir {
        shim::remove(shim_dir, binary)?
    } else {
        false
    };
    write_config(&config_path, &config)?;
    // The daemon's approvals cache may still hold entries for this wrap, and
    // nothing here can reach them: they are keyed on a `ProcessIdentity` this
    // process cannot enumerate, and they carry no TTL — the parent process's
    // own lifetime is their expiry (see `consent::ApprovalEntry`). So an
    // entry survives until its parent exits or the daemon does, and
    // `secreq daemon stop` is the way to clear one deliberately.
    match (removed, shim_removed) {
        (true, true) => println!("Unwrapped `{binary}` (config + shim removed)."),
        (true, false) => println!("Removed config entry for `{binary}` (no shim was present)."),
        (false, true) => println!("Removed shim for `{binary}` (no config entry was present)."),
        (false, false) => println!("Nothing to remove for `{binary}`."),
    }
    Ok(0)
}

/// `secreq wraps` — list configured wraps.
pub fn wraps_list(config_path: Option<&Path>) -> Result<i32> {
    let config_path = resolve_config_path(config_path)?;
    if !config_path.is_file() {
        println!("(no config at {})", config_path.display());
        return Ok(0);
    }
    let config = WrapsConfig::load(&config_path)?;
    if config.wraps.is_empty() {
        println!("(no wraps configured)");
        return Ok(0);
    }
    for wrap in config.wraps.values() {
        let reason = wrap.reason.as_deref().unwrap_or("");
        let reason_suffix = if reason.is_empty() {
            String::new()
        } else {
            format!(" — {reason}")
        };
        println!("{}{}", wrap.name, reason_suffix);
        for (name, ref_str) in &wrap.env {
            // Render the provider (and a short locator) but never the value.
            let summary = match Reference::parse(ref_str) {
                Some(r) => format!("{} ({})", name, r.provider),
                None => format!("{} (bare locator)", name),
            };
            println!("    {summary}");
        }
    }
    Ok(0)
}

/// `secreq edit` — open the wraps config in `$EDITOR`.
pub fn edit_cmd(config_path: Option<&Path>) -> Result<i32> {
    let config_path = resolve_config_path(config_path)?;
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vi".to_owned());

    // Seed an empty config so `$EDITOR` opens something. The third writer of
    // this file, and the first one a new user reaches — it created the config
    // at the umask for the same reason [`write_config`] did, and takes the
    // same `Mode::Like` (which resolves to 0600 here, the destination being
    // absent by construction). `atomic::replace` makes the parent, so the
    // `create_dir_all` this replaced is no longer needed.
    if !config_path.exists() {
        crate::atomic::replace(
            &config_path,
            b"{\n}\n",
            crate::atomic::Mode::Like(&config_path),
        )?;
    }
    let status = Command::new(&editor)
        .arg(&config_path)
        .status()
        .with_context(|| format!("failed to launch $EDITOR ({editor})"))?;
    Ok(status.code().unwrap_or(0))
}

/// `secreq check` — validate the config.
pub fn check(config_path: Option<&Path>) -> Result<i32> {
    let config_path = resolve_config_path(config_path)?;
    if !config_path.is_file() {
        println!(
            "✗ no config at {} (run `secreq init`)",
            config_path.display()
        );
        return Ok(1);
    }
    let mut config = WrapsConfig::load(&config_path)?;
    config.merge_builtin_providers();

    let mut problems = 0;
    println!("Config: {}", config_path.display());

    // Every env entry must reference a known provider.
    for wrap in config.wraps.values() {
        for (env_name, ref_str) in &wrap.env {
            let Some(reference) = Reference::parse(ref_str) else {
                println!(
                    "  ✗ {}.env.{}: not a valid `secret://provider/locator` reference",
                    wrap.name, env_name
                );
                problems += 1;
                continue;
            };
            if !config.providers.contains_key(&reference.provider) {
                println!(
                    "  ✗ {}.env.{}: unknown provider scheme `{}`",
                    wrap.name, env_name, reference.provider
                );
                problems += 1;
            }
        }
    }

    if problems == 0 {
        println!(
            "✓ config OK: {} wrap(s), {} provider(s)",
            config.wraps.len(),
            config.providers.len()
        );
        Ok(0)
    } else {
        println!("✗ {problems} problem(s) found");
        Ok(1)
    }
}

/// `secreq doctor` — `check` plus confirm used providers' CLIs are on PATH.
pub fn doctor(config_path: Option<&Path>) -> Result<i32> {
    let exit = check(config_path)?;
    let config_path = resolve_config_path(config_path)?;
    if !config_path.is_file() {
        return Ok(exit);
    }
    let mut config = WrapsConfig::load(&config_path)?;
    config.merge_builtin_providers();

    let mut problems = 0;

    // 1. Wrap shadowing: for every wrap, the first thing `execvp(<bin>, …)`
    // finds on PATH must be *our* shim. Detects the common failure where
    // homebrew (or any other path-prepending tool) shadows our shim dir.
    println!("\nWrap resolution (the first match on PATH):");
    if config.wraps.is_empty() {
        println!("  (no wraps configured)");
    } else if let Some(shim_dir) = config.shim_dir.as_ref() {
        for wrap_name in config.wraps.keys() {
            let expected = shim_dir.join(wrap_name);
            match first_on_path(wrap_name) {
                Some(found) if found == expected => {
                    println!("  ✓ {wrap_name} → {} (shim)", found.display());
                }
                Some(found) => {
                    println!(
                        "  ✗ {wrap_name} → {} (shadowed; expected the shim at {})",
                        found.display(),
                        expected.display()
                    );
                    problems += 1;
                }
                None => {
                    println!("  ✗ {wrap_name} → not on PATH at all");
                    problems += 1;
                }
            }
        }
        if problems > 0 {
            println!(
                "\n  Fix: make sure {} comes before other PATH entries (e.g. /opt/homebrew/bin) \
                in your shell's startup. zsh users: the secreq init block must be in .zshrc, \
                not .zshenv, because .zshrc runs after .zprofile (where `brew shellenv` lives).",
                shim_dir.display()
            );
        }
    } else {
        println!("  (no $shim_dir configured — run `secreq init`)");
        problems += 1;
    }

    // 2. Shim bodies: every managed shim must exec *this* secreq by absolute
    // path. A shim from an older secreq says `exec secreq x <wrap>`, which
    // resolves our name through the caller's PATH — anything that prepends to
    // PATH later can take our place, with no prompt and no audit row. One
    // written before the binary moved names a path that no longer exists.
    // Both are repaired here rather than only reported: the shim is ours, the
    // rewrite is what `secreq wrap` already does, and leaving a hijackable
    // shim in place after naming it would be a strange kind of help.
    if let Some(shim_dir) = config.shim_dir.as_ref() {
        let stale: Vec<&String> = config
            .wraps
            .keys()
            .filter(|w| shim::is_managed(shim_dir, w) && !shim::is_current(shim_dir, w))
            .collect();
        if !stale.is_empty() {
            println!("\nShim bodies:");
            for wrap_name in stale {
                match shim::install(shim_dir, wrap_name) {
                    Ok(path) => println!(
                        "  ✓ {wrap_name} → refreshed {} to exec secreq by absolute path",
                        path.display()
                    ),
                    Err(err) => {
                        println!("  ✗ {wrap_name} → could not refresh the shim: {err:#}");
                        problems += 1;
                    }
                }
            }
        }
    }

    // 3. Provider CLIs.
    let used: std::collections::BTreeSet<String> = config
        .wraps
        .values()
        .flat_map(|w| w.env.values())
        .filter_map(|v| Reference::parse(v).map(|r| r.provider))
        .collect();

    println!("\nProvider CLIs (used by a wrap):");
    if used.is_empty() {
        println!("  (no wraps reference any provider yet)");
    } else {
        for scheme in &used {
            let Some(provider) = config.providers.get(scheme) else {
                continue;
            };
            let Some(program) = provider::retrieve_program(provider) else {
                continue;
            };
            if which_on_path(program) {
                println!("  ✓ {scheme} → {program}");
            } else {
                println!("  ✗ {scheme} → {program} (not found on PATH)");
                problems += 1;
            }
        }
    }

    if problems > 0 {
        println!("\n✗ {problems} problem(s) found");
        return Ok(1);
    }
    Ok(exit)
}

fn parse_env_assignments(envs: &[String]) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for raw in envs {
        let (k, v) = raw
            .split_once('=')
            .with_context(|| format!("--env `{raw}` is not in NAME=secret://… form"))?;
        if k.is_empty() {
            bail!("--env `{raw}` has an empty name");
        }
        if Reference::parse(v).is_none() {
            bail!("--env `{raw}`: value must be a `secret://provider/locator` reference");
        }
        out.insert(k.to_owned(), v.to_owned());
    }
    Ok(out)
}

/// Serialize a `WrapsConfig` to JSON-pretty (the parser accepts JSON5, so
/// this is a valid input). Same caveat as `store`: comments and exact
/// formatting from a hand-edited file aren't preserved through a write.
///
/// **`Mode::Like` the destination, not `Mode::Exactly(0o600)`.** The fallback
/// is the fix: `Like` resolves to 0600 when the mode source does not exist, and
/// on a create it does not — which is the whole bug, since the `fs::write`
/// this replaces preserved an *existing* file's mode and so only ever handed
/// the umask's `0666 & !umask` to a file it created.
///
/// Forcing 0600 was the tempting answer here in a way it was not for
/// `auto-rules.json5`, because this file's `providers` entries are shell
/// commands secreq executes: a world-writable one is arbitrary code execution
/// as the user on the next resolve, not a disclosure of which secrets exist.
/// It is still the wrong answer, for two reasons that do not apply next door:
///
/// - **`path` is not always secreq's.** The global `--config` points this
///   function at any file the user names. Clamping would mean `secreq wrap`
///   chmods a file secreq does not own, every time.
/// - **Migration 0001 already promises to carry this exact filename's mode**
///   across an upgrade (`wraps.json5` is in its `CONFIG_FILES`, copied with
///   `Mode::Like`). Clamping here would make that promise expire on the
///   user's next `wrap add` — worse than either policy alone, because the
///   upgrade would still have said it preserved the mode.
///
/// What actually bounds the code-execution risk is the *directory*, and it is
/// already owner-only: the migration runner creates `~/.secreq` at 0700 from
/// `cli::run` before any command sees control, and `init` narrows an existing
/// one. So no [`crate::paths::ensure_private_dir`] call belongs here — it
/// would be redundant on the default path and actively dangerous on the
/// `--config` one, where `--config /tmp/x.json5` would `chmod 0700 /tmp`.
pub(super) fn write_config(path: &Path, config: &WrapsConfig) -> Result<()> {
    let value = config_to_json_value(config)?;
    let text = serde_json::to_string_pretty(&value)?;
    // Validate by round-tripping before writing.
    WrapsConfig::parse(&text, &path.display().to_string())
        .context("internal: serialized config doesn't re-parse")?;
    crate::atomic::replace(
        path,
        format!("{text}\n").as_bytes(),
        crate::atomic::Mode::Like(path),
    )
    .with_context(|| format!("failed to write {}", path.display()))
}

fn config_to_json_value(config: &WrapsConfig) -> Result<serde_json::Value> {
    let mut root = serde_json::Map::new();
    if let Some(shim) = &config.shim_dir {
        root.insert(
            "$shim_dir".to_owned(),
            serde_json::Value::String(shim.display().to_string()),
        );
    }
    // Preserve the reserved machine-local toggles across a rewrite — a
    // wrap-add / ssh-add must not silently drop a user's `$wait_indicator`
    // or `$editor` (which the rule editor writes on an editor pick).
    if let Some(on) = config.wait_indicator {
        root.insert(
            wraps::WAIT_INDICATOR_KEY.to_owned(),
            serde_json::Value::Bool(on),
        );
    }
    if let Some(editor) = &config.editor {
        root.insert(
            wraps::EDITOR_KEY.to_owned(),
            serde_json::Value::String(editor.clone()),
        );
    }
    for (name, wrap) in &config.wraps {
        let mut obj = serde_json::Map::new();
        if let Some(reason) = &wrap.reason {
            obj.insert(
                "$reason".to_owned(),
                serde_json::Value::String(reason.clone()),
            );
        }
        let mut env_obj = serde_json::Map::new();
        for (k, v) in &wrap.env {
            env_obj.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
        obj.insert("env".to_owned(), serde_json::Value::Object(env_obj));
        root.insert(name.clone(), serde_json::Value::Object(obj));
    }
    // Providers: only include user-declared schemes, not built-ins (avoid
    // baking them into the file; built-ins overlay at load time).
    let builtin_map = crate::manifest::builtin_providers();
    let builtin_names: std::collections::BTreeSet<&str> =
        builtin_map.keys().map(String::as_str).collect();
    let user_providers: std::collections::BTreeMap<&String, &crate::manifest::Provider> = config
        .providers
        .iter()
        .filter(|(name, _)| !builtin_names.contains(name.as_str()))
        .collect();
    if !user_providers.is_empty() {
        let mut providers_obj = serde_json::Map::new();
        for (name, p) in user_providers {
            providers_obj.insert(name.clone(), provider_to_json_value(p));
        }
        root.insert(
            "providers".to_owned(),
            serde_json::Value::Object(providers_obj),
        );
    }
    if !config.ssh.is_empty() {
        let mut ssh_obj = serde_json::Map::new();
        for (name, identity) in &config.ssh {
            let mut obj = serde_json::Map::new();
            if let Some(reason) = &identity.reason {
                obj.insert(
                    "$reason".to_owned(),
                    serde_json::Value::String(reason.clone()),
                );
            }
            obj.insert(
                "public_key".to_owned(),
                serde_json::Value::String(identity.public_key.clone()),
            );
            obj.insert(
                "private_key".to_owned(),
                serde_json::Value::String(identity.private_key.to_string()),
            );
            ssh_obj.insert(name.clone(), serde_json::Value::Object(obj));
        }
        root.insert(
            wraps::SSH_KEY.to_owned(),
            serde_json::Value::Object(ssh_obj),
        );
    }
    Ok(serde_json::Value::Object(root))
}

fn provider_to_json_value(p: &crate::manifest::Provider) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "retrieve".to_owned(),
        serde_json::Value::Array(
            p.retrieve
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        ),
    );
    // We don't currently round-trip store/retrieve_batch from user-defined
    // providers when we re-emit the config; users who declare those should
    // edit the file by hand. `secreq edit` is the supported path.
    serde_json::Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_config_preserves_ssh_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wraps.json5");

        let mut config = WrapsConfig::default();
        config.wraps.insert(
            "gh".to_owned(),
            Wrap {
                name: "gh".to_owned(),
                reason: Some("GitHub API access".to_owned()),
                env: std::iter::once((
                    "GITHUB_TOKEN".to_owned(),
                    "secret://op/Private/gh/token".to_owned(),
                ))
                .collect(),
            },
        );
        config.ssh.insert(
            "github".to_owned(),
            wraps::SshIdentity {
                reason: Some("git pushes".to_owned()),
                public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1 me@mac".to_owned(),
                private_key: Reference::parse("secret://op/Private/GitHub/private key").unwrap(),
            },
        );

        write_config(&path, &config).unwrap();

        let reloaded = WrapsConfig::load(&path).unwrap();
        let id = reloaded
            .ssh
            .get("github")
            .expect("ssh identity must survive a write/reload round-trip");
        assert_eq!(id.reason.as_deref(), Some("git pushes"));
        assert_eq!(id.public_key, "ssh-ed25519 AAAAC3NzaC1lZDI1 me@mac");
        assert_eq!(id.private_key.provider, "op");
        assert_eq!(id.private_key.locator, "Private/GitHub/private key");
    }

    #[test]
    fn write_config_preserves_editor_and_wait_indicator() {
        // A later `wrap add` / `ssh add` rewrites the whole file via
        // `write_config`; the reserved machine-local toggles must survive
        // so a GUI-set `$editor` (and a hand-set `$wait_indicator`) aren't
        // silently dropped.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wraps.json5");

        let config = WrapsConfig {
            editor: Some("zed".to_owned()),
            wait_indicator: Some(false),
            ..Default::default()
        };
        write_config(&path, &config).unwrap();

        let reloaded = WrapsConfig::load(&path).unwrap();
        assert_eq!(reloaded.editor.as_deref(), Some("zed"));
        assert_eq!(reloaded.wait_indicator, Some(false));
    }

    // ── The config's mode ─────────────────────────────────────────────

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    /// `fs::write` preserves an existing file's mode, so the umask only ever
    /// reached this file on **creation** — which is why it went unnoticed.
    /// A created `wraps.json5` came out at `0666 & !umask`: 0644 under the
    /// common 022, 0666 under the `umask 000` container and CI images set.
    /// The `providers` block in there is a set of shell commands secreq
    /// executes, so a writable one is code execution, not disclosure.
    ///
    /// Asserted exactly, and no umask is touched to make it bite: the old
    /// code gave 0644 on an ordinary developer box, which `mode & 0o022 == 0`
    /// would have called clean while the file was still world-readable.
    #[test]
    fn a_config_secreq_creates_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wraps.json5");

        write_config(&path, &WrapsConfig::default()).unwrap();

        assert_eq!(mode_of(&path), 0o600, "{}", path.display());
    }

    /// The reason the mode source is the destination rather than a blanket
    /// `Mode::Exactly(0o600)`. This file is hand-editable with a published
    /// schema, migration 0001 already promises to carry its mode across an
    /// upgrade (`moved_config_keeps_the_mode_the_user_chose` moves a
    /// `wraps.json5`), and `--config` points `write_config` at files secreq
    /// does not own at all. Clamping here would make the migration's promise
    /// last until the user's next `wrap add`.
    #[test]
    fn a_config_write_keeps_a_mode_the_user_chose() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wraps.json5");
        write_config(&path, &WrapsConfig::default()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        write_config(&path, &WrapsConfig::default()).unwrap();

        assert_eq!(mode_of(&path), 0o640);
    }

    /// The side effect worth having: `fs::write` truncates in place, so a
    /// process killed mid-write left the user with a *half* `wraps.json5` —
    /// on a file they hand-edit and whose comments they care about. Staging
    /// and renaming means a reader sees the old contents or the new ones.
    #[test]
    fn a_config_write_replaces_the_inode_rather_than_truncating_it() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wraps.json5");
        write_config(&path, &WrapsConfig::default()).unwrap();
        let before = std::fs::metadata(&path).unwrap().ino();

        write_config(&path, &WrapsConfig::default()).unwrap();

        assert_ne!(std::fs::metadata(&path).unwrap().ino(), before);
        // And no staging litter beside it.
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["wraps.json5".to_string()]);
    }
}
