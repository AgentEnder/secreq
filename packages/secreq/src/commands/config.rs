//! Authoring and inspecting `config.toml`: `secreq wrap` / `unwrap` /
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
use crate::wraps::{Wrap, WrapsConfig, SECRETS_KEY};

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
            // Render the provider (and the declaration it came from) but
            // never the value.
            let summary = match config.resolve_ref(ref_str) {
                Ok(resolved) => match &resolved.declared_as {
                    Some(declared) => format!(
                        "{name} ({declared} → {}, ttl {})",
                        resolved.reference.provider,
                        resolved.ttl.label()
                    ),
                    None => format!(
                        "{name} ({}, ttl {})",
                        resolved.reference.provider,
                        resolved.ttl.label()
                    ),
                },
                Err(_) => format!("{name} (unresolvable reference)"),
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
            let reference = match config.resolve_ref(ref_str) {
                Ok(resolved) => resolved.reference,
                Err(err) => {
                    println!("  ✗ {}.env.{}: {err:#}", wrap.name, env_name);
                    problems += 1;
                    continue;
                }
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
        .filter_map(|v| config.resolve_ref(v).ok().map(|r| r.reference.provider))
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
        // Both written forms are legal here. An undeclared name is caught by
        // `write_config`'s round-trip through the parser, with the message
        // that names both readings — better than second-guessing it without
        // the config in hand.
        if Reference::parse_form(v).is_none() {
            bail!(
                "--env `{raw}`: value must be a `secret://provider/locator` reference \
                 or a declared secret's name (`secret://<name>`)"
            );
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
/// `auto-rules.toml`, because this file's `providers` entries are shell
/// commands secreq executes: a world-writable one is arbitrary code execution
/// as the user on the next resolve, not a disclosure of which secrets exist.
/// It is still the wrong answer, for two reasons that do not apply next door:
///
/// - **`path` is not always secreq's.** The global `--config` points this
///   function at any file the user names. Clamping would mean `secreq wrap`
///   chmods a file secreq does not own, every time.
/// - **Migration 0001 already promises to carry this exact filename's mode**
///   across an upgrade (`config.toml` is in its `CONFIG_FILES`, copied with
///   `Mode::Like`). Clamping here would make that promise expire on the
///   user's next `wrap add` — worse than either policy alone, because the
///   upgrade would still have said it preserved the mode.
///
/// What actually bounds the code-execution risk is the *directory*, and it is
/// already owner-only: the migration runner creates `~/.secreq` at 0700 from
/// `cli::run` before any command sees control, and `init` narrows an existing
/// one. So no [`crate::paths::ensure_private_dir`] call belongs here — it
/// would be redundant on the default path and actively dangerous on the
/// `--config` one, where `--config /tmp/x.toml` would `chmod 0700 /tmp`.
///
/// ## The write is a merge, not a rebuild
///
/// This used to reconstruct the whole file from [`WrapsConfig`] and hand it to
/// a serializer, which meant every `wrap add`, `ssh add` or editor pick
/// silently deleted the user's comments and layout. Now the existing document
/// is parsed with `toml_edit`, the changed values are set *into* it, and
/// everything the parser doesn't model — comments, blank lines, key order —
/// survives untouched.
pub(super) fn write_config(path: &Path, config: &WrapsConfig) -> Result<()> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut doc: toml_edit::DocumentMut = existing
        .parse()
        .with_context(|| format!("{} is not valid TOML", path.display()))?;

    sync_document(&mut doc, config);

    let text = doc.to_string();
    // Validate by round-tripping before writing.
    WrapsConfig::parse(&text, &path.display().to_string())
        .context("internal: serialized config doesn't re-parse")?;
    crate::atomic::replace(path, text.as_bytes(), crate::atomic::Mode::Like(path))
        .with_context(|| format!("failed to write {}", path.display()))
}

/// Set every value `config` carries into `doc`, and drop the entries it no
/// longer has. Anything else in the document is left exactly as written.
fn sync_document(doc: &mut toml_edit::DocumentMut, config: &WrapsConfig) {
    use toml_edit::Item;

    fn set_or_remove(doc: &mut toml_edit::DocumentMut, key: &str, v: Option<toml_edit::Value>) {
        match v {
            Some(v) => {
                crate::rule_scaffold::set_preserving_decor(doc.as_table_mut(), key, Item::Value(v));
            }
            None => {
                doc.remove(key);
            }
        }
    }

    set_or_remove(
        doc,
        "shim_dir",
        config
            .shim_dir
            .as_ref()
            .map(|p| crate::daemon::ui::abbreviate_home(&p.display().to_string()).into()),
    );
    set_or_remove(doc, "wait_indicator", config.wait_indicator.map(Into::into));
    set_or_remove(
        doc,
        "editor",
        config.editor.as_ref().map(|e| e.as_str().into()),
    );

    // Built-ins overlay at load time, so they are never written back — baking
    // them into the file would freeze today's defaults into the user's config.
    let builtin = crate::manifest::builtin_providers();
    let user_providers: BTreeMap<&String, &crate::manifest::Provider> = config
        .providers
        .iter()
        .filter(|(name, _)| !builtin.contains_key(name.as_str()))
        .collect();

    sync_table(doc, "wraps", &config.wraps);
    sync_table(doc, "providers", &user_providers);
    sync_table(doc, "ssh", &config.ssh);
    // Declarations are synced for the same reason the `ssh` block is: a block
    // this writer forgets is a block the next `wrap add` silently deletes —
    // taking every wrap's `secret://<name>` with it.
    sync_table(doc, SECRETS_KEY, &config.secrets);

    // An emptied-out section is removed rather than left as a bare header.
    for key in ["wraps", "providers", "ssh", SECRETS_KEY] {
        if doc
            .get(key)
            .and_then(Item::as_table)
            .is_some_and(toml_edit::Table::is_empty)
        {
            doc.remove(key);
        }
    }
}

/// Merge one `[section.<name>]` map into the document, serializing each entry
/// through its `Serialize` impl and removing names that are gone.
fn sync_table<K, V>(doc: &mut toml_edit::DocumentMut, section: &str, entries: &BTreeMap<K, V>)
where
    K: std::borrow::Borrow<String> + Ord,
    V: serde::Serialize,
{
    use toml_edit::{Item, Table};

    if entries.is_empty() && doc.get(section).is_none() {
        return;
    }
    let table = doc
        .entry(section)
        .or_insert_with(|| {
            let mut t = Table::new();
            t.set_implicit(true);
            Item::Table(t)
        })
        .as_table_mut()
        .expect("config section must be a table");

    let names: Vec<String> = entries.keys().map(|k| k.borrow().clone()).collect();
    table.retain(|existing, _| names.iter().any(|n| n == existing));

    for (name, entry) in entries {
        let serialized = toml_edit::ser::to_document(entry)
            .expect("config entries serialize infallibly")
            .as_table()
            .clone();
        crate::rule_scaffold::set_preserving_decor(table, name.borrow(), Item::Table(serialized));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wraps::{CacheTtl, SecretDecl};

    #[test]
    fn env_assignment_errors_are_a_single_clean_sentence() {
        // These strings reach a user's terminal verbatim, and nothing else
        // asserts on them — which is how an edit that joined two source lines
        // shipped ~18 literal spaces into the middle of this one. A run of
        // whitespace is never intentional in a message, so check for it
        // directly rather than pinning the exact wording.
        let cases = [
            "NOT_AN_ASSIGNMENT",
            "=secret://op/x/y",
            "GITHUB_TOKEN=not-a-reference",
        ];
        for raw in cases {
            let err = parse_env_assignments(&[raw.to_owned()])
                .unwrap_err()
                .to_string();
            assert!(
                !err.contains("  "),
                "`--env {raw}` error has a run of whitespace in it: {err:?}"
            );
            assert!(!err.contains('\n'), "`--env {raw}` error wraps: {err:?}");
            assert!(err.contains(raw), "error must quote the offender: {err:?}");
        }

        // Both written forms of a reference are accepted here; an undeclared
        // name is `write_config`'s round-trip to reject, with the config in
        // hand and the message that names both readings.
        let ok = parse_env_assignments(&[
            "A=secret://op/Work/PG/url".to_owned(),
            "B=secret://github_token".to_owned(),
        ])
        .expect("both reference forms are legal in --env");
        assert_eq!(ok["A"], "secret://op/Work/PG/url");
        assert_eq!(ok["B"], "secret://github_token");
    }

    #[test]
    fn write_config_preserves_declared_secrets_and_the_names_that_reference_them() {
        // `secreq wrap` re-serializes the whole model, so a block this writer
        // forgets is a block the next `wrap add` silently deletes — taking
        // every `secret://<name>` in the file with it. The round-trip through
        // the parser inside `write_config` would then fail on the dangling
        // names, so this also proves the two halves agree.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let mut config = WrapsConfig::default();
        config.secrets.insert(
            "github_token".to_owned(),
            SecretDecl {
                reference: Reference::parse("secret://op/Personal/GitHub/token").unwrap(),
                ttl: CacheTtl::Secs(900),
            },
        );
        config.secrets.insert(
            "no_ttl".to_owned(),
            SecretDecl {
                reference: Reference::parse("secret://op/Personal/Other/token").unwrap(),
                ttl: CacheTtl::DaemonLifetime,
            },
        );
        config.wraps.insert(
            "gh".to_owned(),
            Wrap {
                name: "gh".to_owned(),
                reason: None,
                env: std::iter::once((
                    "GITHUB_TOKEN".to_owned(),
                    "secret://github_token".to_owned(),
                ))
                .collect(),
            },
        );

        write_config(&path, &config).unwrap();
        let reloaded = WrapsConfig::load(&path).unwrap();

        assert_eq!(reloaded.secrets, config.secrets);
        assert_eq!(
            reloaded
                .wrap("gh")
                .unwrap()
                .env
                .get("GITHUB_TOKEN")
                .unwrap(),
            "secret://github_token",
            "the wrap must still reference the declaration by name"
        );
        // A default TTL writes no `ttl` key, so a file the user never gave one
        // does not grow one. And the one that is written keeps the unit it was
        // declared in rather than being normalised to seconds.
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("ttl = \"15m\""), "{text}");
        // `ttl = `, not `ttl` — the `no_ttl` declaration's *name* contains the
        // substring, and counting that would pass no matter what was written.
        assert_eq!(text.matches("ttl = ").count(), 1, "{text}");
    }

    #[test]
    fn write_config_preserves_ssh_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

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
            crate::wraps::SshIdentity {
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
        // so a GUI-set `editor` (and a hand-set `wait_indicator`) aren't
        // silently dropped.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

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
    /// A created `config.toml` came out at `0666 & !umask`: 0644 under the
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
        let path = dir.path().join("config.toml");

        write_config(&path, &WrapsConfig::default()).unwrap();

        assert_eq!(mode_of(&path), 0o600, "{}", path.display());
    }

    /// The reason the mode source is the destination rather than a blanket
    /// `Mode::Exactly(0o600)`. This file is hand-editable with a published
    /// schema, migration 0001 already promises to carry its mode across an
    /// upgrade (`moved_config_keeps_the_mode_the_user_chose` moves a
    /// `config.toml`), and `--config` points `write_config` at files secreq
    /// does not own at all. Clamping here would make the migration's promise
    /// last until the user's next `wrap add`.
    #[test]
    fn a_config_write_keeps_a_mode_the_user_chose() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_config(&path, &WrapsConfig::default()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        write_config(&path, &WrapsConfig::default()).unwrap();

        assert_eq!(mode_of(&path), 0o640);
    }

    /// The side effect worth having: `fs::write` truncates in place, so a
    /// process killed mid-write left the user with a *half* `config.toml` —
    /// on a file they hand-edit and whose comments they care about. Staging
    /// and renaming means a reader sees the old contents or the new ones.
    #[test]
    fn a_config_write_replaces_the_inode_rather_than_truncating_it() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_config(&path, &WrapsConfig::default()).unwrap();
        let before = std::fs::metadata(&path).unwrap().ino();

        write_config(&path, &WrapsConfig::default()).unwrap();

        assert_ne!(std::fs::metadata(&path).unwrap().ino(), before);
        // And no staging litter beside it.
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["config.toml".to_string()]);
    }
}
