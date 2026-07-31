//! Authoring and inspecting `config.toml`: `secreq wrap` / `unwrap` /
//! `wraps` / `edit` / `check` / `doctor`, plus the writer every one of
//! those (and `ssh add`, and `init`) goes through.
//!
//! [`edit_config`] is the single writer, and it takes [`ConfigEdit`]s rather
//! than a whole [`WrapsConfig`]: a write touches the entries it names and
//! leaves the rest of the file — including everything the model cannot see —
//! byte for byte as the user wrote it. It round-trips the edited text back
//! through the parser before touching the file, so a config we cannot re-read
//! is never the one on disk.

use std::collections::BTreeMap;
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::path_setup;
use crate::provider;
use crate::reference::Reference;
use crate::shim;
use crate::wraps::{Wrap, WrapsConfig};

use super::binaries::first_on_path;
use super::{prompt, resolve_config_path, which_on_path};

/// Args for `secreq wrap`.
#[derive(Debug, Clone, Default)]
pub struct WrapArgs {
    pub binary: String,
    pub reason: Option<String>,
    pub secrets: Vec<String>, // each: a top-level [secrets.<NAME>] key
    pub envs: Vec<String>,    // each: "ENV_NAME=secret://provider/locator"
}

/// `secreq wrap <BINARY>` — add (or update) a wrap entry and install the
/// shim. Interactive when both injection flag lists are empty; non-interactive
/// otherwise.
pub fn wrap(args: WrapArgs, config_path: Option<&Path>) -> Result<i32> {
    let config_path = resolve_config_path(config_path)?;
    let mut config = if config_path.is_file() {
        WrapsConfig::load(&config_path)?
    } else {
        WrapsConfig::default()
    };
    // Overlay the built-ins so the interactive picker can offer them even
    // when the user has no `providers` block. Nothing writes `providers`, so
    // they cannot reach the file.
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
    let interactive =
        args.secrets.is_empty() && args.envs.is_empty() && std::io::stdin().is_terminal();
    if interactive {
        crate::term::soft_reset();
        cliclack::intro(format!("Wrap `{}`", args.binary))?;
    }

    // Build both injection forms. Three paths:
    //  - `--secret` / `--env` flags supplied → parse them (non-interactive).
    //  - interactive terminal   → ask gate-only vs inject-secrets.
    //  - no flags, no terminal  → gate-only. There's nothing to inject and
    //    nothing to prompt on, so absence of either flag means "just gate it".
    // Empty injection forms make a *gate-only* wrap: consent is still
    // required, but nothing is resolved or injected. Used for tools like `op`.
    let (env_secrets, env): (Vec<String>, BTreeMap<String, String>) =
        if !args.secrets.is_empty() || !args.envs.is_empty() {
            (args.secrets.clone(), parse_env_assignments(&args.envs)?)
        } else if interactive {
            if prompt::wrap_is_gate_only()? {
                (Vec::new(), BTreeMap::new())
            } else {
                // Suggest declarations and references already present in the
                // config, computed before the new wrap is inserted.
                let known = config.known_secret_refs();
                prompt::interactive_wrap_envs(&config.providers, &known)?
            }
        } else {
            (Vec::new(), BTreeMap::new())
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
        env_secrets,
        env,
    };
    // No injection through either form means we created a gate-only wrap.
    let gate_only = wrap.is_gate_only();

    // Only this wrap is written. The built-ins merged in above were for the
    // picker's benefit and never reach the file, because nothing asks to write
    // `providers` — where a whole-model write had to filter them back out to
    // avoid freezing today's defaults into the user's config.
    edit_config(&config_path, &[ConfigEdit::UpsertWrap(wrap)])?;

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
    let config = WrapsConfig::load(&config_path)?;
    let removed = config.wrap(binary).is_some();
    let shim_removed = if let Some(shim_dir) = &config.shim_dir {
        shim::remove(shim_dir, binary)?
    } else {
        false
    };
    if removed {
        edit_config(&config_path, &[ConfigEdit::RemoveWrap(binary.to_owned())])?;
    }
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
        for (name, resolved) in config.wrap_refs(wrap)? {
            // Render the provider (and the declaration it came from) but
            // never the value.
            let summary = match &resolved.declared_as {
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

    // Every injected entry, through either form, must reference a known
    // provider.
    for wrap in config.wraps.values() {
        for (env_name, resolved) in config.wrap_refs(wrap)? {
            let reference = resolved.reference;
            if !config.providers.contains_key(&reference.provider) {
                let source = if wrap.env_secrets.contains(&env_name) {
                    "env_secrets"
                } else {
                    "env"
                };
                println!(
                    "  ✗ {}.{}.{}: unknown provider scheme `{}`",
                    wrap.name, source, env_name, reference.provider
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
    let mut used = std::collections::BTreeSet::new();
    for wrap in config.wraps.values() {
        used.extend(
            config
                .wrap_refs(wrap)?
                .into_iter()
                .map(|(_, resolved)| resolved.reference.provider),
        );
    }

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
/// ## The write is a targeted edit, not a rebuild
///
/// This used to reconstruct the whole file from [`WrapsConfig`] and hand it to
/// a serializer, which meant every `wrap add`, `ssh add` or editor pick
/// silently deleted the user's comments and layout. Parsing with `toml_edit`
/// fixed the *file* level, but the shape stayed a rebuild: reconciling a whole
/// [`WrapsConfig`] re-serialized **every** entry on every write, so a comment
/// inside `[wraps.gh]` still died to a `secreq wrap aws` that never mentioned
/// `gh`.
///
/// So callers say what changed. Each [`ConfigEdit`] names one entry, and
/// nothing else in the document is read, rewritten, or reordered.
pub(super) fn edit_config(path: &Path, edits: &[ConfigEdit]) -> Result<()> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut doc: toml_edit::DocumentMut = existing
        .parse()
        .with_context(|| format!("{} is not valid TOML", path.display()))?;

    for edit in edits {
        apply_edit(&mut doc, edit);
    }

    let text = doc.to_string();
    // Validate by round-tripping before writing. An edit that produced a
    // config secreq cannot read — an `env` naming an undeclared secret, say —
    // fails here rather than on the user's next command.
    WrapsConfig::parse(&text, &path.display().to_string())
        .context("internal: edited config doesn't re-parse")?;
    crate::atomic::replace(path, text.as_bytes(), crate::atomic::Mode::Like(path))
        .with_context(|| format!("failed to write {}", path.display()))
}

/// One targeted change to `config.toml`.
///
/// Deliberately not "here is the new [`WrapsConfig`], work out the diff". A
/// diff against the model can only see what the model holds, so it reports a
/// comment, a blank line or a key order as no change at all and then destroys
/// them anyway. Naming the entry is what keeps the rest of the file out of the
/// write entirely.
pub(super) enum ConfigEdit {
    /// Where `secreq wrap` drops PATH shims. Written back with a leading `~/`.
    SetShimDir(PathBuf),
    /// Add a wrap, or replace the one of the same name.
    UpsertWrap(Wrap),
    /// Drop a wrap. A no-op when it was not there.
    RemoveWrap(String),
    /// Add an SSH identity, or replace the one of the same name.
    UpsertSshIdentity(String, crate::wraps::SshIdentity),
}

fn apply_edit(doc: &mut toml_edit::DocumentMut, edit: &ConfigEdit) {
    use toml_edit::Item;
    match edit {
        ConfigEdit::SetShimDir(dir) => {
            let shown = crate::daemon::ui::abbreviate_home(&dir.display().to_string());
            crate::rule_scaffold::set_preserving_decor(
                doc.as_table_mut(),
                "shim_dir",
                Item::Value(shown.into()),
            );
        }
        ConfigEdit::UpsertWrap(wrap) => upsert_entry(doc, "wraps", &wrap.name, wrap),
        ConfigEdit::RemoveWrap(name) => remove_entry(doc, "wraps", name),
        ConfigEdit::UpsertSshIdentity(name, identity) => upsert_entry(doc, "ssh", name, identity),
    }
}

/// Write one `[section.<name>]` entry. Every other entry in the section is
/// left exactly as the user wrote it — not re-serialized, not reordered.
fn upsert_entry<V: serde::Serialize>(
    doc: &mut toml_edit::DocumentMut,
    section: &str,
    name: &str,
    entry: &V,
) {
    use toml_edit::{Item, Table};

    let mut serialized = toml_edit::ser::to_document(entry)
        .expect("config entries serialize infallibly")
        .as_table()
        .clone();
    crate::rule_scaffold::shape_config_entry(&mut serialized);

    let table = doc
        .entry(section)
        .or_insert_with(|| {
            let mut t = Table::new();
            t.set_implicit(true);
            Item::Table(t)
        })
        .as_table_mut()
        .expect("config section must be a table");

    // A comment above `[wraps.gh]` labels the entry, not its current body, so
    // it survives the body being rewritten. `set_preserving_decor` cannot do
    // this one: a table's header decoration lives on the table, not the key.
    if let Some(existing) = table.get(name).and_then(Item::as_table) {
        *serialized.decor_mut() = existing.decor().clone();
    }
    crate::rule_scaffold::set_preserving_decor(table, name, Item::Table(serialized));
}

/// Drop one `[section.<name>]` entry, and the section header with it once it
/// holds nothing — an emptied-out section would otherwise sit in the file as a
/// bare header.
fn remove_entry(doc: &mut toml_edit::DocumentMut, section: &str, name: &str) {
    let Some(table) = doc.get_mut(section).and_then(toml_edit::Item::as_table_mut) else {
        return;
    };
    table.remove(name);
    if table.is_empty() {
        doc.remove(section);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wraps::CacheTtl;

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

    /// Nothing writes `secrets`, so a `wrap add` beside a declaration block
    /// leaves it exactly as the user typed it — the `ttl` unit, the comment,
    /// the blank line and all.
    ///
    /// Under a whole-model write this was a live hazard rather than a
    /// tautology: the writer had to remember to re-emit the block, and a
    /// writer that forgot deleted every declaration in the file along with the
    /// `secret://<name>` references pointing at them.
    #[test]
    fn an_unrelated_secrets_block_is_untouched_by_a_wrap_add() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = "\
# tokens I reuse
[secrets.github_token]
ref = \"secret://op/Personal/GitHub/token\"
ttl = \"15m\"

[wraps.gh.env]
GITHUB_TOKEN = \"secret://github_token\"
";
        std::fs::write(&path, original).unwrap();

        edit_config(
            &path,
            &[ConfigEdit::UpsertWrap(Wrap {
                name: "aws".to_owned(),
                reason: None,
                env_secrets: Vec::new(),
                env: std::iter::once(("AWS_KEY".to_owned(), "secret://op/Work/AWS/k".to_owned()))
                    .collect(),
            })],
        )
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.starts_with(original),
            "the existing file must be a prefix of the new one:\n{text}"
        );
        assert!(text.contains("[wraps.aws.env]"), "{text}");

        // And the declaration still resolves for the wrap that names it.
        let reloaded = WrapsConfig::load(&path).unwrap();
        assert_eq!(reloaded.secrets["github_token"].ttl, CacheTtl::Secs(900));
        assert_eq!(
            reloaded
                .resolve_ref("secret://github_token")
                .unwrap()
                .reference
                .locator,
            "Personal/GitHub/token"
        );
    }

    /// A wrap that only injects env vars needs no header of its own:
    /// `[wraps.gh.env]` already implies `[wraps.gh]`, and writing both leaves
    /// an empty stanza above every wrap in the file.
    ///
    /// The gate-only wrap in here is the reason this is a condition and not a
    /// blanket rule. It has no values *and* no sub-tables, so nothing would
    /// imply it — made implicit it renders as nothing at all and the wrap is
    /// gone on the next load.
    #[test]
    fn a_wrap_whose_only_entry_is_a_table_gets_no_header_of_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        edit_config(
            &path,
            &[
                ConfigEdit::UpsertWrap(Wrap {
                    name: "gh".to_owned(),
                    reason: None,
                    env_secrets: Vec::new(),
                    env: std::iter::once(("GH_TOKEN".to_owned(), "secret://op/x/y".to_owned()))
                        .collect(),
                }),
                ConfigEdit::UpsertWrap(Wrap {
                    name: "op".to_owned(),
                    reason: None,
                    env_secrets: Vec::new(),
                    env: BTreeMap::new(),
                }),
            ],
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();

        assert!(!text.contains("[wraps.gh]"), "{text}");
        assert!(text.contains("[wraps.gh.env]"), "{text}");
        assert!(
            text.contains("[wraps.op]"),
            "gate-only wrap needs a header: {text}"
        );

        let reloaded = WrapsConfig::load(&path).unwrap();
        assert!(
            reloaded.wrap("op").is_some(),
            "the gate-only wrap must survive the round-trip: {text}"
        );
        assert_eq!(
            reloaded.wrap("gh").unwrap().env["GH_TOKEN"],
            "secret://op/x/y"
        );
    }

    /// Adding one wrap must not reformat a different one.
    ///
    /// The whole point of `toml_edit` is that a write touches what changed and
    /// nothing else. Reconciling the entire model re-serializes every entry on
    /// every write, so a comment a user wrote inside `[wraps.gh]` is deleted by
    /// a `secreq wrap aws` that never mentioned `gh`.
    #[test]
    fn adding_a_wrap_leaves_every_other_entry_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = "\
# the GitHub CLI
[wraps.gh]
reason = \"GitHub API access\"

# the token lives in the Personal vault
[wraps.gh.env]
GITHUB_TOKEN = \"secret://op/Personal/GitHub/token\"
";
        std::fs::write(&path, original).unwrap();

        edit_config(
            &path,
            &[ConfigEdit::UpsertWrap(Wrap {
                name: "aws".to_owned(),
                reason: None,
                env_secrets: Vec::new(),
                env: std::iter::once(("AWS_KEY".to_owned(), "secret://op/Work/AWS/k".to_owned()))
                    .collect(),
            })],
        )
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.starts_with(original),
            "an untouched entry must stay byte-identical:\n{text}"
        );
        assert!(text.contains("# the GitHub CLI"), "{text}");
        assert!(
            text.contains("# the token lives in the Personal vault"),
            "{text}"
        );
        assert!(text.contains("[wraps.aws.env]"), "{text}");
    }

    /// The two writers have to author an entry the same way.
    ///
    /// Re-writing a wrap the migration produced, with the same contents, must
    /// be a no-op on the bytes. While they disagreed, a freshly migrated config
    /// reflowed the first time secreq touched it — the `[wraps.gh.env]` stanza
    /// collapsing onto one inline `env = { … }` line, which is the clobbering
    /// this whole format change exists to stop.
    #[test]
    fn re_writing_a_migrated_entry_unchanged_is_a_no_op_on_the_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let migrated = "[wraps.gh.env]\nGH_TOKEN = \"secret://op/x/y\"\n\n[wraps.op]\n";
        std::fs::write(&path, migrated).unwrap();

        let config = WrapsConfig::load(&path).unwrap();
        let edits: Vec<ConfigEdit> = config
            .wraps
            .values()
            .cloned()
            .map(ConfigEdit::UpsertWrap)
            .collect();
        edit_config(&path, &edits).unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), migrated);
    }

    /// A wrap carrying anything of its own still gets a header to carry it.
    #[test]
    fn a_wrap_with_its_own_values_keeps_its_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        edit_config(
            &path,
            &[ConfigEdit::UpsertWrap(Wrap {
                name: "gh".to_owned(),
                reason: Some("GitHub API access".to_owned()),
                env_secrets: Vec::new(),
                env: std::iter::once(("GH_TOKEN".to_owned(), "secret://op/x/y".to_owned()))
                    .collect(),
            })],
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("[wraps.gh]"), "{text}");
        assert!(text.contains("reason = \"GitHub API access\""), "{text}");
    }

    #[test]
    fn an_ssh_identity_round_trips_through_an_edit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        edit_config(
            &path,
            &[ConfigEdit::UpsertSshIdentity(
                "github".to_owned(),
                crate::wraps::SshIdentity {
                    reason: Some("git pushes".to_owned()),
                    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1 me@mac".to_owned(),
                    private_key: Reference::parse("secret://op/Private/GitHub/private key")
                        .unwrap(),
                },
            )],
        )
        .unwrap();

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

    /// The machine-local toggles and an unrelated `ssh` block survive a
    /// `wrap add` because nothing names them, so nothing rewrites them.
    ///
    /// This is the failure `config_to_json_value` carried a comment about: it
    /// had to re-emit `wait_indicator` and `editor` by hand or a `wrap add`
    /// dropped them. Naming the edit retires that whole class of bug rather
    /// than patching the two fields that were noticed.
    #[test]
    fn the_reserved_blocks_and_toggles_are_untouched_by_a_wrap_add() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = "\
editor = \"zed\"
wait_indicator = false

[ssh.github]
public_key = \"ssh-ed25519 AAAAC3NzaC1lZDI1 me@mac\"
private_key = \"secret://op/Private/GitHub/private key\"
";
        std::fs::write(&path, original).unwrap();

        edit_config(
            &path,
            &[ConfigEdit::UpsertWrap(Wrap {
                name: "gh".to_owned(),
                reason: None,
                env_secrets: Vec::new(),
                env: BTreeMap::new(),
            })],
        )
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(original), "{text}");

        let reloaded = WrapsConfig::load(&path).unwrap();
        assert_eq!(reloaded.editor.as_deref(), Some("zed"));
        assert_eq!(reloaded.wait_indicator, Some(false));
        assert!(reloaded.ssh.contains_key("github"));
        assert!(reloaded.wrap("gh").is_some());
    }

    /// Removing the last wrap takes the `[wraps]` section with it, rather than
    /// leaving a bare header behind.
    #[test]
    fn removing_the_last_wrap_removes_the_section_too() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "editor = \"zed\"\n\n[wraps.gh.env]\nT = \"secret://op/x/y\"\n",
        )
        .unwrap();

        edit_config(&path, &[ConfigEdit::RemoveWrap("gh".to_owned())]).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("wraps"), "{text}");
        assert!(text.contains("editor = \"zed\""), "{text}");
    }

    /// A comment above `[wraps.gh]` labels the entry, so re-wrapping `gh`
    /// keeps it even though the body is rewritten.
    #[test]
    fn re_wrapping_keeps_the_comment_that_labels_the_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "# the GitHub CLI\n[wraps.gh]\nreason = \"old\"\n").unwrap();

        edit_config(
            &path,
            &[ConfigEdit::UpsertWrap(Wrap {
                name: "gh".to_owned(),
                reason: Some("new".to_owned()),
                env_secrets: Vec::new(),
                env: BTreeMap::new(),
            })],
        )
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# the GitHub CLI"), "{text}");
        assert!(text.contains("reason = \"new\""), "{text}");
        assert!(!text.contains("old"), "{text}");
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

        edit_config(
            &path,
            &[ConfigEdit::SetShimDir(PathBuf::from("/tmp/shims"))],
        )
        .unwrap();

        assert_eq!(mode_of(&path), 0o600, "{}", path.display());
    }

    /// The reason the mode source is the destination rather than a blanket
    /// `Mode::Exactly(0o600)`. This file is hand-editable with a published
    /// schema, migration 0001 already promises to carry its mode across an
    /// upgrade (`moved_config_keeps_the_mode_the_user_chose` moves a
    /// `config.toml`), and `--config` points `edit_config` at files secreq
    /// does not own at all. Clamping here would make the migration's promise
    /// last until the user's next `wrap add`.
    #[test]
    fn a_config_write_keeps_a_mode_the_user_chose() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        edit_config(
            &path,
            &[ConfigEdit::SetShimDir(PathBuf::from("/tmp/shims"))],
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        edit_config(
            &path,
            &[ConfigEdit::SetShimDir(PathBuf::from("/tmp/shims"))],
        )
        .unwrap();

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
        edit_config(
            &path,
            &[ConfigEdit::SetShimDir(PathBuf::from("/tmp/shims"))],
        )
        .unwrap();
        let before = std::fs::metadata(&path).unwrap().ino();

        edit_config(
            &path,
            &[ConfigEdit::SetShimDir(PathBuf::from("/tmp/shims"))],
        )
        .unwrap();

        assert_ne!(std::fs::metadata(&path).unwrap().ino(), before);
        // And no staging litter beside it.
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["config.toml".to_string()]);
    }
}
