//! Migration 0003 — `wraps.json5` → `config.toml`, and `auto-rules.json5` →
//! `auto-rules.toml`.
//!
//! Two things change at once, because the migration is the only moment either
//! file is rewritten wholesale and doing them in separate levels would leave a
//! window where the two config files disagree about what format secreq speaks.
//!
//! - **Format.** JSON5 → TOML. Reading is now serde over `toml`, and writing
//!   is `toml_edit` editing a parsed document, so a `wrap add` no longer
//!   deletes the comments a user wrote.
//! - **Shape.** Wraps move from the root to `[wraps.<binary>]` and the `$`
//!   sigils go. The root used to be an open namespace — anything that wasn't
//!   `providers`, `ssh` or `$`-prefixed *was* a binary name — which is why a
//!   mistyped `provdiers` silently became a wrap. With every root key known,
//!   an unrecognised one is an error. `$` also isn't a legal TOML bare-key
//!   character, so keeping the sigils would have meant quoting them forever.
//!
//! **This module is the only place JSON5 is still read.** The loader has no
//! branch for it; a permanent dual-format reader would be the compatibility
//! layer the project's standards forbid, and it would double the surface every
//! future config field has to be tested against. When this level is old enough
//! to retire, the `json5` dependency goes with it.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;

use super::{Ctx, Outcome};

/// The pre-migration filenames, captured before anything is rewritten.
pub fn snapshot_files(ctx: &Ctx) -> Vec<PathBuf> {
    vec![
        ctx.root.join(LEGACY_CONFIG),
        ctx.root.join(LEGACY_RULES),
        ctx.root.join(CONFIG),
        ctx.root.join(RULES),
    ]
}

const LEGACY_CONFIG: &str = "wraps.json5";
const LEGACY_RULES: &str = "auto-rules.json5";
const CONFIG: &str = "config.toml";
const RULES: &str = "auto-rules.toml";

pub fn run(ctx: &Ctx) -> Result<Outcome> {
    for (from, to, f) in [
        (
            ctx.root.join(LEGACY_CONFIG),
            ctx.root.join(CONFIG),
            config_json5_to_toml as fn(&Value) -> Result<String>,
        ),
        (
            ctx.root.join(LEGACY_RULES),
            ctx.root.join(RULES),
            rules_json5_to_toml,
        ),
    ] {
        if let Some(reason) = convert(&from, &to, f)? {
            return Ok(Outcome::Incomplete(reason));
        }
    }
    clear_legacy_symlinks(ctx)?;
    Ok(Outcome::Done)
}

/// Migration 0001 left a symlink at each old location so an **older secreq**
/// kept working after the files moved. Renaming the targets here would leave
/// those dangling, and repointing them would be a lie: an older secreq cannot
/// parse TOML wherever it finds it. So they are removed.
///
/// Only a symlink is touched, and only one pointing into our own root — a real
/// file at the legacy path belongs to someone else and is left alone.
fn clear_legacy_symlinks(ctx: &Ctx) -> Result<()> {
    let Some(dir) = &ctx.legacy_config_dir else {
        return Ok(());
    };
    for name in [LEGACY_CONFIG, LEGACY_RULES] {
        let link = dir.join(name);
        let Ok(meta) = link.symlink_metadata() else {
            continue;
        };
        if !meta.file_type().is_symlink() {
            continue;
        }
        if std::fs::read_link(&link).is_ok_and(|target| target.starts_with(&ctx.root)) {
            std::fs::remove_file(&link)
                .with_context(|| format!("remove stale symlink {}", link.display()))?;
        }
    }
    Ok(())
}

/// Read `from`, convert, write `to`, remove `from`. A missing source is the
/// fresh-install case and a nothing-to-do; an already-present target means a
/// previous run got there, so the source is simply cleared.
///
/// Returns `Some(reason)` when the source will not parse. That is a stop, not
/// a failure: the level goes unstamped, so the migration retries on the next
/// run once the user has fixed the file. Hard-erroring would wedge *every*
/// secreq command behind a config the user can still repair by hand.
fn convert(from: &Path, to: &Path, f: fn(&Value) -> Result<String>) -> Result<Option<String>> {
    let text = match std::fs::read_to_string(from) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read {}", from.display())),
    };
    if !to.exists() {
        let root: Value = match json5::from_str(&text) {
            Ok(root) => root,
            Err(err) => {
                return Ok(Some(format!(
                    "{} could not be read as JSON5 ({err}); fix it and re-run, \
                     or delete it to start fresh",
                    from.display()
                )))
            }
        };
        let converted = f(&root).with_context(|| format!("convert {}", from.display()))?;
        // `Mode::Like(from)` carries the old file's permissions onto the new
        // one. Migration 0001 already promised to preserve this file's mode
        // across an upgrade; renaming it must not quietly expire that.
        crate::atomic::replace(to, converted.as_bytes(), crate::atomic::Mode::Like(from))
            .with_context(|| format!("write {}", to.display()))?;
    }
    std::fs::remove_file(from).with_context(|| format!("remove {}", from.display()))?;
    Ok(None)
}

/// `wraps.json5` → `config.toml`, moving wraps under `[wraps.*]` and dropping
/// the `$` sigils.
fn config_json5_to_toml(root: &Value) -> Result<String> {
    let obj = root
        .as_object()
        .context("top level must be an object")?
        .clone();

    let mut doc = toml_edit::DocumentMut::new();
    let mut wraps = toml_edit::Table::new();
    wraps.set_implicit(true);

    let root = doc.as_table_mut();
    for (key, value) in obj {
        match key.as_str() {
            // Reserved blocks keep their names and their shape.
            "providers" | "ssh" => {
                root.insert(&key, json_to_item(&strip_sigils(&value)));
            }
            // Machine-local settings shed the sigil.
            "$shim_dir" => {
                root.insert("shim_dir", json_to_item(&value));
            }
            "$wait_indicator" => {
                root.insert("wait_indicator", json_to_item(&value));
            }
            "$editor" => {
                root.insert("editor", json_to_item(&value));
            }
            // `$schema` pointed an editor at the JSON Schema. TOML carries
            // that as a `#:schema` comment instead, so the key is dropped
            // rather than translated.
            other if other.starts_with('$') => continue,
            // Everything else was a binary name.
            binary => {
                let mut body = strip_sigils(&value);
                // `env: {}` and an absent `env` both mean gate-only, so the
                // empty one is dropped rather than migrated into a bare
                // `[wraps.<binary>.env]` header. The *wrap* body may still be
                // empty — that is exactly what a gate-only wrap looks like.
                if let Some(map) = body.as_object_mut() {
                    if map
                        .get("env")
                        .is_some_and(|e| e.as_object().is_some_and(serde_json::Map::is_empty))
                    {
                        map.remove("env");
                    }
                }
                wraps.insert(binary, json_to_item(&body));
            }
        }
    }

    if !wraps.is_empty() {
        root.insert("wraps", toml_edit::Item::Table(wraps));
    }
    Ok(doc.to_string())
}

/// `auto-rules.json5` → `auto-rules.toml`. The rules file has no dynamic keys
/// and no sigils, so this is a pure format change.
fn rules_json5_to_toml(root: &Value) -> Result<String> {
    let doc = toml_edit::ser::to_document(root).context("re-serialize rules as TOML")?;
    Ok(doc.to_string())
}

/// Recursively drop the `$` from `$reason` (and any sibling sigil'd key),
/// which is the only sigil that ever appeared below the root.
fn strip_sigils(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let key = k.strip_prefix('$').unwrap_or(k).to_owned();
                    (key, strip_sigils(v))
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Convert a `serde_json` value into a `toml_edit` item. A JSON `null` has no
/// TOML spelling; the loader already treated an explicit null as an absent
/// key, so it is dropped here for the same reason.
fn json_to_item(value: &Value) -> toml_edit::Item {
    fn to_value(v: &Value) -> Option<toml_edit::Value> {
        Some(match v {
            Value::Null => return None,
            Value::Bool(b) => (*b).into(),
            Value::Number(n) => match (n.as_i64(), n.as_f64()) {
                (Some(i), _) => i.into(),
                (_, Some(f)) => f.into(),
                _ => return None,
            },
            Value::String(s) => s.as_str().into(),
            Value::Array(items) => {
                toml_edit::Value::Array(items.iter().filter_map(to_value).collect())
            }
            Value::Object(map) => {
                let mut t = toml_edit::InlineTable::new();
                for (k, v) in map {
                    if let Some(v) = to_value(v) {
                        t.insert(k, v);
                    }
                }
                toml_edit::Value::InlineTable(t)
            }
        })
    }

    match value {
        // A map becomes a real table so it renders as `[section]` rather than
        // one long inline `{ … }` line.
        Value::Object(map) => {
            let mut table = toml_edit::Table::new();
            for (k, v) in map {
                table.insert(k, json_to_item(v));
            }
            toml_edit::Item::Table(table)
        }
        other => match to_value(other) {
            Some(v) => toml_edit::Item::Value(v),
            None => toml_edit::Item::None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn convert_config(text: &str) -> String {
        let root: Value = json5::from_str(text).expect("fixture is valid JSON5");
        config_json5_to_toml(&root).expect("convert")
    }

    #[test]
    fn wraps_move_under_the_wraps_table_and_lose_their_sigils() {
        let out = convert_config(
            r#"{
                $shim_dir: "~/.secreq/shims",
                gh: {
                    $reason: "GitHub API access",
                    env: { GITHUB_TOKEN: "secret://op/Personal/GitHub/token" },
                },
            }"#,
        );
        let c = crate::wraps::WrapsConfig::parse(&out, "converted").expect("re-parses as TOML");
        let gh = c.wrap("gh").expect("gh survived");
        assert_eq!(gh.reason.as_deref(), Some("GitHub API access"));
        assert_eq!(
            gh.env.get("GITHUB_TOKEN").map(String::as_str),
            Some("secret://op/Personal/GitHub/token")
        );
        assert!(c.shim_dir.is_some(), "shim_dir carried across");
    }

    #[test]
    fn a_binary_named_like_a_reserved_key_survives_the_move() {
        // The whole point of the `[wraps.*]` nesting: before it, a wrap could
        // not be called `providers` at all.
        let out = convert_config(r#"{ providers: { op: { retrieve: ["true"] } } }"#);
        let c = crate::wraps::WrapsConfig::parse(&out, "converted").expect("re-parses");
        assert!(c.providers.contains_key("op"));
        assert!(!c.wraps.contains_key("providers"));
    }

    #[test]
    fn ssh_identities_keep_their_shape_and_lose_the_reason_sigil() {
        let out = convert_config(
            r#"{
                ssh: {
                    github: {
                        $reason: "git pushes",
                        public_key: "ssh-ed25519 AAAA me@mac",
                        private_key: "secret://op/Private/gh/key",
                    },
                },
            }"#,
        );
        let c = crate::wraps::WrapsConfig::parse(&out, "converted").expect("re-parses");
        let id = &c.ssh["github"];
        assert_eq!(id.reason.as_deref(), Some("git pushes"));
        assert_eq!(id.private_key.provider, "op");
    }

    #[test]
    fn the_schema_pointer_is_dropped_rather_than_translated() {
        // TOML carries it as a `#:schema` comment, so a `$schema` key would
        // just be an unknown field the new loader rejects.
        let out = convert_config(r#"{ $schema: "https://secreq.dev/x.json", gh: { env: {} } }"#);
        assert!(!out.contains("schema"), "got: {out}");
        crate::wraps::WrapsConfig::parse(&out, "converted").expect("re-parses");
    }

    #[test]
    fn an_explicit_null_reason_becomes_an_absent_key() {
        // TOML has no null. The loader already read one as "absent", so
        // dropping it preserves the meaning rather than changing it.
        let out = convert_config(r#"{ gh: { $reason: null, env: { X: "secret://op/x" } } }"#);
        let c = crate::wraps::WrapsConfig::parse(&out, "converted").expect("re-parses");
        assert_eq!(c.wrap("gh").expect("gh").reason, None);
    }

    #[test]
    fn converting_is_idempotent_when_the_target_already_exists() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join(LEGACY_CONFIG);
        let to = dir.path().join(CONFIG);
        std::fs::write(&from, r#"{ gh: { env: {} } }"#).unwrap();
        std::fs::write(&to, "[wraps.terraform]\n").unwrap();

        assert!(convert(&from, &to, config_json5_to_toml)
            .expect("convert")
            .is_none());

        // The pre-existing target wins and the legacy file is cleared, so a
        // re-run cannot clobber a config written since.
        assert!(!from.exists(), "legacy file removed");
        assert_eq!(std::fs::read_to_string(&to).unwrap(), "[wraps.terraform]\n");
    }

    #[test]
    fn a_missing_legacy_file_is_a_fresh_install_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(convert(
            &dir.path().join(LEGACY_CONFIG),
            &dir.path().join(CONFIG),
            config_json5_to_toml,
        )
        .expect("nothing to do")
        .is_none());
        assert!(!dir.path().join(CONFIG).exists());
    }

    #[test]
    fn an_unparseable_legacy_file_stops_the_migration_instead_of_failing_it() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join(LEGACY_CONFIG);
        std::fs::write(&from, "this is not JSON5 at all").unwrap();

        let stop = convert(&from, &dir.path().join(CONFIG), config_json5_to_toml)
            .expect("a bad config is a stop, not an error")
            .expect("it should report a reason");

        assert!(stop.contains(LEGACY_CONFIG), "names the file: {stop}");
        // Left in place so the user can repair it and re-run.
        assert!(from.exists(), "the unreadable original is not deleted");
    }

    /// The sigil is stripped from *keys* only — a `$` inside a value is the
    /// user's text and stays.
    #[test]
    fn strip_sigils_only_touches_keys() {
        let v: Value = json5::from_str(r#"{ $reason: "keep $this value" }"#).unwrap();
        let stripped = strip_sigils(&v);
        assert_eq!(
            stripped["reason"],
            Value::String("keep $this value".to_owned())
        );
        assert!(stripped.get("$reason").is_none());
    }
}
