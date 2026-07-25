//! Scaffolding for **programmatic (wasm) auto-rules** and the editor
//! plumbing behind the rule editor's "Open in editor" split-button.
//!
//! The declarative rule form ([`crate::daemon::ui`]) authors match-clause
//! rules; the *primary* way to write an auto-approval, though, is a
//! programmatic rule — a single AssemblyScript `decide(ctx)` function
//! compiled to a sandboxed wasm module (see [`crate::wasm_rules`] and
//! `docs/wasm-rules.md`). This module makes that a one-click path from the
//! editor:
//!
//! 1. [`scaffold_new_rule`] writes a ready-to-edit rule project to disk
//!    (under `$SECREQ_HOME/rule-drafts/<slug>/`).
//! 2. [`detect_editors`] probes the machine for installed editors so the
//!    split-button only offers ones that are actually present.
//! 3. [`preferred_editor`] / [`save_preferred_editor`] persist the user's
//!    pick as the reserved `$editor` key in `wraps.json5`, so the
//!    split-button defaults to it next time.
//!
//! Everything here is pure/local — no daemon round-trip. The rule editor
//! runs in a child process with ordinary filesystem access, so it writes
//! the scaffold, launches the editor, and records the preference directly.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::paths;

/// One editor the machine offers, in the shape the split-button needs.
/// `id` is the stable value persisted to config (and matched back on
/// load); `display` is the human label; `program` is the executable to
/// spawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Editor {
    /// Stable identifier, also the executable's basename — e.g. `"code"`,
    /// `"nvim"`. This is what lands in `$editor`.
    pub id: String,
    /// Human-facing name for the button — e.g. `"VS Code"`, `"Neovim"`.
    pub display: String,
    /// The program to launch. Usually equal to `id`, but kept separate so
    /// a future entry can point at an absolute path.
    pub program: String,
}

impl Editor {
    /// Construct an editor entry. Public so the screenshot harness can
    /// seed a deterministic list without probing the host.
    pub fn new(id: &str, display: &str, program: &str) -> Editor {
        Editor {
            id: id.to_owned(),
            display: display.to_owned(),
            program: program.to_owned(),
        }
    }
}

/// The known-editor catalog, in preference order (GUI editors first, so a
/// machine with both VS Code and vim defaults to the graphical one). Each
/// entry is `(id/program, display)`. Only the ones present on `PATH` are
/// surfaced — see [`detect_editors`].
const EDITOR_CATALOG: &[(&str, &str)] = &[
    ("code", "VS Code"),
    ("code-insiders", "VS Code Insiders"),
    ("cursor", "Cursor"),
    ("windsurf", "Windsurf"),
    ("zed", "Zed"),
    ("subl", "Sublime Text"),
    ("idea", "IntelliJ IDEA"),
    ("gedit", "gedit"),
    ("kate", "Kate"),
    ("hx", "Helix"),
    ("nvim", "Neovim"),
    ("vim", "Vim"),
    ("emacs", "Emacs"),
    ("micro", "micro"),
    ("nano", "nano"),
];

/// Detected editors, filtered to those actually installed on this
/// machine. Probes `PATH`; the result is the split-button's menu.
pub fn detect_editors() -> Vec<Editor> {
    detect_editors_with(program_on_path)
}

/// Testable core of [`detect_editors`]: `probe(program)` decides whether a
/// catalog entry is installed. Preserves catalog order.
pub fn detect_editors_with(probe: impl Fn(&str) -> bool) -> Vec<Editor> {
    EDITOR_CATALOG
        .iter()
        .filter(|&&(program, _)| probe(program))
        .map(|&(program, display)| Editor::new(program, display, program))
        .collect()
}

/// Is `program` resolvable on `PATH`? Mirrors `commands::which_on_path`
/// but kept local so this module has no cross-module coupling for a
/// one-line lookup.
fn program_on_path(program: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| dir.join(program).exists())
}

/// The outcome of scaffolding: the project directory and the entry file
/// (`rule.ts`) the editor should open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scaffold {
    /// The generated project directory.
    pub dir: PathBuf,
    /// The AssemblyScript source the user edits — what "Open in editor"
    /// targets.
    pub entry: PathBuf,
}

/// Scaffold a fresh programmatic-rule project under the standard
/// `$SECREQ_HOME/rule-drafts/` tree with a unique slug, ready to edit.
pub fn scaffold_new_rule() -> Result<Scaffold> {
    let parent = paths::rule_drafts_dir()?;
    // Short random suffix keeps successive scaffolds from colliding
    // without asking the user to name the draft up front.
    let id = crate::rules::new_rule_id();
    let slug = format!("rule-{}", &id[..8.min(id.len())]);
    scaffold_rule(&parent, &slug)
}

/// Write the rule-project skeleton into `parent/<slug>/`. Split from
/// [`scaffold_new_rule`] so tests can point it at a tempdir. Refuses to
/// overwrite an existing directory — a scaffold never clobbers work.
pub fn scaffold_rule(parent: &Path, slug: &str) -> Result<Scaffold> {
    if slug.is_empty() || slug.contains('/') || slug == "." || slug == ".." {
        bail!("invalid rule-project slug {slug:?}");
    }
    let dir = parent.join(slug);
    if dir.exists() {
        bail!("rule project {} already exists", dir.display());
    }
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create rule project dir {}", dir.display()))?;

    let entry = dir.join("rule.ts");
    std::fs::write(&entry, RULE_TS_TEMPLATE)
        .with_context(|| format!("write {}", entry.display()))?;
    let readme = dir.join("README.md");
    std::fs::write(&readme, README_TEMPLATE)
        .with_context(|| format!("write {}", readme.display()))?;

    Ok(Scaffold { dir, entry })
}

/// Starter `rule.ts` — a compiling, passing rule the user edits in place.
/// Mirrors the shape documented in `packages/secreq-rule` and `docs/wasm-rules.md`.
const RULE_TS_TEMPLATE: &str = r#"// A programmatic secreq auto-rule.
//
// You write one function — `decide(ctx)` — that returns `approve()`,
// `deny(reason)`, or `pass()` (no opinion → fall through to the prompt).
// It runs in a sandbox before the consent prompt: no filesystem, network,
// clock, or env access; the only thing it can read is `ctx`.
//
// Edit the policy below, then compile and register:
//
//     npm install                                  # once, pulls assemblyscript
//     npx secreq-rule-build rule.ts -o rule.wasm
//     secreq rules add-wasm rule.wasm --name "my rule" --secret GITHUB_TOKEN
//
// See docs/wasm-rules.md for the full authoring guide.

import { RuleCtx, Decision, approve, pass, deny } from "secreq-rule";

export function decide(ctx: RuleCtx): Decision {
  // Example: auto-approve read-only `gh api --get` calls, and never
  // auto-approve repo deletes. Replace with your own policy.
  if (ctx.wrap == "gh") {
    if (ctx.joinedArgv.startsWith("gh repo delete")) {
      return deny("repo deletes are never auto-approved");
    }
    if (ctx.joinedArgv.startsWith("gh api --get ")) {
      return approve();
    }
  }

  // No opinion — let declarative rules and the interactive prompt decide.
  return pass();
}
"#;

/// Starter `README.md` dropped beside the rule so the project is
/// self-documenting when opened.
const README_TEMPLATE: &str = r#"# secreq programmatic rule

This is a scaffolded **programmable secreq auto-rule**. Edit `rule.ts`,
then build and register it:

```sh
npm install                                  # once, pulls assemblyscript
npx secreq-rule-build rule.ts -o rule.wasm
secreq rules add-wasm rule.wasm --name "my rule" --secret GITHUB_TOKEN
```

`rule.ts` exports a single `decide(ctx)` function returning `approve()`,
`deny(reason)`, or `pass()`. It runs sandboxed before the consent prompt —
no filesystem, network, clock, or env access; it only sees `ctx`.

See `docs/wasm-rules.md` in the secreq repo for the full guide.
"#;

/// Launch `editor` on `path`, detached from this process. Best-effort:
/// GUI editors (`code`, `zed`, …) open the file; terminal editors
/// (`vim`, `nano`, …) are spawned too, though they need a terminal to be
/// useful. Returns an error only if the spawn itself fails.
pub fn launch_editor(editor: &Editor, path: &Path) -> Result<()> {
    Command::new(&editor.program)
        .arg(path)
        .spawn()
        .with_context(|| format!("launch editor `{}`", editor.program))?;
    Ok(())
}

// ── Editor preference: the reserved `$editor` key in wraps.json5 ───────────

/// The user's persisted editor pick (the `$editor` id), if any. Read from
/// `wraps.json5`; a missing/unreadable config just yields `None`.
pub fn preferred_editor() -> Option<String> {
    let path = paths::wraps_path().ok()?;
    let config = crate::wraps::WrapsConfig::load(&path).ok()?;
    config.editor
}

/// Persist `id` as the reserved top-level `$editor` key in `wraps.json5`,
/// preserving everything else in the file (comments, provider defs, and
/// the store/retrieve details the full serializer would drop). A missing
/// config file is created as `{ $editor: "id" }`.
pub fn save_preferred_editor(id: &str) -> Result<()> {
    let path = paths::wraps_path()?;
    let existing = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "{\n}\n".to_owned(),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let updated = upsert_editor_key(&existing, id);
    // Round-trip through the parser so a malformed edit never lands — and
    // confirm the key actually resolves to `id` (guards the pathological
    // case of a pre-existing inline `$editor` the line-based upsert can't
    // see, where a stale duplicate would otherwise silently win).
    let parsed = crate::wraps::WrapsConfig::parse(&updated, &path.display().to_string())
        .context("internal: config with updated $editor doesn't re-parse")?;
    if parsed.editor.as_deref() != Some(id) {
        bail!(
            "could not set `$editor` in {} — edit it by hand to `$editor: {id:?}`",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, updated).with_context(|| format!("write {}", path.display()))
}

/// Insert-or-replace the top-level `$editor: "<id>"` assignment in a
/// wraps.json5 text, leaving all other content untouched.
///
/// `$editor` is a reserved *top-level* key — [`crate::wraps`] rejects it
/// anywhere else — so a line-oriented match is unambiguous: we replace the
/// first line that assigns `$editor` (bare or quoted), or, if none exists,
/// insert a fresh assignment right after the opening `{`.
fn upsert_editor_key(text: &str, id: &str) -> String {
    let value = serde_json::to_string(id).unwrap_or_else(|_| format!("{id:?}"));
    let new_line = format!("  \"$editor\": {value},");

    // Try to replace an existing assignment first.
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    for line in &mut lines {
        if line_assigns_editor(line) {
            *line = new_line.clone();
            let mut out = lines.join("\n");
            if text.ends_with('\n') {
                out.push('\n');
            }
            return out;
        }
    }

    // No existing key — insert after the first `{`.
    if let Some(pos) = text.find('{') {
        let (head, tail) = text.split_at(pos + 1);
        return format!("{head}\n{new_line}{tail}");
    }

    // Not an object at all (empty/garbage) — write a fresh minimal config.
    format!("{{\n{new_line}\n}}\n")
}

/// Does this line assign the top-level `$editor` key? Matches `$editor:`,
/// `"$editor":`, or `'$editor':` after leading whitespace.
fn line_assigns_editor(line: &str) -> bool {
    let t = line.trim_start();
    for stripped in [
        t.strip_prefix("$editor"),
        t.strip_prefix("\"$editor\""),
        t.strip_prefix("'$editor'"),
    ]
    .into_iter()
    .flatten()
    {
        if stripped.trim_start().starts_with(':') {
            return true;
        }
    }
    false
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_filters_to_installed_and_keeps_catalog_order() {
        // Pretend only vim and code are installed; result must be
        // [code, vim] (catalog order), not detection/probe order.
        let installed = ["vim", "code"];
        let editors = detect_editors_with(|p| installed.contains(&p));
        let ids: Vec<&str> = editors.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["code", "vim"]);
        assert_eq!(editors[0].display, "VS Code");
    }

    #[test]
    fn detect_empty_when_nothing_installed() {
        assert!(detect_editors_with(|_| false).is_empty());
    }

    #[test]
    fn scaffold_writes_rule_ts_and_readme() {
        let tmp = tempfile::tempdir().expect("tmp");
        let out = scaffold_rule(tmp.path(), "rule-abc123").expect("scaffold");
        assert!(out.entry.ends_with("rule.ts"));
        assert!(out.entry.exists());
        assert!(out.dir.join("README.md").exists());
        let src = std::fs::read_to_string(&out.entry).expect("read");
        assert!(src.contains("export function decide"));
        assert!(src.contains("secreq-rule"));
    }

    #[test]
    fn scaffold_refuses_to_clobber_existing_dir() {
        let tmp = tempfile::tempdir().expect("tmp");
        scaffold_rule(tmp.path(), "dup").expect("first");
        let err = scaffold_rule(tmp.path(), "dup").expect_err("second must fail");
        assert!(format!("{err:#}").contains("already exists"));
    }

    #[test]
    fn scaffold_rejects_traversal_slug() {
        let tmp = tempfile::tempdir().expect("tmp");
        assert!(scaffold_rule(tmp.path(), "../escape").is_err());
        assert!(scaffold_rule(tmp.path(), "").is_err());
    }

    #[test]
    fn upsert_inserts_into_empty_object() {
        let out = upsert_editor_key("{\n}\n", "code");
        assert!(out.contains("\"$editor\": \"code\""));
        // Still parses as a config with the editor set.
        let c = crate::wraps::WrapsConfig::parse(&out, "t").expect("parse");
        assert_eq!(c.editor.as_deref(), Some("code"));
    }

    #[test]
    fn upsert_replaces_existing_editor_preserving_other_keys() {
        let text = "{\n  \"$editor\": \"vim\",\n  gh: { env: {} },\n}\n";
        let out = upsert_editor_key(text, "zed");
        assert!(out.contains("\"$editor\": \"zed\""));
        assert!(!out.contains("\"vim\""));
        // The unrelated wrap survives the edit.
        assert!(out.contains("gh: { env: {} }"));
        let c = crate::wraps::WrapsConfig::parse(&out, "t").expect("parse");
        assert_eq!(c.editor.as_deref(), Some("zed"));
        assert!(c.wraps.contains_key("gh"));
    }

    #[test]
    fn upsert_preserves_comments_when_inserting() {
        let text = "{\n  // keep me\n  gh: { env: {} },\n}\n";
        let out = upsert_editor_key(text, "cursor");
        assert!(out.contains("// keep me"), "comment must survive: {out}");
        assert!(out.contains("\"$editor\": \"cursor\""));
    }

    #[test]
    fn line_match_is_top_level_only() {
        assert!(line_assigns_editor("  $editor: \"code\","));
        assert!(line_assigns_editor("\"$editor\": \"code\""));
        assert!(line_assigns_editor("  '$editor' : 'x'"));
        // A wrap literally named something with $editor inside isn't a
        // top-level assignment line.
        assert!(!line_assigns_editor("  gh: { $editor_note: 1 },"));
        assert!(!line_assigns_editor("  // $editor is the key"));
    }
}
