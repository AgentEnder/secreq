//! Scaffolding for **programmatic (wasm) auto-rules** and the editor
//! plumbing behind the rule editor's "Open in editor" split-button.
//!
//! The declarative rule form ([`crate::daemon::ui`]) authors match-clause
//! rules; the *primary* way to write an auto-approval, though, is a
//! programmatic rule — a single AssemblyScript `decide(ctx)` function
//! compiled to a sandboxed wasm module (see [`crate::wasm_rules`] and
//! `docs/wasm-rules.md`). This module writes the whole project:
//!
//! 1. [`write_project`] lays down a buildable npm package — `package.json`
//!    wired to the `secreq-rule` SDK, the `assembly/rule.ts` stub, an
//!    as-pect spec, and the test-runner config. Two commands reach it:
//!    `secreq rules new-wasm <dir>` for a directory the user names, and
//!    [`scaffold_new_rule`] for the rule editor's one-click draft under
//!    `$SECREQ_HOME/rule-drafts/<slug>/`.
//! 2. [`detect_editors`] probes the machine for installed editors so the
//!    split-button only offers ones that are actually present.
//! 3. [`preferred_editor`] / [`save_preferred_editor`] persist the user's
//!    pick as the reserved `editor` key in `config.toml`, so the
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
    /// `"nvim"`. This is what lands in `editor`.
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
/// (`assembly/rule.ts`) the editor should open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scaffold {
    /// The generated project directory.
    pub dir: PathBuf,
    /// The AssemblyScript source the user edits — what "Open in editor"
    /// targets.
    pub entry: PathBuf,
}

/// Version range written for the registry SDK when no checkout is in
/// reach. Held to `packages/secreq-rule/package.json` by a unit test
/// below, so bumping the SDK's version does not silently leave scaffolds
/// asking for the previous one.
pub const SDK_VERSION_RANGE: &str = "^0.1.0";

/// Everything else a generated project installs. Same versions the worked
/// example pins, so a scaffold and the example resolve the same toolchain.
const AS_PECT_RANGE: &str = "^9.0.0";
const ASSEMBLYSCRIPT_RANGE: &str = "^0.28.2";

/// How a generated `package.json` reaches the `secreq-rule` SDK.
///
/// The worked example under `packages/secreq-rule/examples/` depends on
/// `file:../..`, which only means anything from inside the SDK tree — copy
/// it out and `npm install` fails. A scaffold lands wherever the user
/// pointed it, so it needs a specifier that does not depend on where that
/// is: an absolute path, or the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdkDep {
    /// An absolute path to a `secreq-rule` package on this machine,
    /// written as npm's `file:` specifier. Preferred, and the only one
    /// that resolves today.
    Local(PathBuf),
    /// The registry package at [`SDK_VERSION_RANGE`]. What a scaffold
    /// falls back to when no checkout is in reach — and, until the SDK is
    /// published, a dependency `npm install` cannot satisfy. Callers say
    /// so rather than handing over a project that fails on install.
    Published,
}

impl SdkDep {
    /// Prefer a checkout on this machine; fall back to the registry.
    pub fn detect() -> SdkDep {
        locate_sdk().map_or(SdkDep::Published, SdkDep::Local)
    }

    /// The value of the manifest's `secreq-rule` entry.
    pub fn spec(&self) -> String {
        match self {
            SdkDep::Local(path) => format!("file:{}", path.display()),
            SdkDep::Published => SDK_VERSION_RANGE.to_owned(),
        }
    }
}

/// The `secreq-rule` package directory on this machine, if one is in
/// reach: walks up from this executable and from the working directory
/// looking for `packages/secreq-rule`.
///
/// That finds the SDK for anyone running from — or standing in — a secreq
/// checkout, which is everyone who can use it at all: an installed
/// `secreq` has no SDK beside it and the package is not on npm yet.
pub fn locate_sdk() -> Option<PathBuf> {
    let starts = [std::env::current_exe().ok(), std::env::current_dir().ok()];
    starts.into_iter().flatten().find_map(|start| {
        start
            .ancestors()
            .map(|dir| dir.join("packages").join("secreq-rule"))
            .find(|candidate| is_sdk_dir(candidate))
    })
}

/// The npm package name the SDK publishes under, and the one a generated
/// project's `import … from 'secreq-rule'` resolves through.
const SDK_PACKAGE_NAME: &str = "secreq-rule";

/// Does `dir` hold the `secreq-rule` package? Checks the two files a
/// generated project actually consumes — the manifest npm resolves and the
/// build wrapper `npm run build` shells out to — **and** that the manifest
/// names the SDK.
///
/// Shape alone is not enough for the ancestor walk. `packages/<x>` with a
/// `package.json` and a `bin/build.js` describes plenty of packages, and
/// the first match wins silently; since a local path is the only SDK
/// specifier that resolves today, a plausible-but-wrong match would be
/// found out at `npm run build`, several steps from the cause.
fn is_sdk_dir(dir: &Path) -> bool {
    if !dir.join("bin").join("build.js").is_file() {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(dir.join("package.json")) else {
        return false;
    };
    let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    pkg.get("name").and_then(serde_json::Value::as_str) == Some(SDK_PACKAGE_NAME)
}

/// Resolve a user-supplied `--sdk` path to the absolute one that goes in
/// the manifest. A relative `file:` specifier would resolve against the
/// generated project, not against the cwd the user typed it from.
pub fn resolve_sdk_dir(dir: &Path) -> Result<PathBuf> {
    let abs = dir
        .canonicalize()
        .with_context(|| format!("--sdk path not readable: {}", dir.display()))?;
    if !is_sdk_dir(&abs) {
        bail!(
            "{} is not the {SDK_PACKAGE_NAME} package (wanted a package.json naming it, \
             plus bin/build.js); point --sdk at `packages/secreq-rule` in a secreq checkout",
            abs.display()
        );
    }
    Ok(abs)
}

/// What a generated project is made of.
pub struct ProjectOpts {
    /// npm package name written into `package.json`.
    pub name: String,
    /// How that manifest reaches the SDK.
    pub sdk: SdkDep,
    /// Seed `assembly/` from this project's own `assembly/` tree — an SDK
    /// example, via `--from` — instead of writing the stub rule and spec.
    pub seed: Option<PathBuf>,
}

impl ProjectOpts {
    /// A stub project named `name`, against whichever SDK this machine
    /// offers.
    pub fn new(name: &str) -> ProjectOpts {
        ProjectOpts {
            name: name.to_owned(),
            sdk: SdkDep::detect(),
            seed: None,
        }
    }
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
///
/// The project directory is owner-only. A bare `create_dir_all` takes
/// the umask's answer — 0755 under the common 022, 0777 under the 000 of
/// a container image — and the draft it holds is the source of a rule
/// that will decide whether commands get a secret without asking. Anyone
/// who can edit `rule.ts` between the scaffold and the build writes that
/// policy.
///
/// [`crate::paths::ensure_private_dir`] narrows as well as creates, so it
/// must never be aimed at a path a user named. It is not one here: the
/// last component is a slug this module minted (`rule-<hex>`) and
/// validated against separators, and in production `parent` is
/// [`crate::paths::rule_drafts_dir`] under the secreq root. The path a
/// user *does* name goes through [`create_project_dir`] instead.
pub fn scaffold_rule(parent: &Path, slug: &str) -> Result<Scaffold> {
    if slug.is_empty() || slug.contains('/') || slug == "." || slug == ".." {
        bail!("invalid rule-project slug {slug:?}");
    }
    let dir = parent.join(slug);
    if dir.exists() {
        bail!("rule project {} already exists", dir.display());
    }
    paths::ensure_private_dir(&dir)
        .with_context(|| format!("create rule project dir {}", dir.display()))?;
    write_project(&dir, &ProjectOpts::new(slug))
}

/// Create the target directory for a project the user named, owner-only
/// when secreq is the one creating it.
///
/// Same reasoning as [`scaffold_rule`]'s — a scaffold holds the source of
/// a policy that releases secrets without asking — with one thing left
/// out. [`crate::paths::ensure_private_dir`] also *narrows* a directory
/// that already exists, which is right under the secreq root and wrong for
/// a path off a command line: `secreq rules new-wasm .` would chmod the
/// user's working directory to 0700.
///
/// An existing directory is accepted only when empty. A scaffold writes
/// several files; landing them into a directory that already holds work is
/// how you lose a `package.json`.
pub fn create_project_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    if dir.exists() {
        if !dir.is_dir() {
            bail!("{} exists and is not a directory", dir.display());
        }
        let mut entries =
            std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))?;
        if entries.next().is_some() {
            bail!(
                "{} is not empty — scaffold into a new directory",
                dir.display()
            );
        }
        return Ok(());
    }
    // Missing parents are the user's own tree, so they get the umask's
    // answer; only the project directory is narrowed.
    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create dir {}", parent.display()))?;
    }
    std::fs::DirBuilder::new()
        .mode(paths::PRIVATE_DIR_MODE)
        .create(dir)
        .with_context(|| format!("create rule project dir {}", dir.display()))?;
    // `DirBuilder::mode` is masked by the umask, which can only clear bits —
    // but an owner bit cleared there leaves a directory secreq cannot write
    // the project into, so say it unmasked. Same follow-up as
    // `paths::ensure_private_dir` and `scoped_agent::create_staging_dir`.
    std::fs::set_permissions(
        dir,
        std::fs::Permissions::from_mode(paths::PRIVATE_DIR_MODE),
    )
    .with_context(|| format!("set mode 0700 on {}", dir.display()))
}

/// Write a buildable rule project into the (existing, empty) directory
/// `dir`.
///
/// Resolving the whole file set first is what makes an unreadable `--from`
/// seed cheap: it fails before the first `write`, so a mistyped example
/// name leaves nothing behind. It is **not** a rollback — a write that
/// fails partway through (a full disk, a revoked permission) leaves the
/// files already written where they are, and the directory is the user's
/// to delete.
///
/// **Neither the directories nor the files take the umask's answer.** Both
/// `mkdir` and `open` mask the mode they are given, and a umask clears
/// owner bits as readily as group and world ones — under `umask 700` a
/// `create_dir_all` here lands 0000 and a `fs::write` lands `----rw-rw-`,
/// a file its own owner cannot read. The command would still exit 0 on the
/// second, having produced a project `npm install` cannot install.
///
/// So directories go through [`crate::paths::ensure_private_dir`] and files
/// through [`crate::atomic::replace`] at [`crate::paths::PRIVATE_FILE_MODE`]
/// — each of which re-applies the mode unmasked after creating. Narrowing
/// the directories is safe here: every component is a constant of this
/// module or a name read out of the seed tree, never a path a user typed.
///
/// **Owner-only, not merely owner-readable.** 0600 rather than 0644 because
/// the enclosing directory is 0700, so a wider file mode grants nobody
/// anything — and because `rule.ts` is the source of a policy that will
/// release secrets without prompting, which is the same reason the
/// directories are owner-only ([`create_project_dir`]). It also puts these
/// files where every other file secreq writes already is; see
/// [`crate::atomic`], whose position is that nothing secreq writes is
/// low-sensitivity enough to want the umask's answer. Git does not record
/// the read bits, so committing and sharing the project are unaffected.
pub fn write_project(dir: &Path, opts: &ProjectOpts) -> Result<Scaffold> {
    for (rel, contents) in project_files(opts)? {
        let path = dir.join(rel);
        if let Some(parent) = path.parent().filter(|p| *p != dir) {
            paths::ensure_private_dir(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
        crate::atomic::replace(
            &path,
            contents.as_bytes(),
            crate::atomic::Mode::Exactly(paths::PRIVATE_FILE_MODE),
        )
        .with_context(|| format!("write {}", path.display()))?;
    }
    Ok(Scaffold {
        dir: dir.to_path_buf(),
        entry: dir.join("assembly").join("rule.ts"),
    })
}

/// Every file a generated project gets, as (project-relative path,
/// contents). The `assembly/` half is what `--from` swaps out; everything
/// else is scaffolding this module owns either way.
fn project_files(opts: &ProjectOpts) -> Result<Vec<(PathBuf, String)>> {
    let mut files = vec![
        (PathBuf::from("package.json"), package_json(opts)),
        (PathBuf::from("README.md"), readme(opts)),
        (PathBuf::from(".gitignore"), GITIGNORE.to_owned()),
        (
            PathBuf::from("as-pect.config.js"),
            AS_PECT_CONFIG.to_owned(),
        ),
        (
            PathBuf::from("as-pect.asconfig.json"),
            AS_PECT_ASCONFIG.to_owned(),
        ),
    ];
    match &opts.seed {
        Some(seed) => files.extend(read_assembly_tree(seed)?),
        None => files.extend([
            (PathBuf::from("assembly/rule.ts"), RULE_TS.to_owned()),
            (
                PathBuf::from("assembly/tsconfig.json"),
                ASSEMBLY_TSCONFIG.to_owned(),
            ),
            (
                PathBuf::from("assembly/__tests__/rule.spec.ts"),
                RULE_SPEC_TS.to_owned(),
            ),
            (
                PathBuf::from("assembly/__tests__/as-pect.d.ts"),
                AS_PECT_DTS.to_owned(),
            ),
        ]),
    }
    Ok(files)
}

/// Read `<seed>/assembly/**` into the file set, rooted back at
/// `assembly/`. The seed is one of the SDK's examples, so it carries its
/// own `tsconfig.json` and `as-pect.d.ts` alongside the rule — take the
/// tree as it stands rather than merging two ideas of it.
fn read_assembly_tree(seed: &Path) -> Result<Vec<(PathBuf, String)>> {
    let root = seed.join("assembly");
    let mut out = Vec::new();
    collect_files(&root, &PathBuf::from("assembly"), &mut out)?;
    if out.is_empty() {
        bail!("{} has no sources to seed from", root.display());
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Recursive half of [`read_assembly_tree`]: every regular file under
/// `dir`, keyed by `prefix`-relative path.
fn collect_files(dir: &Path, prefix: &Path, out: &mut Vec<(PathBuf, String)>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read {}", dir.display()))?;
        let path = entry.path();
        let rel = prefix.join(entry.file_name());
        if path.is_dir() {
            collect_files(&path, &rel, out)?;
        } else {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            out.push((rel, text));
        }
    }
    Ok(())
}

/// npm package name derived from a directory name. See
/// [`package_name`] for the folding.
pub fn package_name_from_dir(dir: &Path) -> String {
    package_name(&dir.file_name().unwrap_or_default().to_string_lossy())
}

/// npm's hard cap on a package name, in characters.
const NPM_NAME_MAX: usize = 214;

/// Name for a project whose directory name folds away to nothing. Not
/// [`SDK_PACKAGE_NAME`]: npm refuses to install a dependency under a
/// package of the same name (`ENOSELF`), and every generated project
/// depends on the SDK.
const FALLBACK_PACKAGE_NAME: &str = "my-secreq-rule";

/// Fold `raw` into a name npm accepts: lowercased, capped at
/// [`NPM_NAME_MAX`], with anything npm would refuse turned into `-`.
/// Applied to `--name` as well as to the directory name, because npm
/// rejects a manifest whose `name` has a space or a capital in it — and a
/// scaffold that cannot `npm install` is the thing this command exists to
/// stop shipping. A string with nothing usable in it falls back to
/// [`FALLBACK_PACKAGE_NAME`].
pub fn package_name(raw: &str) -> String {
    let folded: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    // npm refuses a name starting with `.` or `_`, and a trailing dash is
    // just noise. Trimmed again after the cap, which can leave one.
    let trimmed = folded.trim_matches(['-', '.', '_'].as_slice());
    // Every char is ASCII by construction, so a byte truncation is a char
    // truncation and cannot split a code point.
    let capped = trimmed
        .get(..NPM_NAME_MAX)
        .unwrap_or(trimmed)
        .trim_matches(['-', '.', '_'].as_slice());
    if capped.is_empty() {
        FALLBACK_PACKAGE_NAME.to_owned()
    } else {
        capped.to_owned()
    }
}

/// Escape a string for a JSON string literal.
///
/// `opts.name` is folded to `[a-z0-9._-]` and needs none of this, but the
/// SDK path does: a Unix filename may legally hold a quote, a backslash, a
/// newline or a tab, and an unescaped one of the last two is a manifest
/// that parses nowhere. Reached only through `--sdk`, and cheap to close.
fn json_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            // The rest of C0, which JSON forbids raw and has no short form
            // for.
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The generated `package.json`. Mirrors the worked example's, with the
/// `secreq-rule` dependency resolved for a project that lives anywhere.
fn package_json(opts: &ProjectOpts) -> String {
    format!(
        r#"{{
  "name": "{name}",
  "version": "0.1.0",
  "private": true,
  "description": "A programmable secreq auto-rule.",
  "type": "module",
  "scripts": {{
    "test": "asp --verbose",
    "build": "secreq-rule-build assembly/rule.ts -o rule.wasm"
  }},
  "devDependencies": {{
    "@as-pect/cli": "{as_pect}",
    "assemblyscript": "{assemblyscript}",
    "secreq-rule": "{sdk}"
  }}
}}
"#,
        name = json_escape(&opts.name),
        as_pect = AS_PECT_RANGE,
        assemblyscript = ASSEMBLYSCRIPT_RANGE,
        sdk = json_escape(&opts.sdk.spec()),
    )
}

/// The generated `README.md`. The SDK line differs by [`SdkDep`]: a
/// `file:` dependency is pinned to one machine and has to be re-pointed
/// before the project is shared, and the registry one does not resolve
/// yet.
fn readme(opts: &ProjectOpts) -> String {
    let sdk_note = match &opts.sdk {
        SdkDep::Local(path) => format!(
            "`package.json` depends on the SDK by absolute path\n\
             (`file:{path}`), which is this machine's checkout. Re-point it before\n\
             sharing the project.",
            path = path.display(),
        ),
        SdkDep::Published => format!(
            "`package.json` depends on `secreq-rule@{SDK_VERSION_RANGE}` from the registry.\n\
             The SDK is not published yet, so `npm install` fails until it is —\n\
             re-scaffold with `--sdk <checkout>/packages/secreq-rule` to depend on\n\
             a local copy instead."
        ),
    };
    format!(
        r#"# {name}

A **programmable secreq auto-rule**: one `decide(ctx)` function, compiled to
a sandboxed wasm module the consent daemon consults before it prompts.

```sh
npm install        # assemblyscript + as-pect + the secreq-rule SDK
npm test           # as-pect, against assembly/__tests__/
npm run build      # secreq-rule-build → rule.wasm
```

Then register the module — the daemon vets it, copies it under the secreq
root, and pins it by sha256:

```sh
secreq rules add-wasm rule.wasm --name "{name}" --secret SOME_TOKEN
```

`--secret` is the trained-secrets guard: the rule is never consulted for an
ask requesting a name outside that set. Pass one per env var the rule may
decide.

## Layout

- `assembly/rule.ts` — the rule: one exported `decide(ctx)`.
- `assembly/__tests__/rule.spec.ts` — as-pect specs. **secreq never runs
  these**; you test locally, secreq only loads the compiled module.
- `as-pect.config.js` / `as-pect.asconfig.json` — test-runner wiring.

## The SDK dependency

{sdk_note}

The full authoring guide is `docs/wasm-rules.md` in the secreq repo.
"#,
        name = opts.name,
        sdk_note = sdk_note,
    )
}

/// Starter `assembly/rule.ts` — a compiling rule that passes on
/// everything, with the decision constructors and every `ctx` field
/// written out where the author is about to need them.
const RULE_TS: &str = r#"// A programmable secreq auto-rule.
//
// You write one function — `decide(ctx)` — and secreq runs it in a wasm
// sandbox before the consent prompt. It gets no filesystem, network, clock
// or env access; `ctx` is everything it can see.
//
//     npm install        # once
//     npm test           # as-pect, against assembly/__tests__/
//     npm run build      # → rule.wasm
//     secreq rules add-wasm rule.wasm --secret SOME_TOKEN
//
// AssemblyScript is a *subset* of TypeScript: strings, arrays and plain
// loops behave as you expect; regexes, closures and most of the JavaScript
// standard library are not available.

import { RuleCtx, Decision, pass } from 'secreq-rule';

// Add the decisions you use to the import above:
//
//   approve()        release the secret without prompting
//   deny(reason)     refuse the ask; `reason` is shown to the user
//   prompt(reason)   force the prompt — no other rule may auto-approve
//   pass()           no opinion; fall through to the other rules
//
// A deny beats a prompt beats an approve, and a pass never outranks
// anything.

export function decide(ctx: RuleCtx): Decision {
  // Everything the rule can see:
  //
  //   ctx.wrap        the wrap being asked for, e.g. 'gh'
  //   ctx.joinedArgv  the wrapped command line, e.g. 'gh api /user'
  //   ctx.cwd         working directory of the requesting process
  //   ctx.secrets     names of what the ask would release, e.g. 'GITHUB_TOKEN'
  //                   (for an SSH sign, the single identity 'ssh:<key_id>')
  //   ctx.callers     caller chain, nearest first; each entry has .name,
  //                   .command and .exe — only .exe is not self-reported,
  //                   so gate on it when it matters who is really calling
  //
  // A policy reads like this:
  //
  //   if (ctx.wrap != 'gh') return pass();
  //   if (ctx.joinedArgv.startsWith('gh api --get ')) return approve();
  //   if (ctx.joinedArgv.startsWith('gh repo delete')) {
  //     return deny('repo deletes are never auto-approved');
  //   }

  return pass();
}
"#;

/// Starter as-pect spec. Exercises the stub's one behaviour, so `npm test`
/// is green on a fresh scaffold and there is a shape to copy.
const RULE_SPEC_TS: &str = r#"// as-pect specs for this rule. Run them with `npm test`.
//
// The spec is compiled to wasm and calls `decide` directly — the same
// compiler and language semantics as the deployed module, minus the ABI
// glue `secreq-rule-build` generates. secreq never runs this file: you test
// here, secreq only ever loads the compiled `rule.wasm`.

import { RuleCtx, Caller, DecisionKind } from 'secreq-rule';
import { decide } from '../rule';

function caller(name: string, command: string): Caller {
  const c = new Caller();
  c.name = name;
  c.command = command;
  return c;
}

function ctx(wrap: string, joinedArgv: string, cwd: string): RuleCtx {
  const c = new RuleCtx();
  c.wrap = wrap;
  c.joinedArgv = joinedArgv;
  c.cwd = cwd;
  c.callers = [caller('zsh', '-zsh')];
  c.secrets = ['SOME_TOKEN'];
  return c;
}

describe('rule', () => {
  it('has no opinion until the policy says otherwise', () => {
    const d = decide(ctx('gh', 'gh api /user', '/home/me/code/app'));
    expect(d.kind).toBe(DecisionKind.Pass);
  });
});
"#;

/// `assembly/tsconfig.json` — the AssemblyScript standard-library config
/// every rule package needs.
const ASSEMBLY_TSCONFIG: &str = r#"{
  "extends": "assemblyscript/std/assembly.json",
  "include": ["./**/*.ts"],
  "compilerOptions": {
    "ignoreDeprecations": "6.0"
  }
}
"#;

/// as-pect's ambient types, so `describe` / `it` / `expect` resolve in the
/// spec.
const AS_PECT_DTS: &str = "/// <reference types=\"@as-pect/assembly/types/as-pect\" />\n";

/// as-pect runner config. Matches the worked example's.
const AS_PECT_CONFIG: &str = r#"// as-pect configuration. `npm test` compiles every matching spec (plus the
// rule it imports) to wasm and runs it — see assembly/__tests__/.
// Compiler options live in as-pect.asconfig.json.
export default {
  entries: ['assembly/__tests__/**/*.spec.ts'],
  include: ['assembly/__tests__/**/*.include.ts'],
  disclude: [/node_modules/],
  async instantiate(memory, createImports, instantiate, binary) {
    return instantiate(binary, createImports({ env: { memory } }));
  },
  outputBinary: false,
};
"#;

/// as-pect's compiler options. Matches the worked example's.
const AS_PECT_ASCONFIG: &str = r#"{
  "targets": {
    "coverage": {
      "lib": ["./node_modules/@as-covers/assembly/index.ts"],
      "transform": ["@as-covers/transform", "@as-pect/transform"]
    },
    "noCoverage": {
      "transform": ["@as-pect/transform"]
    }
  },
  "options": {
    "exportMemory": true,
    "outFile": "output.wasm",
    "textFile": "output.wat",
    "bindings": "raw",
    "exportStart": "_start",
    "exportRuntime": true,
    "use": ["RTRACE=1"],
    "debug": true,
    "exportTable": true
  },
  "entries": ["./node_modules/@as-pect/assembly/assembly/index.ts"]
}
"#;

/// The build wrapper writes `.secreq-entry.<rule>.<pid>.ts` beside the
/// rule and removes it in a `finally` — a killed build leaves one behind,
/// and it is generated code that must never be committed.
const GITIGNORE: &str = "node_modules/\n.secreq-entry.*.ts\n";

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

// ── Editor preference: the reserved `editor` key in config.toml ───────────

/// The user's persisted editor pick (the `editor` id), if any. Read from
/// `config.toml`; a missing/unreadable config just yields `None`.
pub fn preferred_editor() -> Option<String> {
    let path = paths::wraps_path().ok()?;
    let config = crate::wraps::WrapsConfig::load(&path).ok()?;
    config.editor
}

/// Persist `id` as the reserved top-level `editor` key in `config.toml`,
/// preserving everything else in the file (comments, provider defs, and
/// the store/retrieve details the full serializer would drop). A missing
/// config file is created as `{ $editor: "id" }`.
pub fn save_preferred_editor(id: &str) -> Result<()> {
    // The parent is the secreq root (`paths::wraps_path`), never a
    // user-named path, so narrowing it is safe and is what
    // `ensure_private_dir` is for — unlike `commands::config::write_config`,
    // whose path can come from `--config`. Propagated rather than `.ok()`d: a
    // root secreq cannot make private is not a detail to swallow while
    // writing the wrap config into it.
    //
    // Here rather than in `save_preferred_editor_at`, which the unit tests
    // point at a tempdir: narrowing is only ever right for a path secreq
    // resolved itself, and that resolution happens on this line.
    let path = paths::wraps_path()?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        paths::ensure_private_dir(parent)
            .with_context(|| format!("create dir {}", parent.display()))?;
    }
    save_preferred_editor_at(&path, id)
}

/// Set `key` to `item`, keeping the existing key's decoration.
///
/// `Table::insert` mints a fresh key, and a comment written above an
/// assignment is stored as that key's prefix — so inserting over an existing
/// entry deletes the user's comment, which is the exact failure moving to
/// `toml_edit` was meant to end. Replacing the *item* leaves the key, and its
/// decoration, in place.
pub(crate) fn set_preserving_decor(table: &mut toml_edit::Table, key: &str, item: toml_edit::Item) {
    match table.get_mut(key) {
        Some(existing) => *existing = item,
        None => {
            table.insert(key, item);
        }
    }
}

/// Give one config entry its final shape: `{ … }` fields become their own
/// stanza, and a header left carrying nothing is dropped.
///
/// Both writers author the same file, so both call this. Without it they
/// disagreed about the same wrap — the migration wrote `[wraps.gh.env]` under
/// an empty `[wraps.gh]`, while `wrap add` re-serialized the entry and
/// collapsed the whole thing onto one inline `env = { … }` line. A file whose
/// shape depends on which command touched it last is the defect moving to
/// `toml_edit` was meant to end.
pub(crate) fn shape_config_entry(entry: &mut toml_edit::Table) {
    promote_inline_fields(entry);
    imply_empty_headers(entry);
}

/// Promote an entry's own `{ … }` fields to real tables, so a wrap's `env`
/// renders one variable per line instead of one long inline run.
///
/// **Depth one only.** A provider's `fields.service = { required = true }` is a
/// short spec that reads better inline; a header apiece would bury the file in
/// stanzas. The entry's own fields are the ones that grow.
fn promote_inline_fields(entry: &mut toml_edit::Table) {
    let keys: Vec<String> = entry.iter().map(|(key, _)| key.to_owned()).collect();
    for key in keys {
        let Some(toml_edit::Item::Value(toml_edit::Value::InlineTable(_))) = entry.get(&key) else {
            continue;
        };
        let Some(toml_edit::Item::Value(toml_edit::Value::InlineTable(inline))) =
            entry.remove(&key)
        else {
            unreachable!("just matched an inline table at {key}")
        };
        entry.insert(&key, toml_edit::Item::Table(inline.into_table()));
    }
}

/// Drop the header of any table whose entries are all sub-tables — the child's
/// own header already implies it.
///
/// **A table with nothing at all keeps its header.** A gate-only wrap has no
/// values *and* no sub-tables, so nothing else would imply it: made implicit it
/// renders as nothing and the wrap is gone on the next load.
fn imply_empty_headers(table: &mut toml_edit::Table) {
    let mut has_own_value = false;
    let mut has_child_table = false;
    for (_, item) in table.iter() {
        match item {
            toml_edit::Item::Value(_) => has_own_value = true,
            toml_edit::Item::Table(_) | toml_edit::Item::ArrayOfTables(_) => has_child_table = true,
            toml_edit::Item::None => {}
        }
    }
    table.set_implicit(!has_own_value && has_child_table);

    for (_, item) in table.iter_mut() {
        if let toml_edit::Item::Table(child) = item {
            imply_empty_headers(child);
        }
    }
}

/// The body of [`save_preferred_editor`] against an explicit path, so the
/// mode it leaves is testable without `$SECREQ_HOME` — which is process-global
/// and races across threads in the same test binary.
///
/// Same `Mode::Like` as `commands::config::write_config`, and it has to be:
/// these two write the same file, and a pair of writers that disagreed
/// about whose mode wins would make the file's permissions depend on which
/// command touched it last.
fn save_preferred_editor_at(path: &Path, id: &str) -> Result<()> {
    let existing = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            format!("#:schema {}\n", crate::wraps::CONFIG_SCHEMA_URL)
        }
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    // `toml_edit` edits the parsed document, so everything else in the file —
    // comments, provider definitions, key order — is carried through
    // untouched. This replaced a line-oriented upsert that could not see an
    // existing inline assignment and had to guard against one silently
    // winning; a document edit has no such blind spot.
    let mut doc: toml_edit::DocumentMut = existing
        .parse()
        .with_context(|| format!("{} is not valid TOML", path.display()))?;
    set_preserving_decor(doc.as_table_mut(), "editor", toml_edit::value(id));
    let updated = doc.to_string();

    // Round-trip through the parser so a malformed edit never lands.
    let parsed = crate::wraps::WrapsConfig::parse(&updated, &path.display().to_string())
        .context("internal: config with updated `editor` doesn't re-parse")?;
    if parsed.editor.as_deref() != Some(id) {
        bail!(
            "could not set `editor` in {} — edit it by hand to `editor = {id:?}`",
            path.display()
        );
    }
    crate::atomic::replace(path, updated.as_bytes(), crate::atomic::Mode::Like(path))
        .with_context(|| format!("write {}", path.display()))
}

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

    /// The scaffold's whole point is that `npm install && npm run build`
    /// works in the directory it wrote — so the manifest, the entry, the
    /// spec and the runner config all have to land, not just the rule.
    #[test]
    fn scaffold_writes_a_buildable_project() {
        let tmp = tempfile::tempdir().expect("tmp");
        let out = scaffold_rule(tmp.path(), "rule-abc123").expect("scaffold");

        assert_eq!(out.entry, out.dir.join("assembly").join("rule.ts"));
        for rel in [
            "package.json",
            "README.md",
            ".gitignore",
            "as-pect.config.js",
            "as-pect.asconfig.json",
            "assembly/rule.ts",
            "assembly/tsconfig.json",
            "assembly/__tests__/rule.spec.ts",
            "assembly/__tests__/as-pect.d.ts",
        ] {
            assert!(out.dir.join(rel).exists(), "missing {rel}");
        }
        let src = std::fs::read_to_string(&out.entry).expect("read");
        assert!(src.contains("export function decide"));
        assert!(src.contains("secreq-rule"));
    }

    /// The manifest has to parse as JSON and carry the build script the
    /// README and the printed next steps promise. A path with a quote in
    /// it is the case a naive `format!` gets wrong.
    #[test]
    fn the_manifest_is_valid_json_with_the_build_script() {
        let opts = ProjectOpts {
            name: "my-rule".to_owned(),
            sdk: SdkDep::Local(PathBuf::from("/tmp/od\"d path/packages/secreq-rule")),
            seed: None,
        };
        let pkg: serde_json::Value =
            serde_json::from_str(&package_json(&opts)).expect("valid JSON");

        assert_eq!(pkg["name"], "my-rule");
        assert_eq!(
            pkg["scripts"]["build"],
            "secreq-rule-build assembly/rule.ts -o rule.wasm"
        );
        assert_eq!(
            pkg["devDependencies"]["secreq-rule"],
            "file:/tmp/od\"d path/packages/secreq-rule"
        );
    }

    /// Without a local SDK the manifest names the registry package — the
    /// half of [`SdkDep`] that does not resolve yet, which is why the
    /// command warns about it.
    #[test]
    fn the_published_fallback_names_the_registry_package() {
        let opts = ProjectOpts {
            name: "my-rule".to_owned(),
            sdk: SdkDep::Published,
            seed: None,
        };
        let pkg: serde_json::Value =
            serde_json::from_str(&package_json(&opts)).expect("valid JSON");
        assert_eq!(pkg["devDependencies"]["secreq-rule"], SDK_VERSION_RANGE);
    }

    /// `--from` replaces `assembly/` wholesale and leaves the manifest and
    /// runner config this module owns.
    #[test]
    fn a_seed_supplies_the_assembly_tree() {
        let tmp = tempfile::tempdir().expect("tmp");
        let seed = tmp.path().join("example");
        std::fs::create_dir_all(seed.join("assembly").join("__tests__")).expect("mkdir");
        std::fs::write(seed.join("assembly/rule.ts"), "// seeded rule\n").expect("write");
        std::fs::write(
            seed.join("assembly/__tests__/rule.spec.ts"),
            "// seeded spec\n",
        )
        .expect("write");

        let dir = tmp.path().join("out");
        std::fs::create_dir(&dir).expect("mkdir");
        let out = write_project(
            &dir,
            &ProjectOpts {
                name: "seeded".to_owned(),
                sdk: SdkDep::Published,
                seed: Some(seed),
            },
        )
        .expect("scaffold");

        assert_eq!(
            std::fs::read_to_string(&out.entry).expect("read"),
            "// seeded rule\n"
        );
        assert!(out.dir.join("assembly/__tests__/rule.spec.ts").exists());
        assert!(out.dir.join("package.json").exists());
    }

    /// A seed with no `assembly/` fails before anything is written, so a
    /// mistyped `--from` cannot leave half a project on disk.
    #[test]
    fn a_seed_with_no_sources_writes_nothing() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("out");
        std::fs::create_dir(&dir).expect("mkdir");

        let out = write_project(
            &dir,
            &ProjectOpts {
                name: "seeded".to_owned(),
                sdk: SdkDep::Published,
                seed: Some(tmp.path().join("nope")),
            },
        );

        assert!(out.is_err(), "a missing seed must fail");
        assert!(std::fs::read_dir(&dir).expect("read").next().is_none());
    }

    /// Every generated file carries the mode secreq chose, not the one the
    /// umask left. Asserted exactly for the reason
    /// [`a_scaffolded_project_is_owner_only`] is: under the ambient 022 an
    /// unforced write lands 0644, which a `& 0o022 == 0` check would call
    /// clean — and under a umask that clears an owner bit it lands on a
    /// file its own owner cannot read. The second half needs a hostile
    /// umask, which is process-global and so lives in an integration test
    /// (`tests/cli.rs`); this half runs in the fast suite.
    #[test]
    fn generated_files_carry_the_mode_secreq_chose() {
        let tmp = tempfile::tempdir().expect("tmp");
        let out = scaffold_rule(tmp.path(), "rule-abc123").expect("scaffold");

        for rel in ["package.json", "assembly/rule.ts"] {
            let path = out.dir.join(rel);
            assert_eq!(mode_of(&path), 0o600, "{rel}");
            assert!(
                !std::fs::read_to_string(&path)
                    .expect("read back")
                    .is_empty(),
                "{rel} must be readable and non-empty"
            );
        }
        assert_eq!(mode_of(&out.dir.join("assembly")), 0o700);
    }

    /// npm refuses a `name` with a capital or a space in it, so an
    /// explicit `--name` gets the same folding the directory name does —
    /// a scaffold that cannot `npm install` defeats the command.
    #[test]
    fn package_names_are_folded_to_something_npm_accepts() {
        assert_eq!(package_name_from_dir(Path::new("/tmp/My Rule!")), "my-rule");
        assert_eq!(package_name_from_dir(Path::new("/tmp/.hidden")), "hidden");
        assert_eq!(package_name("npm publish guard"), "npm-publish-guard");
    }

    /// npm caps a name at 214 characters, so a long directory name folds
    /// into a long *invalid* name unless something truncates it. The
    /// re-trim matters: a cut can land right after a `-`.
    #[test]
    fn a_long_directory_name_is_capped_at_npms_limit() {
        let name = package_name(&format!("{}-tail", "a".repeat(NPM_NAME_MAX)));

        assert_eq!(name.len(), NPM_NAME_MAX);
        assert!(!name.ends_with('-'), "{name}");
    }

    /// The fallback cannot be the SDK's own name: npm refuses to install a
    /// dependency under a package called the same thing (`ENOSELF`), and
    /// every generated project depends on `secreq-rule`.
    #[test]
    fn the_fallback_name_is_not_the_sdks_own() {
        assert_eq!(package_name_from_dir(Path::new("/")), FALLBACK_PACKAGE_NAME);
        assert_ne!(FALLBACK_PACKAGE_NAME, SDK_PACKAGE_NAME);
    }

    /// A Unix filename may hold a newline or a tab, and `--sdk` puts one
    /// straight into the manifest. Unescaped, that is JSON no parser
    /// accepts — found out by npm, several steps from the cause.
    #[test]
    fn a_control_character_in_the_sdk_path_survives_as_json() {
        let path = PathBuf::from("/tmp/od\td\n\u{1}path/packages/secreq-rule");
        let opts = ProjectOpts {
            name: "my-rule".to_owned(),
            sdk: SdkDep::Local(path.clone()),
            seed: None,
        };

        let pkg: serde_json::Value =
            serde_json::from_str(&package_json(&opts)).expect("valid JSON");

        assert_eq!(
            pkg["devDependencies"]["secreq-rule"],
            format!("file:{}", path.display())
        );
    }

    /// Shape alone matched any `packages/<x>` carrying a `package.json`
    /// and a `bin/build.js`, and the ancestor walk takes the first hit —
    /// so a lookalike would be picked up silently and fail at build time.
    #[test]
    fn a_lookalike_package_is_not_taken_for_the_sdk() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("secreq-rule");
        std::fs::create_dir_all(dir.join("bin")).expect("mkdir");
        std::fs::write(dir.join("bin/build.js"), "// not it\n").expect("write");
        std::fs::write(dir.join("package.json"), r#"{"name":"some-other-sdk"}"#).expect("write");

        assert!(
            resolve_sdk_dir(&dir).is_err(),
            "a lookalike must be refused"
        );

        std::fs::write(dir.join("package.json"), r#"{"name":"secreq-rule"}"#).expect("write");
        assert!(resolve_sdk_dir(&dir).is_ok(), "the real thing must resolve");
    }

    /// The registry fallback is a literal in this file and the SDK's
    /// version is a literal in its `package.json`; nothing else holds the
    /// two together, so a version bump would otherwise leave scaffolds
    /// asking for the previous release.
    #[test]
    fn the_fallback_range_tracks_the_sdk_version() {
        let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../secreq-rule/package.json");
        let pkg: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(manifest).expect("read SDK manifest"))
                .expect("SDK manifest must be valid JSON");
        let version = pkg["version"]
            .as_str()
            .expect("SDK manifest declares a version");

        assert_eq!(
            SDK_VERSION_RANGE,
            format!("^{version}"),
            "SDK_VERSION_RANGE is stale against packages/secreq-rule/package.json"
        );
    }

    /// The project directory a user names is created owner-only for the
    /// same reason the editor's draft is: whoever can edit `rule.ts`
    /// before the build writes the policy.
    #[test]
    fn a_user_named_project_dir_is_owner_only() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("nested").join("my-rule");

        create_project_dir(&dir).expect("create");

        assert_eq!(mode_of(&dir), 0o700, "{}", dir.display());
    }

    /// …but an existing directory keeps its mode. `ensure_private_dir`
    /// would narrow it, and `secreq rules new-wasm .` must not chmod the
    /// user's working directory.
    #[test]
    fn an_existing_empty_project_dir_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("mine");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        create_project_dir(&dir).expect("create");

        assert_eq!(mode_of(&dir), 0o755);
    }

    #[test]
    fn a_non_empty_project_dir_is_refused() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("mine");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::write(dir.join("package.json"), "{}").expect("write");

        let err = create_project_dir(&dir).expect_err("must refuse");

        assert!(format!("{err:#}").contains("not empty"));
    }

    #[test]
    fn scaffold_refuses_to_clobber_existing_dir() {
        let tmp = tempfile::tempdir().expect("tmp");
        scaffold_rule(tmp.path(), "dup").expect("first");
        let err = scaffold_rule(tmp.path(), "dup").expect_err("second must fail");
        assert!(format!("{err:#}").contains("already exists"));
    }

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    /// The draft directory holds the source of a rule that will decide
    /// whether commands get a secret without asking. `create_dir_all`
    /// took the umask's answer, so on a `umask 000` box the project was
    /// 0777 and anyone could rewrite `rule.ts` between the scaffold and
    /// the build.
    ///
    /// Asserted exactly, and the ambient umask is what makes it bite:
    /// under 022 the old code gave 0755, under 000 it gave 0777, and
    /// `mode & 0o022 == 0` would have called the first of those clean.
    #[test]
    fn a_scaffolded_project_is_owner_only() {
        let tmp = tempfile::tempdir().expect("tmp");

        let out = scaffold_rule(tmp.path(), "rule-abc123").expect("scaffold");

        assert_eq!(mode_of(&out.dir), 0o700, "{}", out.dir.display());
    }

    /// A `rule-drafts/` that a previous secreq built at 0755 stays that
    /// way until something narrows it — the same lazy-narrowing gap the
    /// root had. `ensure_private_dir` creates missing parents owner-only,
    /// which is umask-independent and so is this assertion.
    #[test]
    fn scaffolding_creates_a_missing_drafts_dir_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tmp");
        // A permissive grandparent stands in for a world-writable spot;
        // the drafts dir below it must not inherit that.
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o777))
            .expect("chmod");
        let drafts = tmp.path().join("rule-drafts");

        let out = scaffold_rule(&drafts, "rule-abc123").expect("scaffold");

        assert_eq!(mode_of(&drafts), 0o700, "{}", drafts.display());
        assert_eq!(mode_of(&out.dir), 0o700, "{}", out.dir.display());
    }

    #[test]
    fn scaffold_rejects_traversal_slug() {
        let tmp = tempfile::tempdir().expect("tmp");
        assert!(scaffold_rule(tmp.path(), "../escape").is_err());
        assert!(scaffold_rule(tmp.path(), "").is_err());
    }

    /// The editor pick is written into `config.toml`, so this writer creates
    /// the same file `write_config` does — and created it at the umask for the
    /// same reason (`fs::write` only takes the umask's answer on creation).
    /// The `providers` block in that file is a set of shell commands secreq
    /// executes; picking an editor must not be the click that publishes it.
    #[test]
    fn saving_an_editor_pick_creates_an_owner_only_config() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("config.toml");

        save_preferred_editor_at(&path, "zed").expect("save");

        assert_eq!(mode_of(&path), 0o600, "{}", path.display());
        let c = crate::wraps::WrapsConfig::load(&path).expect("load");
        assert_eq!(c.editor.as_deref(), Some("zed"));
    }

    /// Same policy boundary as `write_config`: the two writers of this one
    /// file must not disagree about whose mode wins.
    #[test]
    fn saving_an_editor_pick_keeps_a_mode_the_user_chose() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("config.toml");
        save_preferred_editor_at(&path, "vim").expect("first save");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");

        save_preferred_editor_at(&path, "zed").expect("re-save");

        assert_eq!(mode_of(&path), 0o640);
    }

    #[test]
    fn saving_an_editor_pick_creates_the_key() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        save_preferred_editor_at(&path, "code").expect("save");
        let c = crate::wraps::WrapsConfig::load(&path).expect("parse");
        assert_eq!(c.editor.as_deref(), Some("code"));
    }

    #[test]
    fn saving_an_editor_pick_replaces_it_and_keeps_everything_else() {
        // The whole point of editing the document rather than rewriting it:
        // the comment and the unrelated wrap have to survive.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        std::fs::write(
            &path,
            "# keep me\neditor = \"vim\"\n\n[wraps.gh]\nreason = \"gh access\"\n",
        )
        .unwrap();

        save_preferred_editor_at(&path, "zed").expect("save");

        let out = std::fs::read_to_string(&path).unwrap();
        assert!(out.contains("# keep me"), "comment must survive: {out}");
        assert!(!out.contains("vim"));
        let c = crate::wraps::WrapsConfig::load(&path).expect("parse");
        assert_eq!(c.editor.as_deref(), Some("zed"));
        assert_eq!(
            c.wraps["gh"].reason.as_deref(),
            Some("gh access"),
            "an unrelated wrap must survive the edit"
        );
    }
}
