//! `secreq rules …` — the CLI side of the auto-rules store.
//!
//! The daemon owns the rules: this module asks it for the list, renders it,
//! and forwards the mutations. The two rendering functions are split out
//! from their commands so the wasm module-status line — the part that tells
//! an operator a rule can never fire — is unit-testable without a daemon.

use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::Path;

use anyhow::{Context, Result};

use crate::daemon::client as daemon_client;
use crate::rule_scaffold;

/// `secreq rules` (with no subcommand or with `list`): one-line table
/// of every configured rule.
pub fn rules_list() -> Result<i32> {
    let listing = daemon_client::list_rules().context("could not reach the consent daemon")?;
    let (rules, refusals) = (&listing.rules, &listing.refusals);
    if rules.is_empty() {
        println!("no auto-rules configured");
        println!("(create one from the Rules tab in `secreq view`)");
        return Ok(0);
    }
    println!(
        "{:<24}  {:<8}  {:<8}  {:<16}  {:<16}  name",
        "id", "decide", "enabled", "wrap match", "wrap scope"
    );
    for r in rules {
        println!("{}", rule_list_line(r, refusals));
    }
    Ok(0)
}

/// One `rules list` row. A rule with anything refused against it —
/// a wasm module that would not load, a match pattern that would not
/// compile — gets a trailing `[REFUSED: <what>]` marker. Without it,
/// a tampered module or a fat-fingered glob renders as a normal enabled
/// rule that mysteriously never fires.
fn rule_list_line(r: &crate::rules::Rule, refusals: &crate::rules::RuleRefusals) -> String {
    let enabled = if r.enabled { "yes" } else { "no" };
    // A wasm rule has no static decision — the module returns one
    // per ask — and no match clause to take a wrap from.
    let (decide, wrap_match) = match &r.body {
        crate::rules::RuleBody::Declarative { r#match, decide } => (
            match decide.decision() {
                crate::rules::RuleDecision::Approve => "approve",
                crate::rules::RuleDecision::Deny => "deny",
            },
            r#match.wrap.as_str(),
        ),
        crate::rules::RuleBody::Wasm(_) => ("wasm", "—"),
    };
    let wrap_scope = r.wraps.as_ref().map_or_else(
        || "(all)".to_owned(),
        |wraps| wraps.iter().cloned().collect::<Vec<_>>().join(","),
    );
    let labels: Vec<_> = refusals
        .for_rule(&r.id)
        .into_iter()
        .map(|(label, _)| label)
        .collect();
    let refused = if labels.is_empty() {
        String::new()
    } else {
        format!("  [REFUSED: {}]", labels.join(", "))
    };
    format!(
        "{:<24}  {:<8}  {:<8}  {:<16}  {:<16}  {}{}",
        r.id, decide, enabled, wrap_match, wrap_scope, r.name, refused
    )
}

/// `secreq rules show <target>` — verbose dump of one rule. `target`
/// matches by id first, then by exact name.
pub fn rules_show(target: &str) -> Result<i32> {
    let listing = daemon_client::list_rules().context("could not reach the consent daemon")?;
    let rule = find_rule(&listing.rules, target)?;
    print!("{}", rule_show_text(rule, &listing.refusals));
    Ok(0)
}

/// The full `rules show` body. Split from [`rules_show`] so the
/// rendering — in particular the wasm module-status line — is unit
/// testable without a daemon.
fn rule_show_text(rule: &crate::rules::Rule, refusals: &crate::rules::RuleRefusals) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "id:             {}", rule.id);
    let _ = writeln!(out, "name:           {}", rule.name);
    let _ = writeln!(out, "enabled:        {}", rule.enabled);
    let wrap_scope = rule.wraps.as_ref().map_or_else(
        || "(all — no consultation gate)".to_owned(),
        |wraps| wraps.iter().cloned().collect::<Vec<_>>().join(", "),
    );
    let _ = writeln!(out, "wrap scope:     {wrap_scope}");
    if let Some(refusal) = refusals
        .scopes
        .iter()
        .find(|refusal| refusal.rule_id == rule.id)
    {
        let _ = writeln!(
            out,
            "scope status:   REFUSED ({}) — this rule cannot fire as written",
            refusal.label()
        );
        let _ = writeln!(out, "refusal reason: {}", refusal.reason);
    }
    let mut deny_message = None;
    match &rule.body {
        crate::rules::RuleBody::Declarative { r#match, decide } => {
            let _ = writeln!(
                out,
                "decide:         {}",
                match decide.decision() {
                    crate::rules::RuleDecision::Approve => "approve",
                    crate::rules::RuleDecision::Deny => "deny",
                }
            );
            let _ = writeln!(out, "wrap match:     {}", r#match.wrap);
            if let Some(p) = &r#match.argv {
                let _ = writeln!(out, "argv match:     {}", p.as_str());
            }
            if let Some(p) = &r#match.ancestor {
                let _ = writeln!(out, "ancestor match: {}", p.as_str());
            }
            if let Some(p) = &r#match.cwd {
                let _ = writeln!(out, "cwd match:      {}", p.as_str());
            }
            deny_message = decide.deny_message();
        }
        crate::rules::RuleBody::Wasm(w) => {
            let _ = writeln!(out, "decide:         wasm (module decides per ask)");
            let _ = writeln!(out, "wasm module:    {}", w.path);
            let _ = writeln!(out, "wasm sha256:    {}", w.sha256);
            if let Some(declared) = &w.declared_secrets {
                let _ = writeln!(
                    out,
                    "declared:       {}",
                    declared.iter().cloned().collect::<Vec<_>>().join(", ")
                );
            }
            // Integrity as of the daemon's last rules load: a refused
            // module (sha256 mismatch, missing file, sandbox rejection)
            // can never fire, and the full reason names files and hashes
            // — never secret values.
            match refusals
                .wasm
                .iter()
                .find(|refusal| refusal.rule_id == rule.id)
            {
                Some(refusal) => {
                    let _ = writeln!(
                        out,
                        "wasm status:    REFUSED ({}) — this rule can never fire",
                        refusal.category.label()
                    );
                    let _ = writeln!(out, "refusal reason: {}", refusal.reason);
                }
                None => {
                    let _ = writeln!(out, "wasm status:    ok (module loaded and hash-verified)");
                }
            }
        }
    }
    if !rule.trained_secrets.is_empty() {
        let names: Vec<_> = rule.trained_secrets.iter().cloned().collect();
        let _ = writeln!(out, "trained on:     {}", names.join(", "));
    } else if rule.is_wasm() {
        let scope = if rule.wraps.is_some() {
            "every ask inside its wrap scope"
        } else {
            "every ask"
        };
        let _ = writeln!(
            out,
            "trained on:     (none — module is consulted for {scope})"
        );
    }
    // A refused pattern only happens on a declarative rule, and it is
    // the one thing on this dump that changes what the rule *does*
    // rather than describing it — so it is spelled out, not implied by
    // the pattern line above reading back as the operator wrote it.
    for refusal in refusals
        .patterns
        .iter()
        .filter(|refusal| refusal.rule_id == rule.id)
    {
        let key = format!("{} status:", refusal.field.as_str());
        let _ = writeln!(out, "{key:<16}REFUSED — not a valid glob");
        let _ = writeln!(out, "refusal reason: {}", refusal.reason);
    }
    if let Some(msg) = deny_message {
        let _ = writeln!(out, "deny message:   {msg}");
    }
    if rule.created_at_unix > 0 {
        let _ = writeln!(out, "created at:     {} (unix)", rule.created_at_unix);
    }
    out
}

/// `secreq rules add-wasm <file.wasm>` — register a compiled wasm rule
/// module. The daemon does the real work (vet in the sandbox, copy to
/// the canonical store, pin by sha256, persist); this side validates
/// the flags, resolves the module path to an absolute one (the
/// daemon's cwd is not ours), and renders the result.
pub fn rules_add_wasm(
    file: &Path,
    name: Option<&str>,
    secrets: &[String],
    wraps: &[String],
    all_secrets: bool,
    accept_declared: bool,
    config_path: Option<&Path>,
) -> Result<i32> {
    let module_path = file
        .canonicalize()
        .with_context(|| format!("wasm module not readable: {}", file.display()))?;
    let module_bytes = std::fs::read(&module_path)
        .with_context(|| format!("read wasm module: {}", module_path.display()))?;
    let module = crate::wasm_rules::RuleModule::from_binary(&module_bytes)
        .context("vet wasm module before registration")?;
    let declared = module
        .declared_subjects()
        .context("read module subjects declaration")?;
    let requested: BTreeSet<String> = secrets.iter().cloned().collect();
    let trained = registration_grant(declared.as_ref(), &requested, all_secrets)?;

    let resolved_config_path = super::resolve_config_path(config_path)?;
    let config = super::load_config_or_default(Some(&resolved_config_path))?;
    for wrap in wraps {
        if !crate::rules::is_known_wrap_scope(&config, wrap) {
            anyhow::bail!(
                "unknown --wrap `{wrap}` in {}: expected `run`, `read`, a name \
                 under `[wraps]`, or `ssh:<name>` backed by `[ssh.<name>]`",
                resolved_config_path.display()
            );
        }
    }
    let validation_set: BTreeSet<String> = declared
        .iter()
        .flat_map(|subjects| subjects.iter())
        .chain(trained.iter())
        .cloned()
        .collect();
    let scope_errors = crate::rules::subject_validation_errors(&config, &validation_set);
    if !scope_errors.is_empty() {
        anyhow::bail!(
            "invalid wasm rule subjects:\n  {}",
            scope_errors.join("\n  ")
        );
    }

    if secrets.is_empty() && !all_secrets {
        let declared = declared
            .as_ref()
            .context("internal: registration grant lost the module declaration")?;
        println!(
            "module declares: {}",
            declared.iter().cloned().collect::<Vec<_>>().join(", ")
        );
        if !accept_declared {
            if !std::io::stdin().is_terminal() {
                anyhow::bail!(
                    "confirmation requires a terminal; pass --accept-declared to grant \
                     the module's declared subjects non-interactively"
                );
            }
            let confirmed = cliclack::confirm("Register with these subjects?")
                .initial_value(false)
                .interact()
                .context("interactive confirmation failed")?;
            if !confirmed {
                println!("wasm rule was not registered");
                return Ok(0);
            }
        }
    }
    if all_secrets {
        let wrap_extent = if wraps.is_empty() {
            " across every wrap"
        } else {
            " inside the configured wrap scope"
        };
        eprintln!(
            "WARNING: registering with --all-secrets. This rule has no trained-secrets \
             guard: its module will be consulted for every ask{wrap_extent}, and \
             an Approve auto-approves secrets it has never seen. Prefer the module's \
             declared subjects or --secret NAME to scope it."
        );
    }
    let name = match name {
        Some(n) => n.to_owned(),
        None => module_path.file_stem().map_or_else(
            || "wasm rule".to_owned(),
            |s| s.to_string_lossy().into_owned(),
        ),
    };
    let wrap_scope = (!wraps.is_empty()).then(|| {
        wraps
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
    });
    let rule = daemon_client::add_wasm_rule(&name, &module_path, wrap_scope, trained, all_secrets)
        .context("could not register the wasm rule via the daemon")?;
    let wasm = rule
        .wasm()
        .context("daemon registered a wasm rule without a wasm reference")?;
    println!("registered wasm rule '{}' ({})", rule.name, rule.id);
    println!("module stored:  {}", wasm.path);
    println!("sha256:         {}", wasm.sha256);
    let scope = rule.wraps.as_ref().map_or_else(
        || "(all — no consultation gate)".to_owned(),
        |wraps| wraps.iter().cloned().collect::<Vec<_>>().join(", "),
    );
    println!("wrap scope:     {scope}");
    if rule.trained_secrets.is_empty() {
        let extent = if rule.wraps.is_some() {
            "every ask inside its wrap scope"
        } else {
            "every ask"
        };
        println!("trained on:     (none — module is consulted for {extent})");
    } else {
        let names: Vec<_> = rule.trained_secrets.iter().cloned().collect();
        println!("trained on:     {}", names.join(", "));
    }
    Ok(0)
}

/// Resolve the operator's flags and the module author's request into the
/// effective grant persisted as `trained_secrets`.
fn registration_grant(
    declared: Option<&BTreeSet<String>>,
    requested: &BTreeSet<String>,
    all_secrets: bool,
) -> Result<BTreeSet<String>> {
    if declared.is_some_and(BTreeSet::is_empty) {
        anyhow::bail!(
            "the module's `subjects()` declaration is empty; an empty declaration \
             is an error, never an implicit --all-secrets"
        );
    }
    if all_secrets {
        return Ok(BTreeSet::new());
    }
    if requested.is_empty() {
        return declared.cloned().with_context(|| {
            "no --secret given and the module does not export `subjects()`; \
             add a declaration, pass --secret NAME, or explicitly use --all-secrets"
        });
    }
    let Some(declared) = declared else {
        return Ok(requested.clone());
    };
    let effective: BTreeSet<String> = requested.intersection(declared).cloned().collect();
    if effective.is_empty() {
        anyhow::bail!(
            "--secret set [{}] is disjoint from the module-declared set [{}]; \
             registering it would create a rule no ask can reach",
            requested.iter().cloned().collect::<Vec<_>>().join(", "),
            declared.iter().cloned().collect::<Vec<_>>().join(", "),
        );
    }
    Ok(effective)
}

/// `secreq rules new-wasm <dir>` — scaffold a buildable wasm-rule project.
///
/// The counterpart to [`rules_add_wasm`], which only ever *registers* an
/// already-compiled module: before this command the only way to start a
/// rule was to know the worked example existed, copy it out, and then fix
/// the `file:../..` SDK dependency it copied with it.
///
/// The scaffolding itself lives in [`crate::rule_scaffold`], shared with
/// the rule editor's one-click draft. This side resolves what the user
/// named — the SDK, the `--from` example, the package name — and prints
/// the next steps.
pub fn rules_new_wasm(
    dir: &Path,
    name: Option<&str>,
    sdk: Option<&Path>,
    from: Option<&str>,
) -> Result<i32> {
    let sdk_dir = match sdk {
        Some(path) => Some(rule_scaffold::resolve_sdk_dir(path)?),
        None => rule_scaffold::locate_sdk(),
    };
    let seed = match from {
        Some(example) => Some(resolve_example(sdk_dir.as_deref(), example)?),
        None => None,
    };

    rule_scaffold::create_project_dir(dir)?;
    let dir = dir
        .canonicalize()
        .with_context(|| format!("resolve {}", dir.display()))?;
    let opts = rule_scaffold::ProjectOpts {
        name: name.map_or_else(
            || rule_scaffold::package_name_from_dir(&dir),
            rule_scaffold::package_name,
        ),
        sdk: sdk_dir.map_or(
            rule_scaffold::SdkDep::Published,
            rule_scaffold::SdkDep::Local,
        ),
        seed,
    };
    // The SDK is kept publishable (`tests/sdk_publish.rs`) but is not on
    // npm yet, so this fallback is a dependency `npm install` cannot
    // satisfy. Say so at scaffold time rather than letting the install
    // fail with a 404 the user has to interpret.
    if opts.sdk == rule_scaffold::SdkDep::Published {
        eprintln!(
            "WARNING: no secreq-rule checkout found, so package.json depends on \
             `secreq-rule@{}` from the registry — which is not published yet, and \
             `npm install` will fail on it. Re-run with --sdk <checkout>/packages/secreq-rule \
             to depend on a local copy.",
            rule_scaffold::SDK_VERSION_RANGE
        );
    }
    let scaffold = rule_scaffold::write_project(&dir, &opts)?;

    println!("scaffolded {} ({})", scaffold.dir.display(), opts.name);
    println!("  assembly/rule.ts             your decide(ctx)");
    println!("  assembly/__tests__/          as-pect specs");
    println!(
        "  package.json                 secreq-rule = {}",
        opts.sdk.spec()
    );
    println!();
    println!("next:");
    println!("  cd {}", scaffold.dir.display());
    println!("  npm install");
    println!("  npm run build");
    println!(
        "  secreq rules add-wasm rule.wasm --name \"{}\" --accept-declared",
        opts.name
    );
    Ok(0)
}

/// Resolve `--from <example>` to the SDK example directory it seeds from.
/// Rejects a name with a path in it: the value indexes
/// `<sdk>/examples/`, and joining an arbitrary path there would let it
/// seed from anywhere on disk.
fn resolve_example(sdk_dir: Option<&Path>, example: &str) -> Result<std::path::PathBuf> {
    let sdk_dir = sdk_dir.context(
        "--from seeds from the SDK's examples, and no secreq-rule checkout was found; \
         pass --sdk <checkout>/packages/secreq-rule",
    )?;
    if example.is_empty() || example.contains('/') || example.contains('\\') || example == ".." {
        anyhow::bail!("--from takes an example name, not a path: {example:?}");
    }
    let dir = sdk_dir.join("examples").join(example);
    if !dir.join("assembly").is_dir() {
        anyhow::bail!(
            "no example `{example}` under {}{}",
            sdk_dir.join("examples").display(),
            match available_examples(sdk_dir) {
                names if names.is_empty() => String::new(),
                names => format!(" — available: {}", names.join(", ")),
            }
        );
    }
    Ok(dir)
}

/// Example names under `<sdk>/examples/` that a `--from` could take.
/// Best-effort: an unreadable directory just yields nothing to suggest.
fn available_examples(sdk_dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(sdk_dir.join("examples")) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|e| e.path().join("assembly").is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// `secreq rules enable|disable <target>`. Idempotent — flipping a
/// bit that's already in the requested state succeeds silently.
pub fn rules_set_enabled(target: &str, enabled: bool) -> Result<i32> {
    let rules = daemon_client::list_rules()
        .context("could not reach the consent daemon")?
        .rules;
    let rule = find_rule(&rules, target)?;
    let id = rule.id.clone();
    daemon_client::set_rule_enabled(&id, enabled)
        .context("could not update the rule via the daemon")?;
    println!(
        "rule '{}' ({}) is now {}",
        rule.name,
        rule.id,
        if enabled { "enabled" } else { "disabled" }
    );
    Ok(0)
}

/// `secreq rules rm <target>`.
pub fn rules_rm(target: &str) -> Result<i32> {
    let rules = daemon_client::list_rules()
        .context("could not reach the consent daemon")?
        .rules;
    let rule = find_rule(&rules, target)?;
    let id = rule.id.clone();
    let name = rule.name.clone();
    daemon_client::delete_rule(&id).context("could not delete the rule via the daemon")?;
    println!("deleted rule '{name}' ({id})");
    Ok(0)
}

/// Resolve a user-supplied id-or-name to exactly one rule. Errors
/// with the candidate list on ambiguity so the user can disambiguate
/// by id.
fn find_rule<'a>(rules: &'a [crate::rules::Rule], target: &str) -> Result<&'a crate::rules::Rule> {
    if let Some(by_id) = rules.iter().find(|r| r.id == target) {
        return Ok(by_id);
    }
    let by_name: Vec<&crate::rules::Rule> = rules.iter().filter(|r| r.name == target).collect();
    match by_name.as_slice() {
        [] => anyhow::bail!("no rule with id or name `{target}`"),
        [only] => Ok(only),
        _ => {
            let ids = by_name
                .iter()
                .map(|r| r.id.clone())
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!("multiple rules named `{target}`; disambiguate by id: {ids}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── rules list/show rendering + add-wasm flag validation ─────────

    fn wasm_rule_fixture() -> crate::rules::Rule {
        crate::rules::Rule {
            id: "wasm01".to_owned(),
            name: "cursor gh reads".to_owned(),
            enabled: true,
            wraps: None,
            trained_secrets: ["GITHUB_TOKEN".to_owned()].into_iter().collect(),
            created_at_unix: 0,
            body: crate::rules::RuleBody::Wasm(crate::rules::WasmRule {
                path: "rules/wasm01.wasm".to_owned(),
                sha256: "ab".repeat(32),
                declared_secrets: None,
            }),
        }
    }

    fn scoped_wasm_rule_fixture() -> crate::rules::Rule {
        let mut rule = wasm_rule_fixture();
        rule.name = "cursor reads".to_owned();
        rule.wraps = Some(["gh".to_owned()].into_iter().collect());
        rule
    }

    fn no_refusals() -> crate::rules::RuleRefusals {
        crate::rules::RuleRefusals::default()
    }

    fn refusal_fixture() -> crate::rules::RuleRefusals {
        crate::rules::RuleRefusals {
            wasm: vec![crate::rules::WasmRefusal {
                rule_id: "wasm01".to_owned(),
                category: crate::rules::WasmRefusalCategory::Sha256Mismatch,
                reason: "sha256 mismatch for wasm rule `cursor gh reads` (id wasm01)".to_owned(),
            }],
            patterns: Vec::new(),
            scopes: Vec::new(),
        }
    }

    /// A declarative deny whose `argv` glob does not compile — the rule
    /// an operator believes covers a family of commands and which, until
    /// this was refused, covered nothing.
    fn bad_glob_rule_fixture() -> crate::rules::Rule {
        crate::rules::Rule {
            id: "decl01".to_owned(),
            name: "never touch repo secrets".to_owned(),
            enabled: true,
            wraps: None,
            trained_secrets: Default::default(),
            created_at_unix: 0,
            body: crate::rules::RuleBody::Declarative {
                r#match: crate::rules::RuleMatch {
                    wrap: "gh".to_owned(),
                    argv: Some(crate::rules::Pattern::parse(
                        "gh api /repos/*/actions/secrets*[",
                    )),
                    ancestor: None,
                    cwd: None,
                },
                decide: crate::rules::RuleDecision::Deny.into(),
            },
        }
    }

    #[test]
    fn rule_list_line_marks_a_refused_rule() {
        let rule = wasm_rule_fixture();
        // Healthy: no marker.
        let line = rule_list_line(&rule, &no_refusals());
        assert!(line.contains("cursor gh reads"), "{line}");
        assert!(!line.contains("REFUSED"), "{line}");
        // Refused: compact marker with the reason category.
        let line = rule_list_line(&rule, &refusal_fixture());
        assert!(line.contains("[REFUSED: sha256 mismatch]"), "{line}");
    }

    #[test]
    fn rule_show_text_renders_module_path_sha_and_integrity() {
        let rule = wasm_rule_fixture();
        let ok = rule_show_text(&rule, &no_refusals());
        assert!(ok.contains("wasm module:    rules/wasm01.wasm"), "{ok}");
        assert!(
            ok.contains(&format!("wasm sha256:    {}", "ab".repeat(32))),
            "{ok}"
        );
        assert!(ok.contains("wasm status:    ok"), "{ok}");

        let refused = rule_show_text(&rule, &refusal_fixture());
        assert!(
            refused.contains("wasm status:    REFUSED (sha256 mismatch)"),
            "{refused}"
        );
        // The full reason is shown, naming the rule — never a value.
        assert!(
            refused.contains("refusal reason: sha256 mismatch for wasm rule"),
            "{refused}"
        );
    }

    #[test]
    fn rule_list_and_show_surface_the_consult_wrap_scope() {
        let rule = scoped_wasm_rule_fixture();
        let line = rule_list_line(&rule, &no_refusals());
        assert!(line.contains("gh"), "{line}");

        let shown = rule_show_text(&rule, &no_refusals());
        assert!(shown.contains("wrap scope:     gh"), "{shown}");
    }

    #[test]
    fn rule_list_and_show_badge_an_unknown_wrap_scope() {
        let rule = scoped_wasm_rule_fixture();
        let refusals = crate::rules::RuleRefusals {
            scopes: vec![crate::rules::WrapScopeRefusal {
                rule_id: rule.id.clone(),
                category: crate::rules::WrapScopeRefusalCategory::Unknown,
                reason: "unknown wrap scope: gih".to_owned(),
            }],
            ..crate::rules::RuleRefusals::default()
        };

        let line = rule_list_line(&rule, &refusals);
        assert!(line.contains("[REFUSED: unknown wrap scope]"), "{line}");
        let shown = rule_show_text(&rule, &refusals);
        assert!(
            shown.contains("scope status:   REFUSED (unknown wrap scope)"),
            "{shown}"
        );
        assert!(shown.contains("unknown wrap scope: gih"), "{shown}");
    }

    #[test]
    fn rule_show_text_calls_out_an_unscoped_wasm_rule() {
        let mut rule = wasm_rule_fixture();
        rule.trained_secrets.clear();
        let out = rule_show_text(&rule, &no_refusals());
        assert!(
            out.contains("trained on:     (none — module is consulted for every ask)"),
            "{out}"
        );
    }

    #[test]
    fn rule_list_line_marks_a_rule_whose_glob_would_not_compile() {
        let rule = bad_glob_rule_fixture();
        let refusals = crate::rules::RuleRefusals {
            wasm: Vec::new(),
            patterns: crate::rules::pattern_refusals(std::slice::from_ref(&rule)),
            scopes: Vec::new(),
        };
        let line = rule_list_line(&rule, &refusals);
        assert!(line.contains("[REFUSED: bad argv glob]"), "{line}");
        // And a healthy declarative rule is not marked.
        assert!(
            !rule_list_line(&rule, &no_refusals()).contains("REFUSED"),
            "an unrefused rule carries no marker"
        );
    }

    #[test]
    fn rule_show_text_spells_out_a_refused_pattern_and_what_it_costs() {
        let rule = bad_glob_rule_fixture();
        let refusals = crate::rules::RuleRefusals {
            wasm: Vec::new(),
            patterns: crate::rules::pattern_refusals(std::slice::from_ref(&rule)),
            scopes: Vec::new(),
        };
        let out = rule_show_text(&rule, &refusals);
        // The pattern still reads back exactly as it was written…
        assert!(
            out.contains("argv match:     gh api /repos/*/actions/secrets*["),
            "{out}"
        );
        // …so the status line is the only thing that says it is dead.
        assert!(out.contains("argv status:    REFUSED"), "{out}");
        assert!(
            out.contains("goes to the consent prompt"),
            "a refused deny says where its asks go now: {out}"
        );
    }

    #[test]
    fn registration_rejects_an_empty_declaration() {
        let declared = BTreeSet::new();
        let requested = ["GITHUB_TOKEN".to_owned()].into_iter().collect();
        let err = format!(
            "{:#}",
            registration_grant(Some(&declared), &requested, false).expect_err("must refuse")
        );
        assert!(err.contains("declaration is empty"), "{err}");
    }

    #[test]
    fn registration_intersects_explicit_and_declared_subjects() {
        let declared = ["GITHUB_TOKEN".to_owned(), "NPM_TOKEN".to_owned()]
            .into_iter()
            .collect();
        let requested = ["AWS_TOKEN".to_owned(), "GITHUB_TOKEN".to_owned()]
            .into_iter()
            .collect();
        assert_eq!(
            registration_grant(Some(&declared), &requested, false).unwrap(),
            ["GITHUB_TOKEN".to_owned()].into_iter().collect()
        );
    }

    #[test]
    fn registration_uses_the_declaration_when_no_explicit_scope_was_given() {
        let declared = ["GITHUB_TOKEN".to_owned()].into_iter().collect();
        assert_eq!(
            registration_grant(Some(&declared), &BTreeSet::new(), false).unwrap(),
            declared
        );
    }

    #[test]
    fn registration_rejects_disjoint_subjects_and_names_both_sets() {
        let declared = ["GITHUB_TOKEN".to_owned()].into_iter().collect();
        let requested = ["AWS_TOKEN".to_owned()].into_iter().collect();
        let err = format!(
            "{:#}",
            registration_grant(Some(&declared), &requested, false).expect_err("must refuse")
        );
        assert!(err.contains("disjoint"), "{err}");
        assert!(err.contains("AWS_TOKEN"), "{err}");
        assert!(err.contains("GITHUB_TOKEN"), "{err}");
    }

    #[test]
    fn rules_add_wasm_rejects_an_unknown_wrap_before_reading_the_module() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            r#"
                [wraps.gh]
                reason = "GitHub"
            "#,
        )
        .expect("write config");

        let err = format!(
            "{:#}",
            rules_add_wasm(
                Path::new("/nonexistent/rule.wasm"),
                None,
                &["GITHUB_TOKEN".to_owned()],
                &["gih".to_owned()],
                false,
                false,
                Some(&config),
            )
            .expect_err("unknown wrap must fail")
        );
        assert!(err.contains("unknown --wrap `gih`"), "{err}");
        assert!(err.contains("[wraps]"), "{err}");
        assert!(err.contains("[ssh.<name>]"), "{err}");
        assert!(
            !err.contains("wasm module not readable"),
            "scope validation must happen before module work: {err}"
        );
    }

    #[test]
    fn rules_add_wasm_accepts_every_wrap_identity_the_evaluator_can_receive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            r#"
                [wraps.gh]
                reason = "GitHub"

                [ssh.github]
                public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1 me@mac"
                private_key = "secret://op/Private/gh/private key"
            "#,
        )
        .expect("write config");

        for wrap in ["gh", "run", "read", "ssh:github"] {
            let err = format!(
                "{:#}",
                rules_add_wasm(
                    Path::new("/nonexistent/rule.wasm"),
                    None,
                    &["GITHUB_TOKEN".to_owned()],
                    &[wrap.to_owned()],
                    false,
                    false,
                    Some(&config),
                )
                .expect_err("the valid scope must reach module validation")
            );
            assert!(
                err.contains("wasm module not readable"),
                "`{wrap}` is a real EvalCtx.wrap value and must pass scope validation: {err}"
            );
            assert!(!err.contains("unknown --wrap"), "{wrap}: {err}");
        }
    }

    #[test]
    fn rules_add_wasm_missing_config_reports_an_unknown_wrap_not_an_io_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing_config = dir.path().join("missing-config.toml");
        let err = format!(
            "{:#}",
            rules_add_wasm(
                Path::new("/nonexistent/rule.wasm"),
                None,
                &["GITHUB_TOKEN".to_owned()],
                &["gh".to_owned()],
                false,
                false,
                Some(&missing_config),
            )
            .expect_err("an unconfigured wrap must fail")
        );

        assert!(err.contains("unknown --wrap `gh`"), "{err}");
        assert!(
            !err.contains("No such file or directory"),
            "a missing config is the empty config, not an I/O failure: {err}"
        );
    }
}
