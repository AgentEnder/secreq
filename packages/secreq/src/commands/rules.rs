//! `secreq rules …` — the CLI side of the auto-rules store.
//!
//! The daemon owns the rules: this module asks it for the list, renders it,
//! and forwards the mutations. The two rendering functions are split out
//! from their commands so the wasm module-status line — the part that tells
//! an operator a rule can never fire — is unit-testable without a daemon.

use std::path::Path;

use anyhow::{Context, Result};

use crate::daemon::client as daemon_client;

/// `secreq rules` (with no subcommand or with `list`): one-line table
/// of every configured rule.
pub fn rules_list() -> Result<i32> {
    let (rules, refusals) =
        daemon_client::list_rules().context("could not reach the consent daemon")?;
    if rules.is_empty() {
        println!("no auto-rules configured");
        println!("(create one from the Rules tab in `secreq view`)");
        return Ok(0);
    }
    println!(
        "{:<24}  {:<8}  {:<8}  {:<16}  name",
        "id", "decide", "enabled", "wrap"
    );
    for r in &rules {
        println!("{}", rule_list_line(r, &refusals));
    }
    Ok(0)
}

/// One `rules list` row. A wasm rule refused at the daemon's last
/// rules load gets a trailing `[REFUSED: <category>]` marker — without
/// it, a tampered or missing module renders as a normal enabled rule
/// that mysteriously never fires.
fn rule_list_line(r: &crate::rules::Rule, refusals: &[crate::rules::WasmRefusal]) -> String {
    let enabled = if r.enabled { "yes" } else { "no" };
    // A wasm rule has no static decision — the module returns one
    // per ask — and no match clause to take a wrap from.
    let (decide, wrap) = match &r.body {
        crate::rules::RuleBody::Declarative {
            r#match, decide, ..
        } => (
            match decide {
                crate::rules::RuleDecision::Approve => "approve",
                crate::rules::RuleDecision::Deny => "deny",
            },
            r#match.wrap.as_str(),
        ),
        crate::rules::RuleBody::Wasm(_) => ("wasm", "(wasm)"),
    };
    let refused = refusals
        .iter()
        .find(|refusal| refusal.rule_id == r.id)
        .map_or(String::new(), |refusal| {
            format!("  [REFUSED: {}]", refusal.category.label())
        });
    format!(
        "{:<24}  {:<8}  {:<8}  {:<16}  {}{}",
        r.id, decide, enabled, wrap, r.name, refused
    )
}

/// `secreq rules show <target>` — verbose dump of one rule. `target`
/// matches by id first, then by exact name.
pub fn rules_show(target: &str) -> Result<i32> {
    let (rules, refusals) =
        daemon_client::list_rules().context("could not reach the consent daemon")?;
    let rule = find_rule(&rules, target)?;
    print!("{}", rule_show_text(rule, &refusals));
    Ok(0)
}

/// The full `rules show` body. Split from [`rules_show`] so the
/// rendering — in particular the wasm module-status line — is unit
/// testable without a daemon.
fn rule_show_text(rule: &crate::rules::Rule, refusals: &[crate::rules::WasmRefusal]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "id:             {}", rule.id);
    let _ = writeln!(out, "name:           {}", rule.name);
    let _ = writeln!(out, "enabled:        {}", rule.enabled);
    let mut deny_message = None;
    match &rule.body {
        crate::rules::RuleBody::Declarative {
            r#match,
            decide,
            deny_message: msg,
        } => {
            let _ = writeln!(
                out,
                "decide:         {}",
                match decide {
                    crate::rules::RuleDecision::Approve => "approve",
                    crate::rules::RuleDecision::Deny => "deny",
                }
            );
            let _ = writeln!(out, "wrap:           {}", r#match.wrap);
            if let Some(p) = &r#match.argv {
                let _ = writeln!(out, "argv match:     {}", p.as_str());
            }
            if let Some(p) = &r#match.ancestor {
                let _ = writeln!(out, "ancestor match: {}", p.as_str());
            }
            if let Some(p) = &r#match.cwd {
                let _ = writeln!(out, "cwd match:      {}", p.as_str());
            }
            deny_message = msg.as_deref();
        }
        crate::rules::RuleBody::Wasm(w) => {
            let _ = writeln!(out, "decide:         wasm (module decides per ask)");
            let _ = writeln!(out, "wasm module:    {}", w.path);
            let _ = writeln!(out, "wasm sha256:    {}", w.sha256);
            // Integrity as of the daemon's last rules load: a refused
            // module (sha256 mismatch, missing file, sandbox rejection)
            // can never fire, and the full reason names files and hashes
            // — never secret values.
            match refusals.iter().find(|refusal| refusal.rule_id == rule.id) {
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
        let _ = writeln!(
            out,
            "trained on:     (none — module is consulted for every ask)"
        );
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
    all_secrets: bool,
) -> Result<i32> {
    // Finding B: an empty trained-secrets snapshot disables the
    // trained-secrets guard entirely — refuse unless explicitly opted
    // in, before anything touches the daemon.
    if secrets.is_empty() && !all_secrets {
        anyhow::bail!(
            "no --secret given: a wasm rule with an empty trained-secrets snapshot \
             is consulted for EVERY ask across EVERY wrap, and an Approve from it \
             auto-approves secrets it was never trained on.\n\
             Pass --secret NAME for each env var the rule may decide (repeatable), \
             or --all-secrets to accept that blast radius explicitly."
        );
    }
    if all_secrets {
        eprintln!(
            "WARNING: registering with --all-secrets. This rule has no trained-secrets \
             guard: its module will be consulted for every ask across every wrap, and \
             an Approve auto-approves secrets it has never seen. Prefer --secret NAME \
             to scope it."
        );
    }
    let module_path = file
        .canonicalize()
        .with_context(|| format!("wasm module not readable: {}", file.display()))?;
    let name = match name {
        Some(n) => n.to_owned(),
        None => module_path.file_stem().map_or_else(
            || "wasm rule".to_owned(),
            |s| s.to_string_lossy().into_owned(),
        ),
    };
    let trained: std::collections::BTreeSet<String> = secrets.iter().cloned().collect();
    let rule = daemon_client::add_wasm_rule(&name, &module_path, trained, all_secrets)
        .context("could not register the wasm rule via the daemon")?;
    let wasm = rule
        .wasm()
        .context("daemon registered a wasm rule without a wasm reference")?;
    println!("registered wasm rule '{}' ({})", rule.name, rule.id);
    println!("module stored:  {}", wasm.path);
    println!("sha256:         {}", wasm.sha256);
    if rule.trained_secrets.is_empty() {
        println!("trained on:     (none — module is consulted for every ask)");
    } else {
        let names: Vec<_> = rule.trained_secrets.iter().cloned().collect();
        println!("trained on:     {}", names.join(", "));
    }
    Ok(0)
}

/// `secreq rules enable|disable <target>`. Idempotent — flipping a
/// bit that's already in the requested state succeeds silently.
pub fn rules_set_enabled(target: &str, enabled: bool) -> Result<i32> {
    let (rules, _) = daemon_client::list_rules().context("could not reach the consent daemon")?;
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
    let (rules, _) = daemon_client::list_rules().context("could not reach the consent daemon")?;
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
    match by_name.len() {
        0 => anyhow::bail!("no rule with id or name `{target}`"),
        1 => Ok(by_name[0]),
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
            trained_secrets: ["GITHUB_TOKEN".to_owned()].into_iter().collect(),
            created_at_unix: 0,
            body: crate::rules::RuleBody::Wasm(crate::rules::WasmRule {
                path: "rules/wasm01.wasm".to_owned(),
                sha256: "ab".repeat(32),
            }),
        }
    }

    fn refusal_fixture() -> crate::rules::WasmRefusal {
        crate::rules::WasmRefusal {
            rule_id: "wasm01".to_owned(),
            category: crate::rules::WasmRefusalCategory::Sha256Mismatch,
            reason: "sha256 mismatch for wasm rule `cursor gh reads` (id wasm01)".to_owned(),
        }
    }

    #[test]
    fn rule_list_line_marks_a_refused_rule() {
        let rule = wasm_rule_fixture();
        // Healthy: no marker.
        let line = rule_list_line(&rule, &[]);
        assert!(line.contains("cursor gh reads"), "{line}");
        assert!(!line.contains("REFUSED"), "{line}");
        // Refused: compact marker with the reason category.
        let line = rule_list_line(&rule, &[refusal_fixture()]);
        assert!(line.contains("[REFUSED: sha256 mismatch]"), "{line}");
    }

    #[test]
    fn rule_show_text_renders_module_path_sha_and_integrity() {
        let rule = wasm_rule_fixture();
        let ok = rule_show_text(&rule, &[]);
        assert!(ok.contains("wasm module:    rules/wasm01.wasm"), "{ok}");
        assert!(
            ok.contains(&format!("wasm sha256:    {}", "ab".repeat(32))),
            "{ok}"
        );
        assert!(ok.contains("wasm status:    ok"), "{ok}");

        let refused = rule_show_text(&rule, &[refusal_fixture()]);
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
    fn rule_show_text_calls_out_an_unscoped_wasm_rule() {
        let mut rule = wasm_rule_fixture();
        rule.trained_secrets.clear();
        let out = rule_show_text(&rule, &[]);
        assert!(
            out.contains("trained on:     (none — module is consulted for every ask)"),
            "{out}"
        );
    }

    #[test]
    fn rules_add_wasm_refuses_an_empty_snapshot_without_opt_in() {
        // Finding B, CLI side: no --secret and no --all-secrets must
        // fail with the blast-radius explanation *before* touching the
        // file or the daemon (the path here doesn't even exist).
        let err = format!(
            "{:#}",
            rules_add_wasm(Path::new("/nonexistent/rule.wasm"), None, &[], false)
                .expect_err("must refuse")
        );
        assert!(err.contains("--secret"), "{err}");
        assert!(err.contains("--all-secrets"), "{err}");
    }

    #[test]
    fn rules_add_wasm_with_opt_in_proceeds_to_the_module_file() {
        // With --all-secrets the snapshot guard passes and the next
        // failure is the unreadable module — proving the opt-in path
        // is reachable without a daemon in this test.
        let err = format!(
            "{:#}",
            rules_add_wasm(Path::new("/nonexistent/rule.wasm"), None, &[], true)
                .expect_err("must fail on the missing file")
        );
        assert!(err.contains("not readable"), "{err}");
    }
}
