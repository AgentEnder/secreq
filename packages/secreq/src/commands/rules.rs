//! `secreq rules …` — the CLI side of the auto-rules store.
//!
//! The daemon owns the rules: this module asks it for the list, renders it,
//! and forwards the mutations. The two rendering functions are split out
//! from their commands so the wasm module-status line — the part that tells
//! an operator a rule can never fire — is unit-testable without a daemon.

use std::path::Path;

use anyhow::{Context, Result};

use crate::daemon::client as daemon_client;
use crate::rule_scaffold;

/// `secreq rules stats` — load the current config/rules through production
/// parsers and replay historical asks without touching the daemon, providers,
/// consent cache, or secret resolution.
#[allow(clippy::too_many_arguments)]
pub fn rules_stats(
    config_path: Option<&Path>,
    since: Option<&str>,
    wrap: Option<&str>,
    top: usize,
    audit_path: Option<&Path>,
    json: bool,
    verify: bool,
) -> Result<i32> {
    let config_path = match config_path {
        Some(path) => path.to_path_buf(),
        None => crate::paths::wraps_path()?,
    };
    let config = crate::wraps::WrapsConfig::load(&config_path).with_context(|| {
        format!(
            "load current config for rule validation: {}",
            config_path.display()
        )
    })?;
    let rules_path = crate::paths::rules_path()?;
    let loaded = crate::rules::load_rules(&rules_path)?;
    let scope_findings = crate::rule_health::validate_rule_scopes(&config, &loaded.rules);
    let audit_path = audit_path
        .map(Path::to_path_buf)
        .map_or_else(crate::paths::audit_log_path, Ok)?;
    let options = crate::rule_stats::ReplayOptions {
        since_unix: since.map(parse_since).transpose()?,
        wrap: wrap.map(str::to_owned),
        top,
        verify,
    };
    let report = crate::rule_stats::replay_audit(&audit_path, &loaded, scope_findings, &options)?;
    let failed = verify
        && (!report.verification.failures.is_empty()
            || !report.health.refusals.wasm.is_empty()
            || !report.health.refusals.patterns.is_empty()
            || report
                .health
                .scope_findings
                .iter()
                .any(|finding| finding.severity == crate::rule_health::ScopeSeverity::Error)
            || report.rows.malformed > 0);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_stats_report(&report, &rules_path);
    }
    Ok(i32::from(failed))
}

fn print_stats_report(report: &crate::rule_stats::StatsReport, rules_path: &Path) {
    println!(
        "ruleset: {} rule(s) from {}",
        report.health.loaded_rules,
        rules_path.display()
    );
    println!(
        "rows replayed: {} ({} filtered, {} scoped-agent, {} malformed)",
        report.rows.replayed, report.rows.filtered, report.rows.scoped_agent, report.rows.malformed
    );
    println!("\nsimulated outcome");
    println!(
        "  auto-approve : {} ({:.2}%)",
        report.outcomes.auto_approve.count, report.outcomes.auto_approve.percent
    );
    println!(
        "  auto-deny    : {} ({:.2}%)",
        report.outcomes.auto_deny.count, report.outcomes.auto_deny.percent
    );
    println!(
        "  prompt       : {} ({:.2}%; {} mandated, {} uncovered)",
        report.outcomes.prompt.count,
        report.outcomes.prompt.percent,
        report.outcomes.prompt.mandated,
        report.outcomes.prompt.uncovered
    );
    println!("\nby rule");
    for item in &report.attribution {
        println!(
            "  {:>7} asks  {:<7} {} ({}) [{} subject approval(s)]",
            item.asks, item.decision, item.rule_name, item.rule_id, item.approved_subjects
        );
    }
    println!("\nprompts by shape (top {})", report.filters.top);
    for item in &report.prompt_shapes {
        println!("  {:>7}  {}", item.count, item.label);
    }
    println!("\nrecorded decisions for rows that now prompt");
    for item in &report.prompt_recorded {
        println!("  {:>7}  {:?}  {}", item.count, item.traffic, item.decision);
    }
    println!(
        "\nhistorically costly rows: {} ({} now automated, {} still prompting)",
        report.costly.total, report.costly.now_automated, report.costly.still_prompting
    );
    if !report.health.scope_findings.is_empty()
        || !report.health.refusals.wasm.is_empty()
        || !report.health.refusals.patterns.is_empty()
        || !report.runtime_failures.is_empty()
    {
        println!("\nrule health");
        for finding in &report.health.scope_findings {
            println!(
                "  {:?} {} ({}): {}",
                finding.severity, finding.rule_name, finding.rule_id, finding.message
            );
        }
        for refusal in &report.health.refusals.wasm {
            println!("  ERROR {}: {}", refusal.rule_id, refusal.reason);
        }
        for refusal in &report.health.refusals.patterns {
            println!("  ERROR {}: {}", refusal.rule_id, refusal.reason);
        }
        for failure in &report.runtime_failures {
            println!(
                "  ERROR {} ({}): runtime evaluation failed for {} replayed row(s)",
                failure.rule_name, failure.rule_id, failure.count
            );
        }
    }
    if report.verification.enabled {
        println!("\nverification");
        println!(
            "  eligible: {}  agree: {}  disagreements: {}",
            report.verification.eligible,
            report.verification.agree,
            report.verification.failures.len()
        );
        println!(
            "  classified: {} deleted/replaced, {} pre-creation, {} scoped-agent, {} missing rule id",
            report.verification.deleted_rule,
            report.verification.pre_creation,
            report.verification.scoped_agent,
            report.verification.missing_rule_id
        );
        for failure in &report.verification.failures {
            println!(
                "  MISMATCH ts={} wrap={} argv={:?} subjects={:?}\n    recorded: {}\n    replayed: {}",
                failure.timestamp,
                failure.wrap,
                failure.joined_argv,
                failure.subjects,
                failure.recorded,
                failure.replayed
            );
        }
    }
}

fn parse_since(raw: &str) -> Result<u64> {
    if !raw.contains('-') {
        return raw.parse::<u64>().with_context(|| {
            format!("invalid --since value `{raw}` (expected YYYY-MM-DD or Unix timestamp)")
        });
    }
    let mut parts = raw.split('-');
    let year = parts.next().and_then(|part| part.parse::<i64>().ok());
    let month = parts.next().and_then(|part| part.parse::<u32>().ok());
    let day = parts.next().and_then(|part| part.parse::<u32>().ok());
    if parts.next().is_some() {
        anyhow::bail!("invalid --since date `{raw}` (expected YYYY-MM-DD)");
    }
    let (Some(year), Some(month), Some(day)) = (year, month, day) else {
        anyhow::bail!("invalid --since date `{raw}` (expected YYYY-MM-DD)");
    };
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    };
    if year < 1970 || day == 0 || day > month_days {
        anyhow::bail!(
            "invalid --since date `{raw}` (expected a real UTC date at/after 1970-01-01)"
        );
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    u64::try_from(days)
        .ok()
        .and_then(|days| days.checked_mul(86_400))
        .with_context(|| format!("--since date `{raw}` is outside the supported range"))
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

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
        "{:<24}  {:<8}  {:<8}  {:<16}  name",
        "id", "decide", "enabled", "wrap"
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
    let (decide, wrap) = match &r.body {
        crate::rules::RuleBody::Declarative { r#match, decide } => (
            match decide.decision() {
                crate::rules::RuleDecision::Approve => "approve",
                crate::rules::RuleDecision::Deny => "deny",
            },
            r#match.wrap.as_str(),
        ),
        crate::rules::RuleBody::Wasm(_) => ("wasm", "(wasm)"),
    };
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
        "{:<24}  {:<8}  {:<8}  {:<16}  {}{}",
        r.id, decide, enabled, wrap, r.name, refused
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
            deny_message = decide.deny_message();
        }
        crate::rules::RuleBody::Wasm(w) => {
            let _ = writeln!(out, "decide:         wasm (module decides per ask)");
            let _ = writeln!(out, "wasm module:    {}", w.path);
            let _ = writeln!(out, "wasm sha256:    {}", w.sha256);
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
        let _ = writeln!(
            out,
            "trained on:     (none — module is consulted for every ask)"
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
        "  secreq rules add-wasm rule.wasm --name \"{}\" --secret <NAME>",
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
            trained_secrets: ["GITHUB_TOKEN".to_owned()].into_iter().collect(),
            created_at_unix: 0,
            body: crate::rules::RuleBody::Wasm(crate::rules::WasmRule {
                path: "rules/wasm01.wasm".to_owned(),
                sha256: "ab".repeat(32),
            }),
        }
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

    #[test]
    fn stats_since_accepts_unix_timestamps_and_real_utc_dates() {
        assert_eq!(parse_since("0").expect("epoch timestamp"), 0);
        assert_eq!(parse_since("1970-01-01").expect("epoch date"), 0);
        assert_eq!(parse_since("2024-02-29").expect("leap date"), 1_709_164_800);
    }

    #[test]
    fn stats_since_rejects_impossible_dates() {
        for raw in ["2023-02-29", "2024-13-01", "2024-01-32", "1969-12-31"] {
            assert!(parse_since(raw).is_err(), "accepted invalid date {raw}");
        }
    }
}
