//! Cross-check configured auto-rule scopes against subjects real asks declare.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::rules::{Rule, RuleBody, RuleDecision};
use crate::wraps::WrapsConfig;

/// Whether a scope finding makes the live ruleset invalid or is a risky but
/// explicit configuration worth surfacing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeSeverity {
    Error,
    Warning,
}

/// Stable machine-readable category for one scope finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeFindingCode {
    UnknownSubject,
    NamedSecretIsNotSubject,
    UnknownSshIdentity,
    UnscopedApprover,
    NeverConsulted,
}

/// One rule/config mismatch. Messages name only configured subject names,
/// never references or resolved values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopeFinding {
    pub severity: ScopeSeverity,
    pub code: ScopeFindingCode,
    pub rule_id: String,
    pub rule_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub message: String,
}

#[derive(Default)]
struct SubjectUniverse {
    /// Ask subject -> wraps capable of declaring it.
    reaches: BTreeMap<String, BTreeSet<String>>,
    /// Named secret declaration -> env keys that actually bind it.
    named_bindings: BTreeMap<String, BTreeSet<String>>,
}

impl SubjectUniverse {
    fn from_config(config: &WrapsConfig) -> SubjectUniverse {
        let mut out = SubjectUniverse::default();
        for (wrap_name, wrap) in &config.wraps {
            if wrap.env.is_empty() {
                out.reaches
                    .entry(format!("wrap:{wrap_name}"))
                    .or_default()
                    .insert(wrap_name.clone());
                continue;
            }
            for (env_name, raw) in &wrap.env {
                out.reaches
                    .entry(env_name.clone())
                    .or_default()
                    .insert(wrap_name.clone());
                if let Ok(resolved) = config.resolve_ref(raw) {
                    if let Some(name) = resolved.declared_as {
                        out.named_bindings
                            .entry(name)
                            .or_default()
                            .insert(env_name.clone());
                    }
                }
            }
        }
        for key_id in config.ssh.keys() {
            let subject = format!("ssh:{key_id}");
            out.reaches
                .entry(subject.clone())
                .or_default()
                .insert(subject);
        }
        out
    }
}

/// Validate every rule against the subjects the current config can put into
/// the production evaluator: wrap env keys, `ssh:<key_id>`, and
/// `wrap:<name>` for gate-only wraps.
pub fn validate_rule_scopes(config: &WrapsConfig, rules: &[Rule]) -> Vec<ScopeFinding> {
    let universe = SubjectUniverse::from_config(config);
    let candidates: Vec<&str> = universe.reaches.keys().map(String::as_str).collect();
    let mut findings = Vec::new();

    for rule in rules {
        if rule.trained_secrets.is_empty() {
            if rule_can_approve(rule) {
                findings.push(finding(
                    rule,
                    ScopeSeverity::Warning,
                    ScopeFindingCode::UnscopedApprover,
                    None,
                    format!(
                        "rule `{}` has no trained subjects; an approve can apply to every ask",
                        rule.name
                    ),
                ));
            }
            continue;
        }

        let mut reachable_wraps = BTreeSet::new();
        let mut invalid = false;
        for subject in &rule.trained_secrets {
            if let Some(wraps) = universe.reaches.get(subject) {
                reachable_wraps.extend(wraps.iter().cloned());
                continue;
            }
            invalid = true;
            if config.secrets.contains_key(subject) {
                let bindings = universe.named_bindings.get(subject);
                let message = match bindings {
                    Some(bindings) if !bindings.is_empty() => format!(
                        "`{subject}` is a named secret declaration, but asks declare env keys; use {}",
                        quoted(bindings)
                    ),
                    _ => format!(
                        "`{subject}` is a named secret declaration that no wrap binds to an env key; no ask can declare it"
                    ),
                };
                findings.push(finding(
                    rule,
                    ScopeSeverity::Error,
                    ScopeFindingCode::NamedSecretIsNotSubject,
                    Some(subject.clone()),
                    message,
                ));
                continue;
            }

            let suggestion = closest(subject, &candidates)
                .map(|candidate| format!("; did you mean `{candidate}`?"))
                .unwrap_or_default();
            let (code, message) = if subject.starts_with("ssh:") {
                (
                    ScopeFindingCode::UnknownSshIdentity,
                    format!("`{subject}` names no configured SSH identity{suggestion}"),
                )
            } else {
                (
                    ScopeFindingCode::UnknownSubject,
                    format!(
                        "`{subject}` matches no wrap env key, SSH identity, or gate-only wrap{suggestion}"
                    ),
                )
            };
            findings.push(finding(
                rule,
                ScopeSeverity::Error,
                code,
                Some(subject.clone()),
                message,
            ));
        }

        if !invalid {
            if let RuleBody::Declarative { r#match, decide } = &rule.body {
                // Declarative denies are whole-ask vetoes and deliberately
                // ignore the trained-subject snapshot. A mismatched snapshot
                // can make an approval dead, but never makes a deny
                // unconsultable.
                if decide.decision() == RuleDecision::Deny {
                    continue;
                }
                if !reachable_wraps.contains(&r#match.wrap) {
                    let actual = if reachable_wraps.is_empty() {
                        "no configured wrap".to_owned()
                    } else {
                        reachable_wraps
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    findings.push(finding(
                        rule,
                        ScopeSeverity::Error,
                        ScopeFindingCode::NeverConsulted,
                        None,
                        format!(
                            "rule `{}` matches wrap `{}`, but its subjects are declared by {actual}; it can never be consulted",
                            rule.name, r#match.wrap
                        ),
                    ));
                }
            }
        }
    }
    findings
}

fn rule_can_approve(rule: &Rule) -> bool {
    match &rule.body {
        RuleBody::Wasm(_) => true,
        RuleBody::Declarative { decide, .. } => decide.decision() == RuleDecision::Approve,
    }
}

fn finding(
    rule: &Rule,
    severity: ScopeSeverity,
    code: ScopeFindingCode,
    subject: Option<String>,
    message: String,
) -> ScopeFinding {
    ScopeFinding {
        severity,
        code,
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        subject,
        message,
    }
}

fn quoted(values: &BTreeSet<String>) -> String {
    values
        .iter()
        .map(|value| format!("`{value}`"))
        .collect::<Vec<_>>()
        .join(" or ")
}

fn closest<'a>(needle: &str, candidates: &[&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .filter_map(|candidate| {
            let distance = edit_distance(
                &needle.to_ascii_lowercase(),
                &candidate.to_ascii_lowercase(),
            );
            let limit = 2_usize.max(candidate.chars().count() / 3);
            (distance <= limit).then_some((*candidate, distance))
        })
        .min_by(|(left_name, left_distance), (right_name, right_distance)| {
            left_distance
                .cmp(right_distance)
                .then_with(|| left_name.cmp(right_name))
        })
        .map(|(candidate, _)| candidate)
}

fn edit_distance(left: &str, right: &str) -> usize {
    let mut previous: Vec<usize> = (0..=right.chars().count()).collect();
    for (left_index, left_char) in left.chars().enumerate() {
        let mut current = Vec::with_capacity(previous.len());
        current.push(left_index + 1);
        for (right_index, right_char) in right.chars().enumerate() {
            let insertion = current
                .get(right_index)
                .copied()
                .expect("the row starts with one element and grows once per character")
                + 1;
            let deletion = previous
                .get(right_index + 1)
                .copied()
                .expect("the previous row has one element per right character plus its origin")
                + 1;
            let substitution = previous
                .get(right_index)
                .copied()
                .expect("the previous row includes the preceding right character")
                + usize::from(left_char != right_char);
            current.push(insertion.min(deletion).min(substitution));
        }
        previous = current;
    }
    previous.last().copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::rules::{Rule, RuleBody, RuleDecision, RuleMatch, StaticDecision};
    use crate::wraps::WrapsConfig;

    use super::{validate_rule_scopes, ScopeFindingCode, ScopeSeverity};

    fn approve(id: &str, wrap: &str, subjects: &[&str]) -> Rule {
        Rule {
            id: id.to_owned(),
            name: id.to_owned(),
            enabled: true,
            trained_secrets: subjects
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<BTreeSet<_>>(),
            created_at_unix: 1,
            body: RuleBody::Declarative {
                r#match: RuleMatch {
                    wrap: wrap.to_owned(),
                    argv: None,
                    ancestor: None,
                    cwd: None,
                },
                decide: StaticDecision::from(RuleDecision::Approve),
            },
        }
    }

    fn config() -> WrapsConfig {
        WrapsConfig::parse(
            r#"
                [secrets.github_token]
                ref = "secret://op/GitHub/token"

                [wraps.gh.env]
                GITHUB_TOKEN = "secret://github_token"

                [wraps.npm.env]
                NPM_TOKEN = "secret://op/npm/token"

                [wraps.op]

                [ssh.deploy]
                public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2v7v98VSZ3zAZ7Qyn3YrVPaPyAwzp4RmaXxNQQZbwu"
                private_key = "secret://op/SSH/private key"
            "#,
            "fixture",
        )
        .expect("valid config")
    }

    #[test]
    fn reports_unknown_named_ssh_and_unscoped_subjects_with_targeted_help() {
        let rules = [
            approve("typo", "gh", &["GITHUB_TOKN"]),
            approve("named", "gh", &["github_token"]),
            approve("ssh", "ssh:deploy", &["ssh:deply"]),
            approve("unscoped", "npm", &[]),
        ];

        let findings = validate_rule_scopes(&config(), &rules);

        assert!(findings.iter().any(|f| {
            f.code == ScopeFindingCode::UnknownSubject
                && f.message.contains("GITHUB_TOKEN")
                && f.severity == ScopeSeverity::Error
        }));
        assert!(findings.iter().any(|f| {
            f.code == ScopeFindingCode::NamedSecretIsNotSubject
                && f.message.contains("github_token")
                && f.message.contains("GITHUB_TOKEN")
        }));
        assert!(findings.iter().any(|f| {
            f.code == ScopeFindingCode::UnknownSshIdentity && f.message.contains("ssh:deploy")
        }));
        assert!(findings.iter().any(|f| {
            f.code == ScopeFindingCode::UnscopedApprover
                && f.rule_id == "unscoped"
                && f.severity == ScopeSeverity::Warning
        }));
    }

    #[test]
    fn reports_a_rule_whose_valid_subject_can_never_reach_its_wrap() {
        let rule = approve("impossible", "npm", &["GITHUB_TOKEN"]);
        let findings = validate_rule_scopes(&config(), &[rule]);

        assert!(findings.iter().any(|f| {
            f.code == ScopeFindingCode::NeverConsulted
                && f.severity == ScopeSeverity::Error
                && f.message.contains("npm")
                && f.message.contains("gh")
        }));
    }

    #[test]
    fn deny_scope_does_not_claim_the_rule_is_unconsultable() {
        let mut rule = approve("deny", "npm", &["GITHUB_TOKEN"]);
        rule.body = RuleBody::Declarative {
            r#match: RuleMatch {
                wrap: "npm".to_owned(),
                argv: None,
                ancestor: None,
                cwd: None,
            },
            decide: StaticDecision::from(RuleDecision::Deny),
        };

        let findings = validate_rule_scopes(&config(), &[rule]);

        assert!(!findings
            .iter()
            .any(|finding| finding.code == ScopeFindingCode::NeverConsulted));
    }
}
