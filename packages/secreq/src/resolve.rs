//! Union resolution (§7): the eager set ∪ ambient env refs.
//!
//! `run` resolves the union of two sources, both through the same providers:
//! 1. **Eager set** — manifest secrets that are `required:true` (filtered by
//!    `--only`). Always collected; a missing one with no `default` is a hard
//!    error *before* exec.
//! 2. **Ambient refs** — inherited env vars whose value is a `secret://` ref,
//!    resolved in place. A matching manifest entry overlays metadata/default.
//!
//! Building the request list ([`build_plan`]) is pure and testable; executing
//! it ([`resolve_all`]) runs the providers.

use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::manifest::Manifest;
use crate::provider::{self, RetrieveOutcome};
use crate::reference::Reference;
use crate::secret::SecretValue;

/// Where a request originated — affects how it reads in the consent prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Declared `required:true` in the manifest.
    Eager,
    /// Discovered as a `secret://` value in the inherited environment.
    Ambient,
}

/// One secret we intend to resolve and inject.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretRequest {
    pub name: String,
    pub provider: String,
    pub locator: String,
    pub group: Option<String>,
    pub reason: Option<String>,
    pub description: Option<String>,
    pub default: Option<String>,
    pub source: Source,
}

/// The full set of requests for one `run`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResolutionPlan {
    pub requests: Vec<SecretRequest>,
}

impl ResolutionPlan {
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }
}

/// A resolved secret ready to inject. Values are zeroized on drop.
pub struct ResolvedSecret {
    pub name: String,
    pub value: SecretValue,
}

/// Build the resolution plan from the manifest and the inherited environment.
///
/// `only` optionally restricts to a set of groups. `ambient` is the inherited
/// environment as `(name, value)` pairs. `nested` is true when running inside
/// an outer `run` (so already-injected eager secrets are skipped).
pub fn build_plan(
    manifest: &Manifest,
    only: Option<&[String]>,
    ambient: &[(String, String)],
    nested: bool,
) -> Result<ResolutionPlan> {
    let selected = select_groups(manifest, only)?;
    let mut requests: Vec<SecretRequest> = Vec::new();
    let mut seen_names: Vec<String> = Vec::new();

    // (1) Eager set: required secrets from the selected groups.
    for group_name in &selected {
        let group = &manifest.groups[group_name];
        for secret in group.secrets.values() {
            if !secret.required {
                continue;
            }
            // Nested: the outer run already injected this as a plain value.
            if nested && is_present_plain_value(ambient, &secret.name) {
                continue;
            }
            let provider = secret.provider.clone().with_context(|| {
                format!(
                    "secret `{}.{}` is required but has no provider (set `provider` or the group `$provider`)",
                    secret.group, secret.name
                )
            })?;
            seen_names.push(secret.name.clone());
            requests.push(SecretRequest {
                name: secret.name.clone(),
                provider,
                locator: secret.locator.clone(),
                group: Some(secret.group.clone()),
                reason: secret.reason.clone(),
                description: secret.description.clone(),
                default: secret.default.clone(),
                source: Source::Eager,
            });
        }
    }

    // (2) Ambient refs: env values that are `secret://` references.
    for (name, value) in ambient {
        if !Reference::looks_like_ref(value) {
            continue;
        }
        if seen_names.contains(name) {
            continue; // an eager request already covers this env var
        }
        let reference = Reference::parse(value).with_context(|| {
            format!("env var `{name}` looks like a secret reference but is malformed: `{value}`")
        })?;
        // Overlay metadata from a matching manifest declaration, if any.
        let decl = manifest.find_secret(name);
        seen_names.push(name.clone());
        requests.push(SecretRequest {
            name: name.clone(),
            provider: reference.provider,
            locator: reference.locator,
            group: decl.map(|d| d.group.clone()),
            reason: decl.and_then(|d| d.reason.clone()),
            description: decl.and_then(|d| d.description.clone()),
            default: decl.and_then(|d| d.default.clone()),
            source: Source::Ambient,
        });
    }

    Ok(ResolutionPlan { requests })
}

/// Execute every request through its provider, applying the resolution order
/// (found → default → hard error). Returns the resolved values **in plan
/// order** so the consent prompt and the injected env agree.
///
/// Behind the scenes, requests are grouped by provider so a provider with a
/// `retrieve_batch` capability resolves all of its requests in one
/// invocation — critical for `op`, where each `op read` triggers a
/// biometric prompt but `op run -- printenv` resolves any number of refs
/// after a single one. Per-secret retrieves are used when the provider has
/// no batch capability, when it has fewer than two requests (no benefit),
/// or as a fallback if batching fails.
/// Timing and counters for one [`resolve_all`] pass, returned alongside the
/// resolved secrets so a caller (the daemon) can log where a slow read spent
/// its time. Only the batch subprocesses are timed — per-secret retrieves are
/// counted but not individually clocked, since batching is the interesting
/// case for the 1Password read path.
#[derive(Clone, Copy, Debug, Default)]
pub struct ResolveStats {
    /// Summed time across all provider batch subprocesses (e.g. `op run …`).
    pub batch_subprocess: Duration,
    /// Summed time spent parsing batch subprocess output.
    pub batch_parse: Duration,
    /// Number of secrets served by a batch invocation.
    pub batched: usize,
    /// Number of secrets served by a per-secret retrieve: providers with no
    /// batch capability, groups smaller than two, a whole-batch fallback, or
    /// the salvage retry of individual `NotFound` entries.
    pub per_secret: usize,
}

pub fn resolve_all(
    manifest: &Manifest,
    plan: &ResolutionPlan,
) -> Result<(Vec<ResolvedSecret>, ResolveStats)> {
    use std::collections::BTreeMap;

    // Group requests by provider name, preserving insertion order within
    // each group. BTreeMap iteration order is deterministic, which makes
    // the per-provider invocation order deterministic too.
    let mut by_provider: BTreeMap<&str, Vec<&SecretRequest>> = BTreeMap::new();
    for req in &plan.requests {
        by_provider
            .entry(req.provider.as_str())
            .or_default()
            .push(req);
    }

    // Provider-group resolution → outcomes_by_name.
    let mut outcomes: BTreeMap<String, RetrieveOutcome> = BTreeMap::new();
    let mut stats = ResolveStats::default();
    for (provider_name, reqs) in &by_provider {
        let provider = manifest.providers.get(*provider_name).with_context(|| {
            format!(
                "secret `{}` uses unknown provider scheme `{}`",
                reqs[0].name, provider_name
            )
        })?;

        // Try batch when it pays off: ≥2 requests AND a batch capability
        // declared. A single request through batch is no faster and adds a
        // wrapper process (e.g. `op run` instead of `op read`).
        let batched = if reqs.len() >= 2 && provider.retrieve_batch.is_some() {
            let pairs: Vec<(String, String)> = reqs
                .iter()
                .map(|r| (r.name.clone(), r.locator.clone()))
                .collect();
            match provider::retrieve_batch(provider, &pairs) {
                Ok(batched) => Some(batched),
                Err(err) => {
                    // Loud-but-recoverable: tell the user we're falling back
                    // so they can debug their batch template if needed, then
                    // try per-secret retrieves.
                    eprintln!(
                        "secreq: batch retrieve via `{provider_name}` failed ({err:#}); falling back to per-secret reads"
                    );
                    None
                }
            }
        } else {
            None
        };

        if let Some((map, timing)) = batched {
            stats.batch_subprocess += timing.subprocess;
            stats.batch_parse += timing.parse;
            for (name, outcome) in map {
                outcomes.insert(name, outcome);
            }
            // If batching produced NotFound for some names (e.g. a value
            // straddled a newline and our parser lost it), retry just those
            // through per-secret retrieve. Per-secret reads on `op` will
            // prompt biometric again, but only for the secrets we couldn't
            // batch — which is the right trade.
            let salvage: Vec<&&SecretRequest> = reqs
                .iter()
                .filter(|r| matches!(outcomes.get(&r.name), Some(RetrieveOutcome::NotFound { .. })))
                .collect();
            stats.batched += reqs.len() - salvage.len();
            stats.per_secret += salvage.len();
            for req in salvage {
                let outcome = provider::retrieve(provider, &req.locator)?;
                outcomes.insert(req.name.clone(), outcome);
            }
        } else {
            stats.per_secret += reqs.len();
            for req in reqs {
                let outcome = provider::retrieve(provider, &req.locator)?;
                outcomes.insert(req.name.clone(), outcome);
            }
        }
    }

    // Assemble in plan order. Apply default / hard-error per request.
    let mut resolved = Vec::with_capacity(plan.requests.len());
    for req in &plan.requests {
        let outcome = outcomes.remove(&req.name).unwrap_or(RetrieveOutcome::NotFound {
            status: "missing from resolver output".to_owned(),
            stderr: String::new(),
        });
        match outcome {
            RetrieveOutcome::Found(value) => {
                resolved.push(ResolvedSecret {
                    name: req.name.clone(),
                    value,
                });
            }
            RetrieveOutcome::NotFound { status, stderr } => {
                if let Some(default) = &req.default {
                    resolved.push(ResolvedSecret {
                        name: req.name.clone(),
                        value: SecretValue::new(default.clone()),
                    });
                } else {
                    let detail = if stderr.is_empty() {
                        status
                    } else {
                        format!("{status}: {stderr}")
                    };
                    bail!(
                        "secret `{}` could not be resolved from `{}` ({detail}) and has no default",
                        req.name,
                        req.provider
                    );
                }
            }
        }
    }
    Ok((resolved, stats))
}

/// Resolve which groups are in scope, validating any `--only` names.
fn select_groups(manifest: &Manifest, only: Option<&[String]>) -> Result<Vec<String>> {
    match only {
        None => Ok(manifest.groups.keys().cloned().collect()),
        Some(names) => {
            let mut out = Vec::with_capacity(names.len());
            for name in names {
                if !manifest.groups.contains_key(name) {
                    let available: Vec<&str> = manifest.groups.keys().map(String::as_str).collect();
                    bail!(
                        "unknown group `{name}` in --only (available: {})",
                        if available.is_empty() {
                            "none".to_owned()
                        } else {
                            available.join(", ")
                        }
                    );
                }
                out.push(name.clone());
            }
            Ok(out)
        }
    }
}

/// True if `name` is already in the environment with a non-reference value —
/// i.e. an outer `run` already hydrated it.
fn is_present_plain_value(ambient: &[(String, String)], name: &str) -> bool {
    ambient
        .iter()
        .any(|(k, v)| k == name && !Reference::looks_like_ref(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest::parse(
            r#"{
                database: {
                    $provider: "op",
                    $reason: "DB access",
                    DATABASE_URL: { ref: "db/url", required: true },
                    OPTIONAL_TOKEN: { ref: "tok", required: false },
                },
                stripe: {
                    STRIPE_KEY: "secret://op/Work/Stripe/api_key",
                },
                providers: {
                    op: { read: ["printf", "%s", "{locator}"] },
                    keychain: { read: ["security", "{locator}"] },
                },
            }"#,
            "test",
        )
        .unwrap()
    }

    #[test]
    fn eager_set_includes_only_required_secrets() {
        let m = manifest();
        let plan = build_plan(&m, None, &[], false).unwrap();
        let names: Vec<&str> = plan.requests.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"DATABASE_URL"));
        assert!(names.contains(&"STRIPE_KEY"));
        assert!(!names.contains(&"OPTIONAL_TOKEN")); // required:false
    }

    #[test]
    fn only_filters_to_selected_groups() {
        let m = manifest();
        let plan = build_plan(&m, Some(&["stripe".to_owned()]), &[], false).unwrap();
        let names: Vec<&str> = plan.requests.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["STRIPE_KEY"]);
    }

    #[test]
    fn unknown_only_group_errors() {
        let m = manifest();
        let err = build_plan(&m, Some(&["nope".to_owned()]), &[], false).unwrap_err();
        assert!(err.to_string().contains("unknown group `nope`"));
    }

    #[test]
    fn ambient_ref_is_resolved_in_place_with_overlaid_metadata() {
        let m = manifest();
        // OPTIONAL_TOKEN is required:false but appears as an ambient ref.
        let ambient = vec![(
            "OPTIONAL_TOKEN".to_owned(),
            "secret://op/from/env".to_owned(),
        )];
        let plan = build_plan(&m, Some(&["database".to_owned()]), &ambient, false).unwrap();
        let req = plan
            .requests
            .iter()
            .find(|r| r.name == "OPTIONAL_TOKEN")
            .expect("ambient ref should produce a request");
        assert_eq!(req.provider, "op");
        assert_eq!(req.locator, "from/env");
        assert_eq!(req.source, Source::Ambient);
        // Overlaid from the manifest declaration's group.
        assert_eq!(req.reason.as_deref(), Some("DB access"));
    }

    #[test]
    fn non_ref_env_values_are_ignored() {
        let m = manifest();
        let ambient = vec![("PATH".to_owned(), "/usr/bin".to_owned())];
        let plan = build_plan(&m, Some(&["stripe".to_owned()]), &ambient, false).unwrap();
        assert_eq!(plan.requests.len(), 1); // only STRIPE_KEY
    }

    #[test]
    fn malformed_ambient_ref_errors() {
        let m = manifest();
        let ambient = vec![("X".to_owned(), "secret://broken".to_owned())];
        let err = build_plan(&m, Some(&[]), &ambient, false).unwrap_err();
        assert!(err.to_string().contains("malformed"));
    }

    #[test]
    fn nested_run_skips_eager_secrets_already_injected() {
        let m = manifest();
        // Outer already injected DATABASE_URL as a plain value.
        let ambient = vec![("DATABASE_URL".to_owned(), "postgres://real".to_owned())];
        let plan = build_plan(&m, Some(&["database".to_owned()]), &ambient, true).unwrap();
        let names: Vec<&str> = plan.requests.iter().map(|r| r.name.as_str()).collect();
        assert!(
            !names.contains(&"DATABASE_URL"),
            "nested run must not re-resolve an inherited secret"
        );
    }

    #[test]
    fn resolve_all_applies_default_on_not_found() {
        let m = Manifest::parse(
            r#"{
                g: {
                    MISSING: { ref: "x", provider: "fail", default: "fallback", required: true },
                },
                providers: { fail: { read: ["false"] } },
            }"#,
            "t",
        )
        .unwrap();
        let plan = build_plan(&m, None, &[], false).unwrap();
        let (resolved, _stats) = resolve_all(&m, &plan).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].value.expose(), "fallback");
    }

    #[test]
    fn resolve_all_hard_errors_when_required_and_missing() {
        let m = Manifest::parse(
            r#"{
                g: { MISSING: { ref: "x", provider: "fail", required: true } },
                providers: { fail: { read: ["false"] } },
            }"#,
            "t",
        )
        .unwrap();
        let plan = build_plan(&m, None, &[], false).unwrap();
        assert!(resolve_all(&m, &plan).is_err());
    }

    #[test]
    fn resolve_all_uses_batch_capability_when_multiple_requests_share_a_provider() {
        // The batch command appends to a counter file and emits one
        // KEY=VALUE per requested name. With N=3 secrets on the same
        // batch-capable provider, the counter must end at 1 (one batch
        // invocation), not 3 (per-secret).
        let dir = tempfile::tempdir().unwrap();
        let counter = dir.path().join("counter");
        let manifest_text = format!(
            r#"{{
                g: {{
                    A: "secret://op_like/loc-a",
                    B: "secret://op_like/loc-b",
                    C: "secret://op_like/loc-c",
                }},
                providers: {{
                    op_like: {{
                        retrieve: ["false"],
                        retrieve_batch: {{
                            command: ["sh", "-c", "echo x >> {counter}; printenv"],
                            env_value: "echoed::{{locator}}",
                        }},
                    }},
                }},
            }}"#,
            counter = counter.display(),
        );
        let m = Manifest::parse(&manifest_text, "t").unwrap();
        let plan = build_plan(&m, None, &[], false).unwrap();
        let (resolved, _stats) = resolve_all(&m, &plan).unwrap();
        // Order preserved from plan.
        assert_eq!(resolved.len(), 3);
        assert_eq!(
            resolved.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["A", "B", "C"]
        );
        // Values came from the batch's synthetic env substitution.
        assert_eq!(resolved[0].value.expose(), "echoed::loc-a");
        assert_eq!(resolved[1].value.expose(), "echoed::loc-b");
        assert_eq!(resolved[2].value.expose(), "echoed::loc-c");
        // Critical: exactly one invocation.
        let invocations = std::fs::read_to_string(&counter).unwrap().lines().count();
        assert_eq!(
            invocations, 1,
            "batch-capable provider with 3 requests must invoke once, not 3 times"
        );
    }

    #[test]
    fn resolve_all_skips_batch_for_a_single_request_to_avoid_overhead() {
        // One request on a batch-capable provider should use per-secret
        // retrieve (the batch is no faster and adds a wrapper process).
        let dir = tempfile::tempdir().unwrap();
        let counter = dir.path().join("counter");
        let manifest_text = format!(
            r#"{{
                g: {{ A: "secret://op_like/loc-a" }},
                providers: {{
                    op_like: {{
                        retrieve: ["sh", "-c", "echo r >> {counter}; printf %s {{locator}}"],
                        retrieve_batch: {{
                            command: ["sh", "-c", "echo b >> {counter}; printenv"],
                            env_value: "echoed::{{locator}}",
                        }},
                    }},
                }},
            }}"#,
            counter = counter.display(),
        );
        let m = Manifest::parse(&manifest_text, "t").unwrap();
        let plan = build_plan(&m, None, &[], false).unwrap();
        let (resolved, _stats) = resolve_all(&m, &plan).unwrap();
        assert_eq!(resolved[0].value.expose(), "loc-a");
        // The counter should hold a single 'r' (retrieve), no 'b' (batch).
        let log = std::fs::read_to_string(&counter).unwrap();
        assert_eq!(
            log.trim_end(),
            "r",
            "single request must use retrieve, not batch"
        );
    }

    #[test]
    fn resolve_all_falls_back_to_per_secret_when_batch_command_fails() {
        // Batch command exits non-zero → per-secret retrieve is used; the
        // resolution still succeeds.
        let dir = tempfile::tempdir().unwrap();
        let counter = dir.path().join("counter");
        let manifest_text = format!(
            r#"{{
                g: {{ A: "secret://p/a", B: "secret://p/b" }},
                providers: {{
                    p: {{
                        retrieve: ["sh", "-c", "echo r >> {counter}; printf %s {{locator}}"],
                        retrieve_batch: {{
                            command: ["false"],
                            env_value: "{{locator}}",
                        }},
                    }},
                }},
            }}"#,
            counter = counter.display(),
        );
        let m = Manifest::parse(&manifest_text, "t").unwrap();
        let plan = build_plan(&m, None, &[], false).unwrap();
        let (resolved, _stats) = resolve_all(&m, &plan).unwrap();
        assert_eq!(resolved[0].value.expose(), "a");
        assert_eq!(resolved[1].value.expose(), "b");
        // Two per-secret retrieves were performed.
        assert_eq!(
            std::fs::read_to_string(&counter).unwrap().lines().count(),
            2
        );
    }

    #[test]
    fn resolve_all_reads_value_from_provider() {
        let m = manifest();
        let plan = build_plan(&m, Some(&["stripe".to_owned()]), &[], false).unwrap();
        let (resolved, _stats) = resolve_all(&m, &plan).unwrap();
        // `printf %s {locator}` echoes the locator back as the value.
        assert_eq!(resolved[0].name, "STRIPE_KEY");
        assert_eq!(resolved[0].value.expose(), "Work/Stripe/api_key");
    }
}
