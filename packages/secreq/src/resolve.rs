//! Secret resolution: turn a [`ResolutionPlan`] into values, through providers.
//!
//! Callers build the plan themselves — one [`SecretRequest`] per secret a wrap
//! (or the scoped agent, or an SSH sign) is asking for — and [`resolve_all`]
//! executes it, batching per provider wherever the provider supports it.
//!
//! The plan is plain data, which is what keeps this module free of config
//! shapes: it never reads a file, and it never learns where a request came
//! from.

use std::time::Duration;

use anyhow::{Context, Result};

use crate::manifest::Manifest;
use crate::provider::{self, RetrieveOutcome};
use crate::secret::SecretValue;

/// One secret we intend to resolve and inject.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretRequest {
    pub name: String,
    pub provider: String,
    pub locator: String,
    pub reason: Option<String>,
    pub description: Option<String>,
    pub default: Option<String>,
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

/// Execute every request through its provider, applying the resolution order
/// (found → default → hard error).
///
/// Returns the resolved values **in plan order**, so the consent prompt and
/// the injected env agree, paired with the [`ResolveStats`] for the pass. The
/// values are what nearly every caller is after; the stats exist for the
/// daemon's `resolve` log line and are bound as `_stats` everywhere else.
///
/// Behind the scenes, requests are grouped by provider so a provider with a
/// `retrieve_batch` capability resolves all of its requests in one
/// invocation — critical for `op`, where each `op read` triggers a
/// biometric prompt but `op run -- printenv` resolves any number of refs
/// after a single one. Per-secret retrieves are used when the provider has
/// no batch capability, when it has fewer than two requests (no benefit),
/// or as a fallback if batching fails.
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
            // Every value in `by_provider` was pushed to, so `first` is the
            // request that put this scheme in the map.
            let culprit = reqs.first().map_or("", |req| req.name.as_str());
            format!("secret `{culprit}` uses unknown provider scheme `{provider_name}`")
        })?;

        // Try batch when it pays off: ≥2 requests AND a batch capability
        // declared. A single request through batch is no faster and adds a
        // wrapper process (e.g. `op run` instead of `op read`).
        let batch = if reqs.len() >= 2 && provider.retrieve_batch.is_some() {
            let pairs: Vec<(String, String)> = reqs
                .iter()
                .map(|r| (r.name.clone(), r.locator.clone()))
                .collect();
            match provider::retrieve_batch(provider, &pairs) {
                Ok(batch) => Some(batch),
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

        if let Some(batch) = batch {
            stats.batch_subprocess += batch.timing.subprocess;
            stats.batch_parse += batch.timing.parse;
            for (name, outcome) in batch.outcomes {
                outcomes.insert(name, outcome);
            }
            // If batching produced NotFound for some names (e.g. a value
            // straddled a newline and our parser lost it), retry just those
            // through per-secret retrieve. Per-secret reads on `op` will
            // prompt biometric again, but only for the secrets we couldn't
            // batch — which is the right trade.
            let salvage: Vec<&&SecretRequest> = reqs
                .iter()
                .filter(|r| {
                    matches!(
                        outcomes.get(&r.name),
                        Some(RetrieveOutcome::NotFound { .. })
                    )
                })
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
        let outcome = outcomes
            .remove(&req.name)
            .unwrap_or(RetrieveOutcome::NotFound {
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
                    // The provider's detail is the error's *source*, not part
                    // of its top-level message, and the split is load-bearing:
                    // a provider CLI's stderr is output secreq does not control
                    // and may echo part of the value it failed to fetch. The
                    // daemon logs only the top level of this error to
                    // `daemon.log`/`daemon.jsonl`, while the full chain still
                    // travels back to the user who ran the command — so the
                    // diagnostic reaches a terminal without reaching a file
                    // that nothing rotates. Folding `detail` into the top
                    // message, as this once did, defeats both.
                    return Err(anyhow::anyhow!("{detail}").context(format!(
                        "secret `{}` could not be resolved from `{}` and has no default",
                        req.name, req.provider
                    )));
                }
            }
        }
    }
    Ok((resolved, stats))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{BatchRetrieve, Provider};
    use std::collections::BTreeMap;

    /// A retrieve-only provider.
    fn provider(name: &str, retrieve: &[&str]) -> Provider {
        Provider {
            name: name.to_owned(),
            retrieve: retrieve.iter().map(|s| (*s).to_owned()).collect(),
            store: None,
            retrieve_batch: None,
        }
    }

    /// A provider that can also resolve many secrets in one invocation.
    fn batched(name: &str, retrieve: &[&str], command: &[&str], env_value: &str) -> Provider {
        Provider {
            retrieve_batch: Some(BatchRetrieve {
                command: command.iter().map(|s| (*s).to_owned()).collect(),
                env_value_template: env_value.to_owned(),
            }),
            ..provider(name, retrieve)
        }
    }

    fn manifest(providers: &[Provider]) -> Manifest {
        Manifest {
            groups: BTreeMap::new(),
            providers: providers
                .iter()
                .map(|p| (p.name.clone(), p.clone()))
                .collect(),
        }
    }

    /// One request, built the way every production caller builds it.
    fn req(name: &str, provider: &str, locator: &str) -> SecretRequest {
        SecretRequest {
            name: name.to_owned(),
            provider: provider.to_owned(),
            locator: locator.to_owned(),
            reason: None,
            description: None,
            default: None,
        }
    }

    fn plan(requests: Vec<SecretRequest>) -> ResolutionPlan {
        ResolutionPlan { requests }
    }

    #[test]
    fn resolve_all_applies_default_on_not_found() {
        let m = manifest(&[provider("fail", &["false"])]);
        let p = plan(vec![SecretRequest {
            default: Some("fallback".to_owned()),
            ..req("MISSING", "fail", "x")
        }]);
        let (resolved, _stats) = resolve_all(&m, &p).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].value.expose(), "fallback");
    }

    #[test]
    fn resolve_all_hard_errors_when_required_and_missing() {
        let m = manifest(&[provider("fail", &["false"])]);
        let p = plan(vec![req("MISSING", "fail", "x")]);
        assert!(resolve_all(&m, &p).is_err());
    }

    /// A provider CLI's stderr may echo part of the value it failed to fetch,
    /// and the daemon writes its resolve line to disk. So the provider's
    /// detail must live in the error's *source*, not its top-level message:
    /// `{err}` is what goes in `daemon.log`, `{err:#}` is what goes back to
    /// the user who ran the command.
    #[test]
    fn a_providers_stderr_is_below_the_top_level_message_not_inside_it() {
        let m = manifest(&[provider(
            "loud",
            &["sh", "-c", "echo LEAKED-ghp_abc >&2; exit 1"],
        )]);
        let p = plan(vec![req("MISSING", "loud", "x")]);
        // `ResolvedSecret` has no `Debug` (it holds a `SecretValue`), so the
        // `Ok` arm is matched out rather than `unwrap_err`'d.
        let Err(err) = resolve_all(&m, &p) else {
            panic!("a required secret the provider refused must be an error");
        };

        let top = format!("{err}");
        assert!(
            !top.contains("LEAKED"),
            "provider stderr reached the top-level message: {top}"
        );
        assert!(top.contains("MISSING") && top.contains("loud"), "{top}");

        let full = format!("{err:#}");
        assert!(
            full.contains("LEAKED"),
            "the user's own channel must keep the diagnostic: {full}"
        );
    }

    #[test]
    fn resolve_all_uses_batch_capability_when_multiple_requests_share_a_provider() {
        // The batch command appends to a counter file and emits one
        // KEY=VALUE per requested name. With N=3 secrets on the same
        // batch-capable provider, the counter must end at 1 (one batch
        // invocation), not 3 (per-secret).
        let dir = tempfile::tempdir().unwrap();
        let counter = dir.path().join("counter");
        let m = manifest(&[batched(
            "op_like",
            &["false"],
            &[
                "sh",
                "-c",
                &format!("echo x >> {}; printenv", counter.display()),
            ],
            "echoed::{locator}",
        )]);
        let p = plan(vec![
            req("A", "op_like", "loc-a"),
            req("B", "op_like", "loc-b"),
            req("C", "op_like", "loc-c"),
        ]);
        let (resolved, _stats) = resolve_all(&m, &p).unwrap();
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
        let m = manifest(&[batched(
            "op_like",
            &[
                "sh",
                "-c",
                &format!("echo r >> {}; printf %s {{locator}}", counter.display()),
            ],
            &[
                "sh",
                "-c",
                &format!("echo b >> {}; printenv", counter.display()),
            ],
            "echoed::{locator}",
        )]);
        let p = plan(vec![req("A", "op_like", "loc-a")]);
        let (resolved, _stats) = resolve_all(&m, &p).unwrap();
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
        let m = manifest(&[batched(
            "p",
            &[
                "sh",
                "-c",
                &format!("echo r >> {}; printf %s {{locator}}", counter.display()),
            ],
            &["false"],
            "{locator}",
        )]);
        let p = plan(vec![req("A", "p", "a"), req("B", "p", "b")]);
        let (resolved, _stats) = resolve_all(&m, &p).unwrap();
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
        let m = manifest(&[provider("op", &["printf", "%s", "{locator}"])]);
        let p = plan(vec![req("STRIPE_KEY", "op", "Work/Stripe/api_key")]);
        let (resolved, _stats) = resolve_all(&m, &p).unwrap();
        // `printf %s {locator}` echoes the locator back as the value.
        assert_eq!(resolved[0].name, "STRIPE_KEY");
        assert_eq!(resolved[0].value.expose(), "Work/Stripe/api_key");
    }
}
