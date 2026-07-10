# `secreq run` Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `secreq run [--env-file PATH]… -- <cmd>` — resolve `secret://provider/locator` references found in the ambient environment (and any `--env-file`), through the existing consent daemon, then exec the command with the resolved values injected and output masked.

**Architecture:** `run` is the ambient mirror of `x`. It reuses the entire back end unchanged (`exec::run`, `reference.rs`, the daemon resolve/cache/batch path). The only new pieces are: a tiny `dotenv` reader, an ambient-env scan, a shared Ask-builder/client-resolver extracted from the existing `x` consent functions, the `commands::run` orchestrator, a `Run` CLI subcommand, and a one-field protocol change (`Ask.allow_remember`) with a one-line server-side guard so `run` never persists a remembered approval.

**Tech Stack:** Rust, `clap` (CLI), `serde` (wire protocol), the project's `portable-pty`-based `exec` engine, `egui_kittest` screenshot harness.

**Design doc:** `dev-docs/plans/2026-06-29-secreq-run-design.md` — read it first.

**Key existing code to know:**
- `src/commands.rs::wrap_run` (51) — the `x` orchestrator `run` mirrors.
- `src/commands.rs::obtain_wrap_consent` (1774), `resolve_wrap_env` (1861), `to_wire_provider` (1847) — the consent/resolve helpers to refactor.
- `src/exec.rs::run` (23) — `run(command, env_overrides, secrets, cwd)`. **Unchanged.** Applies `env_overrides` *on top of* the inherited process env.
- `src/reference.rs::{Reference::parse, looks_like_ref, SCHEME}` — the ref parser.
- `src/daemon/proto.rs::Ask` (175), `SecretAsk` (251), `WireProvider` (265), `DedupeKey` (230).
- `src/daemon/state.rs:891` — the approvals-cache write (the enforcement point).
- `src/cli.rs` — clap surface; `Command::X` (155) is the pattern to copy.

**Conventions:**
- Run `cargo fmt` and `cargo clippy --all-targets` before every commit; all hook checks must be green (zero warnings).
- Commit after each task with the message shown.
- TDD: write the failing test, see it fail, implement, see it pass.

---

### Task 1: Add `Ask.allow_remember` with a server-side guard

Adds the protocol field and the single enforcement point. `serde` default `true` keeps the attach protocol back-compatible and means only `run` ever sets `false`.

**Files:**
- Modify: `src/daemon/proto.rs` (the `Ask` struct, ~175)
- Modify: `src/daemon/state.rs:891` (approval-write condition)
- Modify: every `Ask { … }` struct literal (compiler will list them: `commands.rs::obtain_wrap_consent`, the SSH ask in `src/daemon/ssh_agent.rs`, and test/fixture literals in `state.rs`, `ui.rs`, `server.rs`)
- Test: `src/daemon/state.rs` (tests module)

**Step 1: Write the failing test**

In `src/daemon/state.rs` tests module, add (mirror the existing `resolve_ssh_ask_remember_does_not_write_wrap_cache_but_normal_ask_does` at ~1667):

```rust
#[test]
fn ask_with_allow_remember_false_does_not_persist_approval() {
    // A `run` ask (allow_remember = false) given ApproveRemember must
    // NOT write the approvals cache — every run re-prompts.
    let mut guard = State::new_for_test();
    let mut ask = wrap_ask_for_test("run", "deploy.sh"); // helper builds an Ask
    ask.allow_remember = false;
    let key = ask.dedupe_key.clone();
    guard.enqueue_for_test(ask);
    let shared = test_shared();
    guard.resolve(&key, Decision::ApproveRemember, ApprovalScope::Caller, &shared);
    assert!(
        guard.approvals.is_empty(),
        "a run ask must not persist an approval even on ApproveRemember"
    );
}
```

If no `wrap_ask_for_test` / `new_for_test` / `enqueue_for_test` helpers exist, reuse whatever the neighboring tests at ~1667–1712 use to build an `Ask` and drive `resolve`; match their exact construction. The assertion that matters is `guard.approvals.is_empty()`.

**Step 2: Run test to verify it fails**

Run: `cargo test --lib daemon::state::tests::ask_with_allow_remember_false -- --nocapture`
Expected: FAIL — either a compile error (`allow_remember` field missing) or the assertion fails because the approval was persisted.

**Step 3: Implement**

In `src/daemon/proto.rs`, add to `Ask` (after the `ssh` field):

```rust
    /// Whether an `ApproveRemember` decision on this ask may persist a
    /// remembered approval. `true` for wrap (`x`) asks; `false` for
    /// `secreq run`, whose fixed `"run"` identity would otherwise let one
    /// remembered approval cover any later command in the same shell.
    /// `#[serde(default = "default_true")]` keeps the attach protocol
    /// back-compatible: an older peer omits the field and decodes `true`.
    #[serde(default = "default_true")]
    pub allow_remember: bool,
```

Add near the top of `proto.rs` (module scope):

```rust
fn default_true() -> bool {
    true
}
```

In `src/daemon/state.rs:891`, extend the condition:

```rust
        if decision == Decision::ApproveRemember
            && entry.representative.ssh.is_none()
            && entry.representative.allow_remember
        {
```

Then add `allow_remember: true` to every `Ask { … }` literal the compiler flags (production sites: `commands.rs::obtain_wrap_consent`, `ssh_agent.rs` SSH ask; plus test/fixture literals).

**Step 4: Run tests to verify they pass**

Run: `cargo test --lib daemon::state` then `cargo build`
Expected: PASS; the existing `…normal_ask_does` test still asserts a wrap ask DOES persist (proves we didn't break `x`).

**Step 5: Commit**

```bash
git add src/daemon/proto.rs src/daemon/state.rs src/daemon/ssh_agent.rs src/commands.rs src/daemon/ui.rs src/daemon/server.rs
git commit -m "feat(daemon): add Ask.allow_remember, gate approval persistence on it"
```

---

### Task 2: A read-only `dotenv` parser for `--env-file`

**Files:**
- Create: `src/dotenv.rs`
- Modify: `src/lib.rs` (add `pub mod dotenv;`)
- Test: in `src/dotenv.rs` (`#[cfg(test)]`)

**Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_pairs_ignoring_comments_and_blanks() {
        let input = "\
# a comment
DATABASE_URL=secret://op/Work/PG/url

STRIPE_KEY = secret://keychain/stripe
";
        let got = parse(input);
        assert_eq!(
            got,
            vec![
                ("DATABASE_URL".to_owned(), "secret://op/Work/PG/url".to_owned()),
                ("STRIPE_KEY".to_owned(), "secret://keychain/stripe".to_owned()),
            ]
        );
    }

    #[test]
    fn value_may_contain_equals_signs() {
        assert_eq!(
            parse("TOKEN=a=b=c"),
            vec![("TOKEN".to_owned(), "a=b=c".to_owned())]
        );
    }

    #[test]
    fn strips_matching_surrounding_quotes() {
        assert_eq!(
            parse("X=\"secret://op/x\"\nY='secret://op/y'"),
            vec![
                ("X".to_owned(), "secret://op/x".to_owned()),
                ("Y".to_owned(), "secret://op/y".to_owned()),
            ]
        );
    }

    #[test]
    fn skips_lines_without_an_equals() {
        assert_eq!(parse("NOTAVAR\nA=1"), vec![("A".to_owned(), "1".to_owned())]);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --lib dotenv`
Expected: FAIL — `parse` not defined.

**Step 3: Implement**

```rust
//! Minimal, read-only `.env` reader for `secreq run --env-file`.
//!
//! Parses `KEY=value` lines so their values can be scanned for
//! `secret://` references. Deliberately tiny: no interpolation, no
//! `export` keyword handling, no writing or scrubbing — unlike the
//! pre-pivot `import` tool, this never mutates the file. Values are
//! taken verbatim except for one layer of matching surrounding quotes.

/// Parse `.env` text into ordered `(key, value)` pairs. Blank lines and
/// `#` comments are skipped; a line with no `=` is skipped.
pub fn parse(input: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim().to_owned();
        if key.is_empty() {
            continue;
        }
        out.push((key, unquote(value.trim())));
    }
    out
}

/// Strip one layer of matching single or double quotes, if present.
fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if value.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        value[1..value.len() - 1].to_owned()
    } else {
        value.to_owned()
    }
}
```

Add `pub mod dotenv;` to `src/lib.rs` (alphabetical with the other `pub mod` lines).

**Step 4: Run tests to verify they pass**

Run: `cargo test --lib dotenv`
Expected: PASS (4 tests).

**Step 5: Commit**

```bash
git add src/dotenv.rs src/lib.rs
git commit -m "feat: add read-only dotenv parser for run --env-file"
```

---

### Task 3: Shared ambient-scan, Ask builder, and client resolver

Refactor `obtain_wrap_consent` / `resolve_wrap_env` so the ref→Ask and ref→client-resolve logic is shared with `run`, instead of duplicated. Behavior for `x` must not change.

**Files:**
- Modify: `src/commands.rs` (extract helpers; rewire `obtain_wrap_consent`, `resolve_wrap_env`)
- Test: `src/commands.rs` (`#[cfg(test)]`)

**Step 1: Write the failing test**

Add a test for the new pure builder. It must assert the fields `run` depends on:

```rust
#[test]
fn build_ask_sets_identity_command_and_remember() {
    use crate::reference::Reference;
    let refs = vec![(
        "DATABASE_URL".to_owned(),
        Reference::parse("secret://op/Work/PG/url").unwrap(),
    )];
    let callers = vec![provenance::Caller {
        pid: 42,
        name: "zsh".to_owned(),
        command: "zsh".to_owned(),
        start_time: 7,
    }];
    let config = WrapsConfig::default(); // providers map may be empty here
    let ask = build_ask(
        AskSpec {
            dedupe_wrap: "run".to_owned(),
            command: vec!["./deploy.sh".to_owned(), "--prod".to_owned()],
            refs: &refs,
            reason: None,
            allow_remember: false,
        },
        &callers,
        std::path::Path::new("/tmp/proj"),
        &config,
    );
    assert_eq!(ask.dedupe_key.wrap, "run");
    assert_eq!(ask.command, vec!["./deploy.sh", "--prod"]);
    assert!(!ask.allow_remember);
    assert_eq!(ask.secrets.len(), 1);
    assert_eq!(ask.secrets[0].name, "DATABASE_URL");
    assert_eq!(ask.secrets[0].provider, "op");
    assert_eq!(ask.secrets[0].locator, "Work/PG/url");
    assert_eq!(ask.dedupe_key.ppid, 42);
}
```

(Match `WrapsConfig` / `provenance::Caller` field names to the real types; adjust if `WrapsConfig::default` isn't available — build a minimal config the way other tests in the file do.)

**Step 2: Run test to verify it fails**

Run: `cargo test --lib commands::tests::build_ask_sets_identity`
Expected: FAIL — `build_ask` / `AskSpec` not defined.

**Step 3: Implement**

Add a shared `EnvRef`-style scan and the two helpers. Suggested shapes:

```rust
/// A parsed env reference: the variable name and its `secret://` target.
pub(crate) struct EnvRef {
    pub name: String,
    pub reference: Reference,
}

/// Scan `(name, value)` env pairs for `secret://provider/locator`
/// values. A value that *looks* like a reference (starts with the
/// scheme) but does not parse is a hard error, naming the variable —
/// never silently pass a literal `secret://…` to the child.
pub(crate) fn scan_env_refs(env: &[(String, String)]) -> Result<Vec<EnvRef>> {
    let mut refs = Vec::new();
    for (name, value) in env {
        if !Reference::looks_like_ref(value) {
            continue;
        }
        let reference = Reference::parse(value).with_context(|| {
            format!("env var `{name}`: `{value}` is not a valid `secret://provider/locator` reference")
        })?;
        refs.push(EnvRef { name: name.clone(), reference });
    }
    Ok(refs)
}

pub(crate) struct AskSpec<'a> {
    pub dedupe_wrap: String,
    pub command: Vec<String>,
    pub refs: &'a [(String, Reference)],
    pub reason: Option<String>,
    pub allow_remember: bool,
}

/// Build the daemon `Ask` from explicit pieces. Pure — no I/O beyond the
/// providers snapshot already loaded into `config`.
pub(crate) fn build_ask(
    spec: AskSpec<'_>,
    callers: &[provenance::Caller],
    cwd: &Path,
    config: &WrapsConfig,
) -> proto::Ask {
    let mut providers = HashMap::new();
    let mut secrets = Vec::new();
    for (name, reference) in spec.refs {
        if let Some(p) = config.providers.get(&reference.provider) {
            providers.insert(reference.provider.clone(), to_wire_provider(p));
        }
        secrets.push(proto::SecretAsk {
            name: name.clone(),
            provider: reference.provider.clone(),
            locator: reference.locator.clone(),
            default: None,
            description: None,
            reason: spec.reason.clone(),
        });
    }
    let parent = callers.first();
    proto::Ask {
        command: spec.command,
        cwd: cwd.display().to_string(),
        callers: callers.iter().map(|c| proto::Caller {
            pid: c.pid, name: c.name.clone(), command: c.command.clone(), start_time: c.start_time,
        }).collect(),
        secrets,
        providers,
        dedupe_key: proto::DedupeKey {
            wrap: spec.dedupe_wrap,
            ppid: parent.map(|p| p.pid).unwrap_or(0),
            parent_start_time: parent.map(|p| p.start_time).unwrap_or(0),
        },
        ssh: None,
        allow_remember: spec.allow_remember,
    }
}

/// Resolve a set of references client-side (the `--yes` path). Reuses
/// `resolve::resolve_all` for batching/grouping.
pub(crate) fn resolve_refs_client_side(
    config: &WrapsConfig,
    refs: &[(String, Reference)],
    reason: Option<&str>,
) -> Result<Vec<(String, SecretValue)>> {
    let manifest = crate::manifest::Manifest {
        groups: std::collections::BTreeMap::new(),
        providers: config.providers.clone(),
    };
    let requests = refs.iter().map(|(name, r)| SecretRequest {
        name: name.clone(),
        provider: r.provider.clone(),
        locator: r.locator.clone(),
        group: None,
        reason: reason.map(|s| s.to_owned()),
        description: None,
        default: None,
        source: Source::Eager,
    }).collect();
    let plan = resolve::ResolutionPlan { requests };
    let resolved = resolve::resolve_all(&manifest, &plan)?;
    Ok(resolved.into_iter().map(|r| (r.name, r.value)).collect())
}
```

Now rewire the existing functions to call these (keep their public signatures):
- `obtain_wrap_consent`: parse `wrap.env` into `Vec<(String, Reference)>` (preserving the existing malformed-ref error message), then `build_ask(AskSpec { dedupe_wrap: wrap.name.clone(), command: [wrap.name]+args, refs, reason: wrap.reason.clone(), allow_remember: true }, …)`, then `daemon_client::request_consent(...)` exactly as before. Keep the "no direct parent ⇒ bail" guard.
- `resolve_wrap_env`: parse `wrap.env` into refs, call `resolve_refs_client_side(config, &refs, wrap.reason.as_deref())`.

Delete the now-duplicated loops. **No `x` behavior changes.**

**Step 4: Run tests to verify they pass**

Run: `cargo test --lib commands` then `cargo build`
Expected: PASS, including any existing `commands` tests (proves `x` path intact).

**Step 5: Commit**

```bash
git add src/commands.rs
git commit -m "refactor(commands): extract shared env-ref scan, Ask builder, client resolver"
```

---

### Task 4: `commands::run` orchestrator

**Files:**
- Modify: `src/commands.rs` (add `pub fn run`)
- Test: `src/commands.rs` (`#[cfg(test)]`) — env merge + scan + substitution logic

**Step 1: Write the failing test**

The daemon round-trip needs a live daemon, so unit-test the pure parts: env merge (inherited wins) and override computation. Extract a small pure helper and test it:

```rust
#[test]
fn effective_env_layers_envfile_under_inherited() {
    let inherited = vec![("A".to_owned(), "from_env".to_owned())];
    let envfile = vec![
        ("A".to_owned(), "from_file".to_owned()),       // inherited wins
        ("B".to_owned(), "secret://op/x".to_owned()),   // file-only
    ];
    let eff = effective_env(&inherited, &envfile);
    assert_eq!(eff.get("A").map(String::as_str), Some("from_env"));
    assert_eq!(eff.get("B").map(String::as_str), Some("secret://op/x"));
}

#[test]
fn overrides_carry_filed_plain_vars_and_resolved_refs_only() {
    // Given the effective env + resolved values, the overrides passed to
    // exec::run must be: file-only plain vars + every resolved ref.
    // Inherited plain vars are NOT re-emitted (the child inherits them).
    let inherited = vec![("PATH".to_owned(), "/usr/bin".to_owned())];
    let envfile = vec![
        ("PLAIN".to_owned(), "hello".to_owned()),
        ("TOKEN".to_owned(), "secret://op/x".to_owned()),
    ];
    let eff = effective_env(&inherited, &envfile);
    let resolved = vec![("TOKEN".to_owned(), "real-token".to_owned())];
    let mut overrides = build_overrides(&eff, &inherited, &resolved);
    overrides.sort();
    assert_eq!(
        overrides,
        vec![
            ("PLAIN".to_owned(), "hello".to_owned()),
            ("TOKEN".to_owned(), "real-token".to_owned()),
        ]
    );
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --lib commands::tests::effective_env`
Expected: FAIL — `effective_env` / `build_overrides` not defined.

**Step 3: Implement**

Add the pure helpers and the orchestrator:

```rust
/// Merge env-file pairs UNDER the inherited environment (inherited wins).
fn effective_env(
    inherited: &[(String, String)],
    envfile: &[(String, String)],
) -> std::collections::BTreeMap<String, String> {
    let mut eff: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (k, v) in envfile {
        eff.insert(k.clone(), v.clone());
    }
    for (k, v) in inherited {
        eff.insert(k.clone(), v.clone()); // inherited wins
    }
    eff
}

/// Compute the overrides for `exec::run`. The child already inherits the
/// process env, so we only emit: (a) keys present in the effective env
/// but not inherited (file-only plain vars), and (b) every resolved ref
/// (replacing its `secret://…` placeholder with the real value).
fn build_overrides(
    eff: &std::collections::BTreeMap<String, String>,
    inherited: &[(String, String)],
    resolved: &[(String, String)],
) -> Vec<(String, String)> {
    use std::collections::HashSet;
    let inherited_keys: HashSet<&str> = inherited.iter().map(|(k, _)| k.as_str()).collect();
    let resolved_keys: HashSet<&str> = resolved.iter().map(|(k, _)| k.as_str()).collect();
    let mut out: Vec<(String, String)> = resolved.to_vec();
    for (k, v) in eff {
        if resolved_keys.contains(k.as_str()) {
            continue; // already carried by `resolved`
        }
        if !inherited_keys.contains(k.as_str()) {
            out.push((k.clone(), v.clone())); // file-only plain var
        }
    }
    out
}

/// `secreq run [--env-file PATH]… -- <cmd>` — resolve ambient `secret://`
/// refs through the daemon, then exec the command with masking.
pub fn run(
    command: &[String],
    env_files: &[PathBuf],
    opts: WrapRunOpts,
    config_path: Option<&Path>,
) -> Result<i32> {
    if command.is_empty() {
        bail!("secreq run: no command given (usage: secreq run [--env-file PATH]… -- <cmd> [args…])");
    }
    let config = load_config_or_default(config_path)?;

    // Recursion guard: if we're already inside secreq's own resolution,
    // just exec the command without re-resolving (mirrors wrap_run).
    if std::env::var_os(crate::RESOLVING_ENV).is_some() {
        let cwd = std::env::current_dir()?;
        return crate::exec::run(command, &[], &[], &cwd);
    }

    // 1. Effective env = inherited, with --env-file layered underneath.
    let inherited: Vec<(String, String)> = std::env::vars().collect();
    let mut envfile_pairs = Vec::new();
    for path in env_files {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("could not read env file {}", path.display()))?;
        envfile_pairs.extend(crate::dotenv::parse(&text));
    }
    let eff = effective_env(&inherited, &envfile_pairs);

    // 2. Scan for secret:// references.
    let eff_pairs: Vec<(String, String)> = eff.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let scanned = scan_env_refs(&eff_pairs)?;
    let refs: Vec<(String, Reference)> =
        scanned.into_iter().map(|r| (r.name, r.reference)).collect();

    let cwd = std::env::current_dir().context("could not determine current directory")?;

    // 3. Nothing to resolve → just exec the file-only plain vars + inherited.
    if refs.is_empty() {
        let overrides = build_overrides(&eff, &inherited, &[]);
        return crate::exec::run(command, &overrides, &[], &cwd);
    }

    // 4 + 5. Consent + resolve (daemon, or client-side under --yes).
    let callers = provenance::caller_chain();
    let resolved: Vec<(String, SecretValue)> = if opts.assume_yes {
        let names: Vec<String> = refs.iter().map(|(n, _)| n.clone()).collect();
        let _ = audit::append(&AuditEntry::new("run", command, &callers, &names, Decision::Approve));
        resolve_refs_client_side(&config, &refs, None)?
    } else {
        let ask = build_ask(
            AskSpec {
                dedupe_wrap: "run".to_owned(),
                command: command.to_vec(),
                refs: &refs,
                reason: None,
                allow_remember: false,
            },
            &callers,
            &cwd,
            &config,
        );
        let names: Vec<String> = refs.iter().map(|(n, _)| n.clone()).collect();
        let outcome = daemon_client::request_consent(ask, config.wait_indicator_enabled())
            .context("daemon consent request failed")?;
        let _ = audit::append(
            &AuditEntry::new("run", command, &callers, &names, outcome.decision)
                .with_rule_id(outcome.rule_id.clone()),
        );
        if !outcome.decision.approved() {
            // Mirror wrap_run's deny messaging.
            if outcome.decision == Decision::DenyAuto {
                let rule_name = outcome.rule_name.as_deref().unwrap_or("(unknown)");
                match outcome.deny_message.as_deref() {
                    Some(msg) => eprintln!("secreq: denied by rule '{rule_name}': {msg}"),
                    None => eprintln!("secreq: denied by rule '{rule_name}'"),
                }
            } else {
                eprintln!("secreq: denied — command not run");
            }
            return Ok(1);
        }
        outcome.secrets.into_iter().map(|(n, v)| (n, SecretValue::new(v))).collect()
    };

    // 6. Substitute resolved values into the env; build overrides.
    let resolved_plain: Vec<(String, String)> =
        resolved.iter().map(|(n, v)| (n.clone(), v.expose().to_owned())).collect();
    let env_overrides = build_overrides(&eff, &inherited, &resolved_plain);

    // 7. Exec with masking (unless --raw).
    let secrets_for_masking: Vec<SecretValue> = if opts.raw {
        Vec::new()
    } else {
        resolved.into_iter().map(|(_, v)| v).collect()
    };
    crate::exec::run(command, &env_overrides, &secrets_for_masking, &cwd)
}
```

Check the real `obtain_wrap_consent`/`request_consent` return type for the exact `ConsentOutcome` fields (`decision`, `secrets`, `rule_id`, `rule_name`, `deny_message`) and match `wrap_run`'s usage at `commands.rs:97–123`. Match `AuditEntry::new` signature exactly (CLAUDE.md notes `run` is a client-side audit writer; `wrap = "run"`).

**Step 4: Run tests to verify they pass**

Run: `cargo test --lib commands` then `cargo build`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/commands.rs
git commit -m "feat(commands): add run orchestrator (ambient secret:// resolution + exec)"
```

---

### Task 5: `Run` CLI subcommand

**Files:**
- Modify: `src/cli.rs` (the `Command` enum ~48, the dispatch `match` ~296)
- Test: a CLI parse smoke test (optional — `cargo build` + manual is acceptable per "skip tests for simple CLI parsing")

**Step 1: Add the subcommand variant**

In `enum Command`, after `X { … }`:

```rust
    /// `op run`, but for every secret store: resolve `secret://provider/locator`
    /// references found in the environment (and any `--env-file`) through the
    /// consent daemon, then run <cmd> with the resolved values injected and
    /// output masked.
    Run {
        /// Load `KEY=value` lines from this file, layered *under* the
        /// inherited environment (inherited wins). The file holds
        /// references, not plaintext. Repeatable.
        #[arg(long = "env-file", value_name = "PATH")]
        env_file: Vec<PathBuf>,
        /// The command to run, and its arguments.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
```

**Step 2: Wire dispatch**

In `pub fn run()`'s match, alongside `Command::X`:

```rust
        Some(Command::Run { env_file, command }) => commands::run(
            &command,
            &env_file,
            WrapRunOpts {
                raw: cli.raw,
                no_remember: cli.no_remember,
                assume_yes: cli.yes,
            },
            config,
        ),
```

**Step 3: Build + manual check**

Run: `cargo build && ./target/debug/secreq run --help`
Expected: help shows `--env-file <PATH>` and the trailing command; `secreq --help` lists `run`.

**Step 4: Smoke test (no refs → passthrough)**

Run: `env FOO=bar ./target/debug/secreq run -- printenv FOO`
Expected: prints `bar`, exit 0, no daemon contact (empty ref set fast path).

**Step 5: Commit**

```bash
git add src/cli.rs
git commit -m "feat(cli): add `secreq run` subcommand"
```

---

### Task 6: End-to-end resolution test against a fake provider

**Files:**
- Test: `tests/` — add `tests/run_resolves.rs` (or extend an existing integration test that drives a real daemon + fake `sh -c` provider, following the pattern in `src/daemon/state.rs` tests ~2018–2140).

**Step 1: Write the test**

Drive `commands::run` (or the binary) with a config whose provider is a `sh -c` script that echoes a known value, an env var set to a `secret://fake/…` ref, and `--yes` (to avoid needing the GUI daemon). Assert the child sees the resolved value:

```rust
// Pseudocode shape — match the repo's existing integration harness.
// fake provider: retrieve = ["sh","-c","printf '%s' resolved-$1","--","{locator}"]
// env: SECRET=secret://fake/thing
// run --yes -- printenv SECRET   => stdout contains "resolved-thing"
```

If `--yes` resolution still requires provider CLIs on PATH, use the `sh`-based fake exactly as `state.rs::resolve_single_cached_resolves_once_then_serves_from_cache` does.

**Step 2: Run to verify it fails, then passes after wiring**

Run: `cargo test --test run_resolves`
Expected: PASS once the config + ref plumbing is correct. This is the real proof the feature works end-to-end (scan → resolve → substitute → exec).

**Step 3: Commit**

```bash
git add tests/run_resolves.rs
git commit -m "test: end-to-end run resolves an ambient secret:// ref"
```

---

### Task 7: Screenshot fixture for the `run` consent card

Per CLAUDE.md, add a fixture for the new scenario and regenerate all PNGs. A `run` ask renders through the existing wrap card, so this exercises the card with a free-form command + ambient-sourced secrets + `allow_remember = false`.

**Files:**
- Modify: `tests/ui_screenshots.rs` (add a fixture; extend the Ask-building helper to set `allow_remember`)
- Create: `dev-docs/ui-screenshots/run-consent.png` (generated)
- Modify: `dev-docs/ui-screenshots/README.md` (add a table row)

**Step 1: Add the fixture**

Follow the existing fixtures and the CLAUDE.md "How to add a fixture" notes. Build an `Ask` with `dedupe_key.wrap = "run"`, `command = vec!["./deploy.sh","--prod"]`, two `SecretAsk`s (`DATABASE_URL` → op, `STRIPE_KEY` → keychain), `allow_remember = false`, status Awaiting. Name the fixture e.g. `run_consent_card`.

**Step 2: Regenerate every screenshot**

Run: `cargo test --test ui_screenshots -- --ignored --nocapture --test-threads=1`
Expected: all fixtures regenerate, including the new `run-consent.png`.

**Step 3: Inspect**

Open `dev-docs/ui-screenshots/run-consent.png` (confirm: command header `./deploy.sh --prod`, the two secrets, Approve/Deny buttons) and one pre-existing fixture (confirm no unintended regression).

**Step 4: Update the README table**

Add a row: file `run-consent.png`, fixture `run_consent_card`, "the `secreq run` consent card — free-form command, ambient-sourced secrets, no remembered approval".

**Step 5: Commit**

```bash
git add tests/ui_screenshots.rs dev-docs/ui-screenshots/
git commit -m "test(ui): add run consent-card screenshot fixture"
```

---

### Task 8: Docs + final verification

**Files:**
- Modify: `README.md` (add `run` to the command list / examples)
- Modify: `docs/` (the overview / commands page — wherever `x` is documented)

**Step 1: Document `run`**

Add a short `secreq run` section mirroring how `x` is described: the `--env-file` flag, the `secret://` ambient-scan behavior, masking, `--yes`, and a one-liner example. Note it does not remember approvals.

**Step 2: Full verification**

Run, in order:
- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- `cargo test --test ui_screenshots -- --ignored --test-threads=1` (if not already green from Task 7)

Expected: all green.

**Step 3: Commit**

```bash
git add README.md docs/
git commit -m "docs: document `secreq run`"
```

---

## Done when

- `secreq run --env-file .env -- <cmd>` resolves every `secret://` ref in the inherited env + the file, through the daemon (one consent, batched unlocks, cache reuse across runs), execs `<cmd>` with values injected and output masked.
- `--yes` resolves client-side; `--raw` disables masking; empty ref set execs directly.
- A `run` ask never persists a remembered approval (`allow_remember = false`, enforced at `state.rs:891`).
- All tests + clippy + fmt green; screenshot fixtures regenerated; design doc and user docs updated.
