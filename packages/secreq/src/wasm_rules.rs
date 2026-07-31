//! Programmable auto-rules — the WebAssembly host side.
//!
//! Users author a rule as a single AssemblyScript function
//! (`decide(ctx) -> approve | pass | deny | prompt`), compile it with the
//! `packages/secreq-rule` helper package, and register the resulting `.wasm`
//! module. At decision time the daemon evaluates the module in the same
//! pre-queue path as the declarative rules in [`crate::rules`].
//!
//! ## Sandbox / trust model
//!
//! A rule module can read exactly one thing — the [`EvalCtx`] the daemon
//! hands it — and produce exactly one thing: a decision. To make that a
//! property of construction rather than convention:
//!
//! - **No WASI, no ambient imports.** The only host-provided import is
//!   AssemblyScript's `env.abort` (which traps). A module importing
//!   anything else — filesystem, network, clocks, randomness — fails at
//!   [`RuleModule::from_binary`] time with an error naming the offending
//!   import.
//! - **Fuel-metered execution.** The store is given a fixed fuel budget
//!   ([`FUEL_BUDGET`]), so an accidental (or hostile) infinite loop
//!   becomes a clean error instead of a hung daemon. Fuel was chosen over
//!   epoch interruption because it is deterministic and needs no
//!   background ticker thread; the ~single-digit-percent slowdown is
//!   irrelevant at rule size.
//! - **Memory-capped.** Guest memory growth is limited to
//!   [`MAX_GUEST_MEMORY_BYTES`] via a store limiter.
//! - **One instance per evaluation.** Every [`RuleModule::evaluate`]
//!   call instantiates fresh, so no state leaks between asks and a
//!   trapped instance is simply dropped.
//!
//! Every failure mode — unparseable module, disallowed import, missing
//! export, guest trap/abort, fuel exhaustion, out-of-bounds decision
//! pointer, invalid UTF-8, malformed decision JSON — surfaces as an
//! `anyhow` error. Nothing in here panics the daemon.
//!
//! ## ABI (kept in lock-step with `packages/secreq-rule/assembly/abi.ts`)
//!
//! The module must export:
//!
//! - `memory` — its linear memory;
//! - `alloc(len: i32) -> i32` — return a buffer for the host to write
//!   into (AssemblyScript stub-runtime bump allocator; nothing is freed);
//! - `decide(ptr: i32, len: i32) -> i64` — evaluate and return
//!   `(ptr << 32) | len` pointing at UTF-8 decision JSON.
//! - optionally, `subjects() -> i64` — return the same packed pointer/length
//!   convention pointing at a UTF-8 JSON array of subjects the module asks
//!   the operator to grant.
//!
//! Host flow: JSON-encode the ctx (UTF-8) → `alloc(len)` → write bytes
//! into guest memory → `decide(ptr, len)` → unpack the packed `u64` →
//! read + parse the decision JSON.
//!
//! Ctx JSON mirrors [`EvalCtx`] with snake_case fields:
//! `{"wrap": "...", "joined_argv": "...", "callers": [{"name": "...",
//! "command": "..."}], "cwd": "...", "secrets": ["..."]}`.
//!
//! Decision JSON is the serde encoding of [`Decision`]:
//! `"approve"` | `"pass"` | `{"deny": "reason"}` | `{"prompt": "reason"}`.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use wasmtime::{
    Config, Engine, ExternType, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, ValType,
};

use crate::rules::EvalCtx;

/// `wasmtime::Error` is its own type (not `anyhow::Error`) and doesn't
/// implement `std::error::Error`, so `anyhow::Context` can't attach to
/// it directly. This mirrors `Context::context` for wasmtime results.
trait WasmContext<T> {
    fn wasm_context(self, msg: &'static str) -> Result<T>;
}

impl<T> WasmContext<T> for std::result::Result<T, wasmtime::Error> {
    fn wasm_context(self, msg: &'static str) -> Result<T> {
        self.map_err(|e| anyhow::Error::from(e).context(msg))
    }
}

/// Fuel budget per `decide` call. Fuel is consumed roughly per wasm
/// instruction, so this allows on the order of 10⁸ instructions — vastly
/// more than any legitimate string-matching rule needs, while an
/// infinite loop still fails in well under a second.
pub const FUEL_BUDGET: u64 = 100_000_000;

/// Cap on guest linear memory growth (64 MiB). Rules operate on a
/// kilobyte-sized ctx; hitting this means the module is broken or
/// hostile, and `memory.grow` failing surfaces as a guest-side error.
pub const MAX_GUEST_MEMORY_BYTES: usize = 64 << 20;

/// Cap on the decision JSON a guest may return. The largest legitimate
/// decision is a deny with a human-readable reason; 64 KiB is already
/// absurdly generous.
const MAX_DECISION_LEN: u32 = 64 * 1024;

/// Cap on the optional declaration JSON returned at registration/load time.
const MAX_SUBJECTS_LEN: u32 = 64 * 1024;

/// What a wasm rule returned. The serde encoding is the wire format
/// (externally tagged): `"approve"`, `"pass"`, `{"deny": "reason"}`, or
/// `{"prompt": "reason"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Auto-approve the ask without prompting.
    Approve,
    /// No opinion — fall through to declarative rules / the prompt.
    Pass,
    /// Auto-deny the ask; the string is shown to the user.
    Deny(String),
    /// Require the consent prompt: no rule may auto-approve this ask.
    ///
    /// The gap [`Pass`] leaves. `Pass` means "no opinion", so a *different*
    /// rule's approve still carries the ask through silently — which is the
    /// right default for a rule that simply does not recognise the request,
    /// and the wrong one for a rule that recognises it as needing a human.
    /// `Prompt` says the second thing: not suspicious enough to refuse
    /// outright, too consequential to release unattended.
    ///
    /// Ranked between the two it sits under: a [`Deny`] still wins (refusing
    /// is strictly stronger than asking), and it beats every approve.
    /// The string explains to the user why they are being asked.
    Prompt(String),
}

/// Wire shape of the ctx JSON — [`EvalCtx`] is authoritative, this is
/// its serialization. Field names are the ABI; renaming one breaks
/// every compiled rule.
#[derive(Serialize)]
struct CtxJson<'a> {
    wrap: &'a str,
    joined_argv: &'a str,
    callers: Vec<CallerJson<'a>>,
    cwd: &'a str,
    secrets: &'a [&'a str],
}

#[derive(Serialize)]
struct CallerJson<'a> {
    name: &'a str,
    command: &'a str,
    /// Absolute path to the executable, when the kernel would say.
    ///
    /// The one caller field a process cannot choose for itself. `name` and
    /// `command` are `comm` and argv; a rule that gates on either is gating
    /// on something the caller wrote. `null` when unresolvable.
    #[serde(skip_serializing_if = "Option::is_none")]
    exe: Option<&'a str>,
}

/// Per-store host state: just the resource limiter. No host functions
/// touch it — the guest gets no host state, that's the point.
struct HostState {
    limits: StoreLimits,
}

/// A compiled, import-vetted rule module, ready to evaluate. Compilation
/// happens once here; each [`evaluate`](Self::evaluate) call is a fresh
/// instantiation.
#[derive(Debug)]
pub struct RuleModule {
    engine: Engine,
    module: Module,
}

impl RuleModule {
    /// Compile `bytes` as a core-wasm rule module and vet it against the
    /// sandbox contract: only `env.abort` may be imported, and the ABI
    /// exports (`memory`, `alloc`, `decide`) must exist with the right
    /// types. The static checks are followed by one throwaway smoke
    /// instantiation, so instantiation-time failures — an `env.abort`
    /// with the wrong signature, a memory minimum above the sandbox cap —
    /// are also caught here. Rejecting at registration time rather than
    /// at first evaluation gives the user the error while they're still
    /// looking.
    pub fn from_binary(bytes: &[u8]) -> Result<RuleModule> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).wasm_context("create wasm engine")?;
        let module =
            Module::from_binary(&engine, bytes).wasm_context("compile wasm rule module")?;

        for import in module.imports() {
            let is_abort = import.module() == "env"
                && import.name() == "abort"
                && matches!(import.ty(), ExternType::Func(_));
            if !is_abort {
                bail!(
                    "wasm rule module imports `{}.{}`, which the sandbox does not \
                     provide — a rule may only import `env.abort`; it gets no \
                     filesystem, network, env, or clock access",
                    import.module(),
                    import.name(),
                );
            }
        }

        check_abi_exports(&module)?;

        let rule = RuleModule { engine, module };
        // Smoke instantiation: everything the static checks above can't
        // see (wrong `env.abort` signature, memory minimum above the
        // sandbox cap, a trapping start function) fails here instead of
        // at the first ask. `decide` is deliberately not called — this
        // vets the module, it doesn't evaluate anything.
        rule.instantiate()
            .context("wasm rule module failed registration-time instantiation")?;
        Ok(rule)
    }

    /// [`from_binary`](Self::from_binary) over a file on disk.
    pub fn from_file(path: &Path) -> Result<RuleModule> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("read wasm rule module: {}", path.display()))?;
        Self::from_binary(&bytes)
            .with_context(|| format!("load wasm rule module: {}", path.display()))
    }

    /// Read the module author's optional subject declaration.
    ///
    /// `None` means the module has no `subjects` export. `Some(empty)` stays
    /// distinct so registration can reject a declaration that would otherwise
    /// look like the trained-secrets guard had been deliberately disabled.
    pub fn declared_subjects(&self) -> Result<Option<BTreeSet<String>>> {
        let (mut store, instance) = self.instantiate()?;
        if instance.get_export(&mut store, "subjects").is_none() {
            return Ok(None);
        }
        let memory = instance
            .get_memory(&mut store, "memory")
            .context("rule module does not export `memory`")?;
        let subjects = instance
            .get_typed_func::<(), u64>(&mut store, "subjects")
            .wasm_context("rule module `subjects` export has wrong type")?;
        let packed = subjects
            .call(&mut store, ())
            .wasm_context("guest subjects declaration trapped")?;
        let declaration_ptr = (packed >> 32) as u32;
        let declaration_len = (packed & 0xffff_ffff) as u32;
        if declaration_len > MAX_SUBJECTS_LEN {
            bail!("guest returned an oversized subjects declaration ({declaration_len} bytes)");
        }

        let mut declaration_bytes = vec![0u8; declaration_len as usize];
        memory
            .read(&store, declaration_ptr as usize, &mut declaration_bytes)
            .context("guest returned an out-of-bounds subjects pointer")?;
        let declaration_text = std::str::from_utf8(&declaration_bytes)
            .context("guest subjects declaration is not valid UTF-8")?;
        let subjects = serde_json::from_str(declaration_text).with_context(|| {
            format!("guest returned malformed subjects JSON: {declaration_text:?}")
        })?;
        Ok(Some(subjects))
    }

    /// Run the module's `decide` against `ctx`. Any guest misbehavior
    /// (trap, abort, runaway loop, bogus decision pointer, malformed
    /// decision JSON) returns an error; the caller treats an erroring
    /// rule as "no decision" and falls through to the prompt.
    pub fn evaluate(&self, ctx: &EvalCtx) -> Result<Decision> {
        let ctx_json = serde_json::to_vec(&CtxJson {
            wrap: ctx.wrap,
            joined_argv: ctx.joined_argv,
            callers: ctx
                .callers
                .iter()
                .map(|c| CallerJson {
                    name: c.name,
                    command: c.command,
                    exe: c.exe,
                })
                .collect(),
            cwd: ctx.cwd,
            secrets: ctx.secrets,
        })
        .context("serialize rule ctx to JSON")?;
        let ctx_len = i32::try_from(ctx_json.len()).context("rule ctx JSON too large")?;

        let (mut store, instance) = self.instantiate()?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .context("rule module does not export `memory`")?;
        let alloc = instance
            .get_typed_func::<i32, u32>(&mut store, "alloc")
            .wasm_context("rule module `alloc` export has wrong type")?;
        let decide = instance
            .get_typed_func::<(u32, i32), u64>(&mut store, "decide")
            .wasm_context("rule module `decide` export has wrong type")?;

        let guest_ptr = alloc
            .call(&mut store, ctx_len)
            .wasm_context("guest alloc trapped")?;
        memory
            .write(&mut store, guest_ptr as usize, &ctx_json)
            .context("guest alloc returned an out-of-bounds buffer")?;

        let packed = decide
            .call(&mut store, (guest_ptr, ctx_len))
            .wasm_context("guest decide trapped")?;
        let decision_ptr = (packed >> 32) as u32;
        let decision_len = (packed & 0xffff_ffff) as u32;
        if decision_len > MAX_DECISION_LEN {
            bail!("guest returned an oversized decision ({decision_len} bytes)");
        }

        let mut decision_bytes = vec![0u8; decision_len as usize];
        memory
            .read(&store, decision_ptr as usize, &mut decision_bytes)
            .context("guest returned an out-of-bounds decision pointer")?;
        let decision_text =
            std::str::from_utf8(&decision_bytes).context("guest decision is not valid UTF-8")?;
        serde_json::from_str(decision_text)
            .with_context(|| format!("guest returned malformed decision JSON: {decision_text:?}"))
    }

    /// Fresh sandboxed store + instance: resource limiter, fuel budget,
    /// and the abort-only import surface. Shared by
    /// [`evaluate`](Self::evaluate) (one instance per call) and the
    /// registration-time smoke instantiation in
    /// [`from_binary`](Self::from_binary).
    fn instantiate(&self) -> Result<(Store<HostState>, wasmtime::Instance)> {
        let mut store = Store::new(
            &self.engine,
            HostState {
                limits: StoreLimitsBuilder::new()
                    .memory_size(MAX_GUEST_MEMORY_BYTES)
                    .memories(1)
                    .tables(1)
                    .instances(1)
                    .build(),
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(FUEL_BUDGET)
            .wasm_context("set fuel budget")?;

        // The entire host-provided import surface: AssemblyScript's
        // `abort(msgPtr, filePtr, line, col)`, implemented as a trap. We
        // don't decode the message (it's an AS-managed UTF-16 string);
        // the trap alone is the contract.
        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        linker
            .func_wrap(
                "env",
                "abort",
                |_msg: i32, _file: i32, _line: i32, _col: i32| {
                    std::result::Result::<(), wasmtime::Error>::Err(wasmtime::Error::msg(
                        "rule called abort()",
                    ))
                },
            )
            .wasm_context("define env.abort")?;

        let instance = linker
            .instantiate(&mut store, &self.module)
            .wasm_context("instantiate wasm rule module")?;
        Ok((store, instance))
    }
}

/// Verify the ABI exports exist with exactly the expected wasm types.
fn check_abi_exports(module: &Module) -> Result<()> {
    // `ValType` doesn't implement `PartialEq` (subtyping makes equality
    // ambiguous upstream), so shape-check by pattern instead.
    let func_shape_is =
        |ty: &ExternType, params: &[fn(&ValType) -> bool], result: fn(&ValType) -> bool| -> bool {
            match ty {
                ExternType::Func(f) => {
                    f.params().len() == params.len()
                        && f.params().zip(params).all(|(p, want)| want(&p))
                        && f.results().len() == 1
                        && f.results().all(|r| result(&r))
                }
                _ => false,
            }
        };
    let i32_ty = |v: &ValType| matches!(v, ValType::I32);
    let i64_ty = |v: &ValType| matches!(v, ValType::I64);

    let mut memory_ok = false;
    let mut alloc_ok = false;
    let mut decide_ok = false;
    let mut subjects_ok = None;
    for export in module.exports() {
        match export.name() {
            "memory" => memory_ok = matches!(export.ty(), ExternType::Memory(_)),
            "alloc" => alloc_ok = func_shape_is(&export.ty(), &[i32_ty], i32_ty),
            "decide" => decide_ok = func_shape_is(&export.ty(), &[i32_ty, i32_ty], i64_ty),
            "subjects" => subjects_ok = Some(func_shape_is(&export.ty(), &[], i64_ty)),
            _ => {}
        }
    }
    if !memory_ok {
        bail!("wasm rule module does not export `memory`");
    }
    if !alloc_ok {
        bail!("wasm rule module does not export `alloc(len: i32) -> i32`");
    }
    if !decide_ok {
        bail!("wasm rule module does not export `decide(ptr: i32, len: i32) -> i64`");
    }
    if subjects_ok == Some(false) {
        bail!(
            "wasm rule module exports `subjects` with the wrong type; \
             expected `subjects() -> i64`"
        );
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::EvalCaller;

    // Compiled from the .ts sources in tests/fixtures/wasm_rules/ by
    // rebuild.sh (checked in so `cargo test` needs no node toolchain).
    const ALWAYS_PASS: &[u8] = include_bytes!("../tests/fixtures/wasm_rules/always_pass.wasm");
    const APPROVE_IF: &[u8] = include_bytes!("../tests/fixtures/wasm_rules/approve_if.wasm");
    const NPM_PUBLISH_GUARD: &[u8] =
        include_bytes!("../../secreq-rule/examples/npm-publish-guard/rule.wasm");
    const DENY_ECHO: &[u8] = include_bytes!("../tests/fixtures/wasm_rules/deny_echo.wasm");
    const BAD_DECISION: &[u8] = include_bytes!("../tests/fixtures/wasm_rules/bad_decision.wasm");
    const ABORTS: &[u8] = include_bytes!("../tests/fixtures/wasm_rules/aborts.wasm");
    const SPINS: &[u8] = include_bytes!("../tests/fixtures/wasm_rules/spins.wasm");
    const PROMPTS: &[u8] = include_bytes!("../tests/fixtures/wasm_rules/prompts.wasm");

    // Hand-written wat fixtures, assembled at test time via the `wat`
    // dev-dependency (the production loader only ever sees binaries).
    const BAD_IMPORT_WASI: &str = include_str!("../tests/fixtures/wasm_rules/bad_import_wasi.wat");
    const NO_EXPORTS: &str = include_str!("../tests/fixtures/wasm_rules/no_exports.wat");
    const OOB_DECISION: &str = include_str!("../tests/fixtures/wasm_rules/oob_decision.wat");
    const BAD_ABORT_SIGNATURE: &str =
        include_str!("../tests/fixtures/wasm_rules/bad_abort_signature.wat");
    const HUGE_MEMORY: &str = include_str!("../tests/fixtures/wasm_rules/huge_memory.wat");
    const OVERSIZED_DECISION: &str =
        include_str!("../tests/fixtures/wasm_rules/oversized_decision.wat");

    fn ctx<'a>(
        wrap: &'a str,
        joined_argv: &'a str,
        callers: &'a [EvalCaller<'a>],
        cwd: &'a str,
        secrets: &'a [&'a str],
    ) -> EvalCtx<'a> {
        EvalCtx {
            wrap,
            joined_argv,
            callers,
            cwd,
            secrets,
        }
    }

    // ── Happy path: the three decisions ───────────────────────────────

    #[test]
    fn always_pass_module_passes() {
        let module = RuleModule::from_binary(ALWAYS_PASS).expect("load");
        let c = ctx("gh", "gh api", &[], "/x", &["GITHUB_TOKEN"]);
        assert_eq!(module.evaluate(&c).expect("evaluate"), Decision::Pass);
    }

    #[test]
    fn approve_if_approves_matching_ask() {
        let module = RuleModule::from_binary(APPROVE_IF).expect("load");
        let callers = &[
            EvalCaller {
                name: "zsh",
                command: "-zsh",
                exe: None,
            },
            EvalCaller {
                name: "Cursor",
                command: "/Applications/Cursor.app/Contents/MacOS/Cursor --psn_0_12345",
                exe: Some("/Applications/Cursor.app/Contents/MacOS/Cursor"),
            },
        ];
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            callers,
            "/home/me/x",
            &["GITHUB_TOKEN"],
        );
        assert_eq!(module.evaluate(&c).expect("evaluate"), Decision::Approve);
    }

    #[test]
    fn approve_if_passes_on_non_matching_ask() {
        let module = RuleModule::from_binary(APPROVE_IF).expect("load");
        // Right argv, but no Cursor.app anywhere in the caller chain.
        let c = ctx(
            "gh",
            "gh api --get /repos/me/x/pulls",
            &[EvalCaller {
                name: "zsh",
                command: "-zsh",
                exe: None,
            }],
            "/home/me/x",
            &["GITHUB_TOKEN"],
        );
        assert_eq!(module.evaluate(&c).expect("evaluate"), Decision::Pass);
    }

    // ── Ctx marshaling fidelity ───────────────────────────────────────

    #[test]
    fn deny_echo_round_trips_every_ctx_field() {
        // The fixture echoes the whole ctx into the deny reason, so one
        // string equality proves the JSON → guest → JSON pipeline
        // preserves every field — including quotes and non-ASCII, which
        // exercise both the host's serializer and the guest's hand-rolled
        // JSON parse/escape.
        let module = RuleModule::from_binary(DENY_ECHO).expect("load");
        let callers = &[
            EvalCaller {
                name: "zsh",
                command: "-zsh",
                exe: None,
            },
            EvalCaller {
                name: "Cursor",
                command: "/Apps/Cursor.app — β",
                exe: None,
            },
        ];
        let c = ctx(
            "gh",
            r#"gh api --jq ".name""#,
            callers,
            "/home/mé",
            &["GITHUB_TOKEN", "GH_HOST"],
        );
        let got = module.evaluate(&c).expect("evaluate");
        assert_eq!(
            got,
            Decision::Deny(
                "wrap=gh|argv=gh api --jq \".name\"|cwd=/home/mé\
                 |callers=zsh:-zsh,Cursor:/Apps/Cursor.app — β\
                 |secrets=GITHUB_TOKEN,GH_HOST"
                    .to_owned()
            )
        );
    }

    #[test]
    fn empty_callers_and_secrets_marshal_cleanly() {
        let module = RuleModule::from_binary(DENY_ECHO).expect("load");
        let c = ctx("aws", "aws s3 ls", &[], "/", &[]);
        assert_eq!(
            module.evaluate(&c).expect("evaluate"),
            Decision::Deny("wrap=aws|argv=aws s3 ls|cwd=/|callers=|secrets=".to_owned())
        );
    }

    // ── Sandbox: the import allowlist ─────────────────────────────────

    #[test]
    fn module_importing_wasi_fails_to_load() {
        let bytes = wat::parse_str(BAD_IMPORT_WASI).expect("assemble wat");
        let err = RuleModule::from_binary(&bytes).expect_err("must reject WASI import");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("wasi_snapshot_preview1") && msg.contains("sandbox"),
            "error should name the disallowed import: {msg}"
        );
    }

    #[test]
    fn asc_compiled_rule_needs_only_env_abort() {
        // The compiled fixture's only import is env.abort — proven by it
        // instantiating against our abort-only linker.
        let module = RuleModule::from_binary(ALWAYS_PASS).expect("load");
        let c = ctx("gh", "gh api", &[], "/x", &[]);
        module
            .evaluate(&c)
            .expect("instantiates with abort-only import set");
    }

    #[test]
    fn wrong_abort_signature_fails_at_registration() {
        // The static import check accepts any `env.abort` function; the
        // smoke instantiation is what catches a signature mismatch — at
        // load time, not at the first ask.
        let bytes = wat::parse_str(BAD_ABORT_SIGNATURE).expect("assemble wat");
        let err = RuleModule::from_binary(&bytes).expect_err("must reject bad abort signature");
        assert!(
            format!("{err:#}").contains("registration-time instantiation"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn memory_minimum_above_cap_fails_at_registration() {
        // 1200 pages ≈ 75 MiB, above MAX_GUEST_MEMORY_BYTES. The store
        // limiter denies the initial memory during the smoke
        // instantiation, so registration fails immediately.
        let bytes = wat::parse_str(HUGE_MEMORY).expect("assemble wat");
        let err = RuleModule::from_binary(&bytes).expect_err("must reject oversized memory");
        assert!(
            format!("{err:#}").contains("registration-time instantiation"),
            "unexpected error: {err:#}"
        );
    }

    // ── Defensive host: every failure is an error, never a panic ──────

    #[test]
    fn garbage_bytes_fail_to_load() {
        let err = RuleModule::from_binary(b"definitely not wasm").expect_err("must reject");
        assert!(format!("{err:#}").contains("compile wasm rule module"));
    }

    #[test]
    fn module_without_abi_exports_fails_to_load() {
        let bytes = wat::parse_str(NO_EXPORTS).expect("assemble wat");
        let err = RuleModule::from_binary(&bytes).expect_err("must reject");
        assert!(
            format!("{err:#}").contains("does not export"),
            "error should name the missing export: {err:#}"
        );
    }

    #[test]
    fn reads_the_optional_subject_declaration() {
        let bytes = wat::parse_str(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 1024)
              (func (export "decide") (param i32 i32) (result i64)
                i64.const 549755813894)
              (func (export "subjects") (result i64)
                i64.const 29)
              (data (i32.const 0) "[\"GITHUB_TOKEN\",\"ssh:deploy\"]")
              (data (i32.const 128) "\"pass\""))
            "#,
        )
        .expect("assemble wat");
        let module = RuleModule::from_binary(&bytes).expect("load");

        assert_eq!(
            module.declared_subjects().expect("read declaration"),
            Some(
                ["GITHUB_TOKEN".to_owned(), "ssh:deploy".to_owned()]
                    .into_iter()
                    .collect()
            )
        );
    }

    #[test]
    fn sdk_build_wrapper_exports_the_authors_subjects() {
        let module = RuleModule::from_binary(NPM_PUBLISH_GUARD).expect("load example");
        assert_eq!(
            module.declared_subjects().expect("read declaration"),
            Some(["NPM_TOKEN".to_owned()].into_iter().collect())
        );
    }

    #[test]
    fn a_module_without_subjects_has_no_declaration() {
        let module = RuleModule::from_binary(ALWAYS_PASS).expect("load");
        assert_eq!(module.declared_subjects().expect("read declaration"), None);
    }

    #[test]
    fn a_subjects_export_with_the_wrong_signature_is_rejected() {
        let bytes = wat::parse_str(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "decide") (param i32 i32) (result i64) i64.const 0)
              (func (export "subjects") (param i32) (result i64) i64.const 0))
            "#,
        )
        .expect("assemble wat");
        let err = RuleModule::from_binary(&bytes).expect_err("must reject");
        assert!(
            format!("{err:#}").contains("subjects() -> i64"),
            "error should name the malformed export: {err:#}"
        );
    }

    #[test]
    fn out_of_bounds_decision_pointer_is_an_error() {
        let bytes = wat::parse_str(OOB_DECISION).expect("assemble wat");
        let module = RuleModule::from_binary(&bytes).expect("shape-valid module loads");
        let c = ctx("gh", "gh api", &[], "/x", &[]);
        let err = module.evaluate(&c).expect_err("oob pointer must error");
        assert!(
            format!("{err:#}").contains("out-of-bounds decision pointer"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn oversized_decision_length_is_an_error() {
        // The guest claims MAX_DECISION_LEN + 1 bytes; the host must
        // refuse the length before even attempting the read.
        let bytes = wat::parse_str(OVERSIZED_DECISION).expect("assemble wat");
        let module = RuleModule::from_binary(&bytes).expect("shape-valid module loads");
        let c = ctx("gh", "gh api", &[], "/x", &[]);
        let err = module
            .evaluate(&c)
            .expect_err("oversized decision must error");
        assert!(
            format!("{err:#}").contains("oversized decision (65537 bytes)"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn malformed_decision_json_is_an_error() {
        let module = RuleModule::from_binary(BAD_DECISION).expect("load");
        let c = ctx("gh", "gh api", &[], "/x", &[]);
        let err = module.evaluate(&c).expect_err("bad decision must error");
        assert!(
            format!("{err:#}").contains("malformed decision JSON"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn guest_abort_is_a_clean_error() {
        let module = RuleModule::from_binary(ABORTS).expect("load");
        let c = ctx("gh", "gh api", &[], "/x", &[]);
        let err = module.evaluate(&c).expect_err("abort must error");
        assert!(
            format!("{err:#}").contains("guest decide trapped"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn runaway_guest_is_stopped_by_fuel() {
        let module = RuleModule::from_binary(SPINS).expect("load");
        let c = ctx("gh", "gh api", &[], "/x", &[]);
        let err = module
            .evaluate(&c)
            .expect_err("infinite loop must be interrupted");
        assert!(
            format!("{err:#}").to_lowercase().contains("fuel"),
            "expected a fuel-exhaustion trap: {err:#}"
        );
    }

    // ── Decision wire format ──────────────────────────────────────────

    #[test]
    fn decision_json_encoding_matches_the_documented_wire_format() {
        assert_eq!(
            serde_json::from_str::<Decision>(r#""approve""#).expect("parse"),
            Decision::Approve
        );
        assert_eq!(
            serde_json::from_str::<Decision>(r#""pass""#).expect("parse"),
            Decision::Pass
        );
        assert_eq!(
            serde_json::from_str::<Decision>(r#"{"deny":"nope"}"#).expect("parse"),
            Decision::Deny("nope".to_owned())
        );
        // And the encode direction, since Phase C will surface decisions
        // in tooling output.
        assert_eq!(
            serde_json::to_string(&Decision::Deny("nope".to_owned())).expect("encode"),
            r#"{"deny":"nope"}"#
        );
    }

    /// The decision that neither approves nor denies: it removes the option
    /// of an auto-approve and hands the ask to the user, with a reason.
    #[test]
    fn a_module_can_mandate_the_consent_prompt() {
        let module = RuleModule::from_binary(PROMPTS).expect("compile");
        let ctx = crate::rules::EvalCtx {
            wrap: "npm",
            joined_argv: "npm publish",
            callers: &[],
            cwd: "/x",
            secrets: &["NPM_TOKEN"],
        };
        assert_eq!(
            module.evaluate(&ctx).expect("evaluate"),
            Decision::Prompt("needs a human for wrap=npm".to_owned())
        );
    }
}
