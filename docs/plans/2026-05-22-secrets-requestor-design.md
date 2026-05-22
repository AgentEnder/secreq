# Secrets Requestor — Design

> Status: **Design / brainstorm complete.** Working title only — name TBD (`secreq`, `vouch`, `keyrunner`, …).
> Date: 2026-05-22

## 1. One-line pitch

**`op run`, but for every secret store you own** — a local-first CLI that resolves
secrets from multiple providers (macOS Keychain, 1Password `op`, LastPass `lpass`,
`pass`, corporate Vault, …) based on a declarative manifest, shows a
provenance-aware consent prompt, injects them as env vars, and runs your command
inside a PTY that masks any secret that leaks to stdout/stderr.

## 2. Motivation

- **Kill `.env` files.** The author keeps secrets in plaintext `.env` files and
  wants them off disk, in real stores, without the migration pain that every
  existing tool imposes.
- **One tool for personal *and* work.** Secrets live across different stores
  (Keychain for personal, `op`/Vault for work). No single existing tool reads
  more than one local store *and* lets you mix them in one config.
- **Awareness.** When something grabs a secret, the author wants to *know what is
  asking* and why — with enough provenance to make an informed allow/deny.

## 3. Goals / Non-goals

### Goals
- Declarative manifest of needed secrets, resolved from **mixed providers in one config**.
- **PTY + multi-provider output masking** — redact *any* resolved secret value
  that leaks to the child's output, regardless of which store it came from.
- **Provenance-aware consent ceremony** before secrets are released.
- **Two-tier providers**: declarative CLI wrappers (no code) + Wasm plugins (code).
- Providers are **capability descriptors** (read + write + field schema), so
  `import`/`add` can store secrets, not just read them.
- **First-class `.env` migration** (`import`) — the primary onboarding path.
- Project-scope **and** user-scope manifests, merged.
- Secrets held only in the Rust core, **zeroized**, never in a GC heap.

### Non-goals (YAGNI — explicitly out)
- **No secret storage backend of our own.** We read/write *your* existing stores.
- **No daemon / broker.** Simple wrapper; consent gates the fetch, not later use.
  (Considered ssh-agent-style brokering; rejected — overkill for awareness+audit.)
- **No live `.env` read interception.** macOS fs-event restrictions make
  transparent read-time substitution infeasible. Migration is explicit (`import`).
- **No cloud SaaS, no rotation / sync / drift detection.** (This is teller's
  scope creep, and a maintenance sink.)
- **Not competing with `op run` on 1Password-only workflows.** We delegate to
  `op` and win only on the multi-provider union.

## 4. Competitive landscape

The space is **crowded but stratified**. Nobody occupies the exact square:
*declarative + multi-provider + **local** stores + exec-wrapper + maintained*.

| Tool | Shape | Backends | Gap vs. us |
|---|---|---|---|
| **teller** (tellerops) | declarative + multi-provider + `run --` | Cloud only (Vault, Consul, AWS, GCP, dotenv) | **No local stores; effectively dead** (last push Jul 2024). v1 had ~21 providers; the v2 Rust rewrite **dropped to 6**, shedding 1Password, LastPass, gopass, KeePass, Azure, GitHub, Doppler, Vercel — exactly the local/personal ones. |
| **summon** (CyberArk) | pluggable provider model + `run --` | Conjur, AWS, keyring; **no 1Password/LastPass** | **One provider per run** (can't mix in one config); thin/aging ecosystem; CyberArk-centric. Alive, though. |
| **envchain** | Keychain → env → exec | macOS Keychain / gnome-keyring **only** | No config file (imperative namespaces); single backend. |
| **`op run` / `op inject`** | exec wrapper w/ `op://` refs; **output masking** | 1Password **only** | Single vendor. *Best-in-class on its turf* (see §4.1). |
| **aws-vault** | exec wrapper; pluggable *secure storage* | AWS creds only | Scoped to AWS; no arbitrary-secret config. |
| **gopass / pass `env`** | store → env → exec | pass store only | Single backend; no manifest. |
| **sops / dotenvx** | encrypted file → env → exec | encryption keys, not live stores | Secrets live in repo; no Keychain/`op`/`lpass` fetch. |
| **doppler / infisical `run`** | exec wrapper | their own SaaS | Single proprietary cloud; account required; not local-first. |
| **direnv** | per-dir shell env (+ ad-hoc integrations) | none native | Mutates interactive shell (not a scoped `run --`); integrations are bash glue. |
| **Vault agent / envconsul** | process supervisor | Vault/Consul only | Heavyweight; server/CI-oriented. |

### 4.1 What `op run` does that we won't beat (and how we relate)
- **Output masking** of 1Password secrets — we *generalize* this across all
  providers, but won't out-engineer 1Password on 1Password alone.
- **Native biometric unlock / account UX** — our `op` provider shells out to
  `op read`, so we **inherit** Touch ID + session for free, but `op read` does
  **not** mask (only `op run` does). So "1Password through us" = `op read` +
  *our* PTY masking + our consent prompt.
- **Deep 1Password data model** (files, SSH keys, sections, multi-account) — we
  pass through; we won't model it richer than `op`.
- **Institutional trust** — for a pure-1Password security team, our process is an
  extra party holding decrypted secrets; `op run` is the safer first-party choice.

### 4.2 The wedge (what we cover that they don't)
1. **Local stores as first-class, mixable in one config** (Keychain *and* `op`
   *and* `lpass` together) — nobody does this.
2. **Multi-provider output masking** in one PTY — a strict superset of `op run`'s
   single-vendor masking; impossible for any single-backend tool.
3. **Provenance-aware consent ceremony** — no existing tool shows *what is asking*
   before releasing secrets.
4. **Capability-descriptor providers** (read + write + fields) → real `.env`
   migration, not just resolution.

### 4.3 Honest risk
Every *single-provider* slice is owned and well-built. **summon already does
pluggable providers and is alive.** Our value exists *only* in the multi-provider,
local-first union + masking + consent. If we don't nail 1Password + Keychain
together with mixed configs and masking, this is just "teller again."

## 5. Architecture

- **Rust core** — owns secrets end-to-end (resolve → consent → exec) so values can
  be `zeroize`d and never cross into a GC heap. Required anyway for native store
  access: macOS Keychain (`security-framework`), Linux Secret Service, Windows
  Credential Vault.
- **PTY** via `portable-pty` (wezterm) for interactive fidelity + output masking.
- **CLI/TUI** via `clap` + `ratatui` for the consent prompt.
- **Wasm host** via `wasmtime` for Tier-2 plugins (sandboxed — a plugin only gets
  capabilities we grant; good fit for a secrets tool).
- **TS launcher: optional/deferred.** Pure Rust to start (distribute via Homebrew
  + `cargo install` + prebuilt GitHub releases). An `npm i -g` wrapper that pulls
  the prebuilt binary can be added later for git-switchboard-style ergonomics — it
  must stay a *thin shim* (arg routing only) so secrets never enter Node.

### Why not pure TS / Bun
Native Keychain / Secret Service / Credential Vault access and secret zeroization
rule out a GC'd runtime for the core. (Bun was attractive — JS plugins free, one
language, matches git-switchboard — but the security + native-API requirements win.)

### Why Wasm plugins (not embedded JS)
A JS engine in the Rust core is heavy; `wasmtime` is lighter, sandboxed, and
language-agnostic (plugin authors target Wasm from Rust/Go/AssemblyScript/Javy).

## 6. Config model

A `secrets.json5` manifest. **Top-level keys are groups**; the reserved
`providers` key defines schemes. Settings use a `$` prefix (env vars can't start
with `$`, so no collision with secret names).

```json5
{
  // a group: a named, selectable subset with inheritable settings
  database: {
    $provider: "op",            // group-default provider
    $reason: "Database access", // shown in the consent prompt
    DATABASE_URL: "secret://keychain/myapp/db_url", // overrides $provider
    DB_PASSWORD: {
      description: "Prod read-replica password",
      required: true,
      ref: "Work/Postgres/password", // uses group $provider (op)
    },
  },
  stripe: {
    STRIPE_KEY: "secret://op/Work/Stripe/api_key",
  },

  providers: {
    // Tier-1 declarative: read + write capability descriptors
    op: {
      read: ["op", "read", "op://{locator}"],
      write: {
        command: ["op", "item", "create", "--category={category}",
                  "--title={title}", "--vault={vault}", "--url={url}",
                  "--tags={tags}", "{field}={value}"],
        fields: {
          category: { default: "login" },
          title:    { required: true },
          vault:    { required: true },
          url:      { optional: true },
          tags:     { optional: true },
          field:    { default: "password" },
        },
        value: "{value}",                // how the secret is supplied (OPEN: stdin?)
        locator: "{vault}/{title}/{field}", // how to build the read-ref afterward
      },
    },
    keychain: {
      read:  ["security", "find-generic-password", "-w", "-s", "{locator}"],
      write: {
        command: ["security", "add-generic-password", "-s", "{service}",
                  "-a", "{account}", "-w", "{value}"],
        fields: { service: { required: true }, account: { required: true } },
        locator: "{service}",
      },
    },
    lastpass: { read: ["lpass", "show", "--password", "{locator}"] },
    // Tier-2: { wasm: "./providers/vault.wasm" }  — exports read/write, declares fields
  },
}
```

### Reference syntax
`secret://<provider>/<locator>`. `<provider>` matches a `providers` key;
`<locator>` is substituted into the read template (Tier-1) or passed to the Wasm
`read` (Tier-2). The same syntax works **inline in ambient env** (see §7).

### Groups
- **Selectable subsets**: `run --only database,stripe -- <cmd>` resolves a slice.
  Default = all groups. Narrower selection ⇒ narrower consent prompt.
- **Inheritable settings** (`$provider`, `$reason`, `$required`, …) apply to all
  secrets in the group; per-secret values override.

### Scope & merge
- **User manifest**: `~/.config/<tool>/secrets.json5` (personal secrets).
- **Project manifest**: `./secrets.json5` (project secrets, committable — refs only).
- **Merge**: union of secrets; **project wins** on key conflict. `providers` merge,
  project may override a scheme.

## 7. Resolution model (union)

`run` resolves the **union** of:
1. **Manifest-declared** secrets (project ∪ user, filtered by `--only`), typed,
   with metadata; and
2. **Ambient-env refs** — any inherited env var whose *value* matches
   `secret://...` is resolved in place (op-run parity; supports `.env`-with-refs
   and ad-hoc usage).

Both resolve through the same provider definitions. Manifest metadata applies to
matching keys.

## 8. `run` flow & consent ceremony

```
run [--only db,stripe] -- <cmd>
  1. Build request set: union(manifest∣--only, ambient secret:// refs)
  2. Provenance: walk parent process tree (name, pid, argv, exe path)
  3. Consent prompt (ratatui): the command, each secret (NAME, provider,
     group $reason — NEVER the value), the caller chain.
     → [a]pprove / [d]eny / approve & [r]emember
  4. Resolve via providers (each may sub-prompt: Keychain Touch ID,
     op biometric). Values held in Rust, zeroize-on-drop.
  5. Allocate PTY; exec child with injected env; stream output through
     the multi-provider masking filter; forward signals/resize.
  6. Append audit record (ts, cwd, command, caller chain, secret NAMES
     granted, decision). Values never logged.
```

### Masking — known hard parts (eyes open)
- **Split across reads**: a secret can straddle two buffer chunks → sliding-window
  matcher keeping a tail buffer ≥ longest secret.
- **Non-TTY / piped output**: no PTY allocated, but still stream-and-mask.
- **Perf / binary output**: scan cheaply; don't corrupt binary streams.

### Prompt fatigue
"Approve & remember" caches a decision keyed by `(manifest hash, command, cwd)`
with a TTL (default 8h, configurable; `--no-remember` to force a prompt).

## 9. CLI surface

- `run [--only g,…] [--no-remember] -- <cmd>` — main path.
- `secret request <ref|NAME> [reason]` — one-off resolve to stdout, same consent.
- `init` — scaffold `secrets.json5`.
- `import <.env>` — **migration** (§10).
- `add <NAME> <ref>` — add/store a secret (uses provider write capability).
- `check` / `doctor` — validate manifest, confirm provider CLIs exist, dry-run
  resolution (reports missing/required; prints no values).
- `list` — declared secrets + provenance; no values.

## 10. `.env` migration (`import`) — primary onboarding

For each `KEY=value` in the `.env`:
1. Choose a provider (prompt; default from a flag or group `$provider`).
2. Prompt for that provider's declared `write.fields`.
3. Run the provider's `write.command`, supplying the value per `write.value`.
4. Construct the read ref via `write.locator`; add a manifest entry.
5. Scrub the line from `.env` (rewrite the file).

Result: `.env` emptied of secrets, values now in real stores, manifest holds refs.
Powered entirely by provider capability descriptors — no hardcoded per-store logic.

## 11. Security / threat model

- **Posture: awareness + audit**, not a hardened isolation boundary. Consent gates
  the *fetch*; once injected as env vars, code in the child can read them (and
  `ps eww` / `/proc/<pid>/environ` may expose them). This is an accepted limit.
- **Mitigations beyond the env-var default**: PTY output masking; values held only
  in zeroizing Rust memory; audit log of every grant; Wasm-sandboxed plugins;
  consent prompt with provenance. (File/stdin delivery and `!file`-style refs are
  possible *future* hardening, not v1.)
- **Never logged / never displayed**: secret values (only NAMES appear in prompts
  and the audit log).

## 12. Open questions (resolve during planning)
- **Write value delivery**: arg placeholder (`{value}`) vs stdin vs
  provider-generated. stdin is safer (keeps secrets out of argv / `ps`).
- **Read-locator construction** from write inputs — confirm the templating story.
- **Wasm plugin ABI**: exact exported functions (`read`, `write`,
  `describe_fields`?), host capabilities granted, and how secrets cross the
  Wasm boundary safely.
- **Audit log location/format** (`~/.local/state/<tool>/audit.log`? JSONL?).
- **Name** of the tool.
- **TS npm wrapper**: ship now or defer? (Recommend defer.)

## 13. Phasing (suggested)
1. **MVP**: Rust core; JSON5 manifest (project scope); Tier-1 `read` providers
   (keychain, op, lpass, pass); `run` with consent prompt + env injection + PTY
   masking; `check`/`list`.
2. **Migration**: provider `write` capabilities; `import`; `add`; user-scope
   manifest + merge.
3. **Plugins**: Wasm (`wasmtime`) Tier-2 providers.
4. **Polish**: remember-TTL, audit log, distribution (Homebrew/cargo/releases),
   optional npm wrapper.
