// The evaluation context handed to a rule's `decide`. Mirrors the host's
// `EvalCtx` in `src/rules.rs` (the Rust side is authoritative); JSON field
// names are snake_case on the wire, camelCase here.

/** One entry of the caller chain, nearest-first. */
export class Caller {
  /** Short process name (executable basename, e.g. `zsh`, `Cursor`). */
  name: string = "";
  /** Full joined command line of the caller. */
  command: string = "";
}

/** Everything a rule can see about one live ask. */
export class RuleCtx {
  /** The wrap name being asked for (e.g. `gh`). */
  wrap: string = "";
  /** Joined argv of the wrapped command (e.g. `gh api --get /repos/x`). */
  joinedArgv: string = "";
  /** Caller chain, nearest-first. */
  callers: Caller[] = [];
  /** Working directory of the requesting process. */
  cwd: string = "";
  /** Names of the secrets (env vars) the ask would release. */
  requestedSecretNames: string[] = [];
}
