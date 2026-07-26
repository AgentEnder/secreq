// The evaluation context handed to a rule's `decide`. Mirrors the host's
// `EvalCtx` in `src/rules.rs` (the Rust side is authoritative); JSON field
// names are snake_case on the wire, camelCase here.

/** One entry of the caller chain, nearest-first. */
export class Caller {
  /**
   * Short process name (`comm`, e.g. `zsh`, `Cursor`).
   *
   * **Self-reported.** A process sets this on itself — one
   * `prctl(PR_SET_NAME)` on Linux, or simply being a file with that name on
   * macOS. Gate on `exe` when it matters who is really calling.
   */
  name: string = '';
  /**
   * Full joined command line of the caller.
   *
   * **Self-reported**, same as `name`: a process chooses its own argv.
   */
  command: string = '';
  /**
   * Absolute path to the caller's executable, or `''` when the kernel would
   * not say (short-lived processes, some platforms).
   *
   * The one caller field the process cannot choose for itself, so it is the
   * one worth gating on. Treat `''` as "unknown", not as "no match".
   */
  exe: string = '';
}

/** Everything a rule can see about one live ask. */
export class RuleCtx {
  /** The wrap name being asked for (e.g. `gh`). */
  wrap: string = '';
  /** Joined argv of the wrapped command (e.g. `gh api --get /repos/x`). */
  joinedArgv: string = '';
  /** Caller chain, nearest-first. */
  callers: Caller[] = [];
  /** Working directory of the requesting process. */
  cwd: string = '';
  /**
   * What the ask would release, by name. Env-var names for a wrap run
   * (`GITHUB_TOKEN`); for an SSH sign, the single identity `ssh:<key_id>`
   * — a sign resolves no secrets, but it still asks for the use of a key,
   * and naming that subject is what lets a rule be scoped to it.
   */
  secrets: string[] = [];
}
