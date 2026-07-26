// The decision a rule returns. Construct via `approve()` / `pass()` /
// `deny(reason)` / `prompt(reason)` — never `new Decision(...)` directly.

export enum DecisionKind {
  Approve,
  Pass,
  Deny,
  Prompt,
}

/** Opaque decision value; see `approve` / `pass` / `deny`. */
export class Decision {
  kind: DecisionKind;
  reason: string;

  constructor(kind: DecisionKind, reason: string) {
    this.kind = kind;
    this.reason = reason;
  }
}

/** Auto-approve the ask without prompting. */
export function approve(): Decision {
  return new Decision(DecisionKind.Approve, '');
}

/** No opinion — fall through to declarative rules / the consent prompt. */
export function pass(): Decision {
  return new Decision(DecisionKind.Pass, '');
}

/** Auto-deny the ask. `reason` is shown to the user. */
export function deny(reason: string): Decision {
  return new Decision(DecisionKind.Deny, reason);
}

/**
 * Require the consent prompt: no rule may auto-approve this ask.
 *
 * The gap `pass()` leaves. `pass()` means "no opinion", so another rule's
 * approve still carries the ask through silently — right for a request your
 * rule does not recognise, wrong for one it recognises as needing a human.
 * `prompt()` says the second thing: not suspicious enough to refuse, too
 * consequential to release unattended.
 *
 * Ranks between the two it sits under. A `deny()` from any rule still wins,
 * and this beats every approve.
 *
 * `reason` is shown to the user, so write it as the answer to "why am I
 * being asked?" — e.g. `prompt('publishing to a registry you have not used
 * before')`.
 */
export function prompt(reason: string): Decision {
  return new Decision(DecisionKind.Prompt, reason);
}
