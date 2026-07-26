// The decision a rule returns. Construct via `approve()` / `pass()` /
// `deny(reason)` — never `new Decision(...)` directly.

export enum DecisionKind {
  Approve,
  Pass,
  Deny,
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
