// Test-only AssemblyScript helpers. Import from `secreq-rule/testing/assembly`
// in as-pect specs; the runtime rule entry point remains dependency-free.

import { Caller, RuleCtx } from '../assembly/ctx';
import { Decision, DecisionKind } from '../assembly/decision';

/** Build one caller-chain entry without repetitive field assignment. */
export function caller(name: string, command: string = '', exe: string = ''): Caller {
  const value = new Caller();
  value.name = name;
  value.command = command;
  value.exe = exe;
  return value;
}

/** Build the complete context shape a rule sees. */
export function ruleCtx(
  wrap: string,
  joinedArgv: string,
  cwd: string = '',
  callers: Caller[] = [],
  subjects: string[] = [],
): RuleCtx {
  const value = new RuleCtx();
  value.wrap = wrap;
  value.joinedArgv = joinedArgv;
  value.cwd = cwd;
  value.callers = callers;
  value.secrets = subjects;
  return value;
}

/** Expected decision for a table-driven rule case. */
export class ExpectedDecision {
  constructor(
    public kind: DecisionKind,
    public reason: string = '',
  ) {}
}

export function expectApprove(): ExpectedDecision {
  return new ExpectedDecision(DecisionKind.Approve);
}

export function expectPass(): ExpectedDecision {
  return new ExpectedDecision(DecisionKind.Pass);
}

export function expectPrompt(reason: string): ExpectedDecision {
  return new ExpectedDecision(DecisionKind.Prompt, reason);
}

export function expectDeny(reason: string): ExpectedDecision {
  return new ExpectedDecision(DecisionKind.Deny, reason);
}

/** Assert both decision kind and, for prompt/deny, its user-facing reason. */
export function assertDecision(
  actual: Decision,
  expected: ExpectedDecision,
  label: string = 'decision',
): void {
  // TypeScript does not know AssemblyScript's built-in `assert`; as-pect/asc do.
  // @ts-expect-error AssemblyScript standard-library global
  assert(actual.kind == expected.kind, label + ': unexpected decision kind');
  if (expected.kind == DecisionKind.Deny || expected.kind == DecisionKind.Prompt) {
    // @ts-expect-error AssemblyScript standard-library global
    assert(actual.reason == expected.reason, label + ': unexpected decision reason');
  }
}
