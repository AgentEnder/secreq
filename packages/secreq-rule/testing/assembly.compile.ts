// Compile-only ABI guard. Nx runs asc over this entry so the test helpers are
// verified as AssemblyScript, not merely accepted by TypeScript tooling.

import { approve, deny, pass, prompt } from '../assembly';
import {
  ExpectedDecision,
  assertDecision,
  caller,
  expectApprove,
  expectDeny,
  expectPass,
  expectPrompt,
  ruleCtx,
} from './assembly';

export function compileTestingHelpers(): i32 {
  const editor = caller('Cursor', 'cursor /work', '/Applications/Cursor.app/Contents/MacOS/Cursor');
  const shell = caller('zsh', '-zsh');
  const ctx = ruleCtx(
    'gh',
    'gh api --field body=line one\nline two',
    '/work',
    [editor, shell],
    ['GITHUB_TOKEN', 'GH_HOST'],
  );
  const expected: ExpectedDecision[] = [
    expectApprove(),
    expectPass(),
    expectPrompt('human required'),
    expectDeny('blocked'),
  ];
  assertDecision(approve(), expected[0], 'approve');
  assertDecision(pass(), expected[1], 'pass');
  assertDecision(prompt('human required'), expected[2], 'prompt');
  assertDecision(deny('blocked'), expected[3], 'deny');
  return ctx.callers.length + ctx.secrets.length;
}
