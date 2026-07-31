// as-pect spec for the npm-publish-guard rule. Runs with `npm test`.
//
// These tests exercise `decide` directly, compiled to wasm by as-pect —
// the same compiler and language semantics as the deployed module, minus
// the secreq ABI glue (which `secreq-rule-build` generates and secreq's
// own test suite covers). secreq never runs this spec: you test locally,
// secreq only ever loads the compiled `rule.wasm`.

import {
  assertDecision,
  caller,
  expectApprove,
  expectDeny,
  expectPass,
  ruleCtx,
} from 'secreq-rule/testing/assembly';
import { decide } from '../rule';

const shell = [caller('zsh', '-zsh', '/bin/zsh')];

describe('npm-publish-guard', () => {
  it('approves a publish from inside the publish root', () => {
    assertDecision(
      decide(ruleCtx('npm', 'npm publish', '/home/me/oss/my-lib', shell, ['NPM_TOKEN'])),
      expectApprove(),
    );
  });

  it('approves at the publish root itself', () => {
    assertDecision(
      decide(ruleCtx('npm', 'npm publish --access public', '/home/me/oss', shell, ['NPM_TOKEN'])),
      expectApprove(),
    );
  });

  it('passes on a publish from outside the publish root', () => {
    assertDecision(
      decide(ruleCtx('npm', 'npm publish', '/tmp/scratch-clone', shell, ['NPM_TOKEN'])),
      expectPass(),
    );
  });

  it('does not treat a prefix-sibling directory as inside the root', () => {
    // /home/me/oss-scratch shares the string prefix but not the subtree.
    assertDecision(
      decide(ruleCtx('npm', 'npm publish', '/home/me/oss-scratch', shell, ['NPM_TOKEN'])),
      expectPass(),
    );
  });

  it('passes on npm commands that are not a publish', () => {
    assertDecision(
      decide(ruleCtx('npm', 'npm install', '/home/me/oss/my-lib', shell, ['NPM_TOKEN'])),
      expectPass(),
    );
  });

  it('does not match `npm publish-please` on the prefix', () => {
    assertDecision(
      decide(ruleCtx('npm', 'npm publish-please', '/home/me/oss/my-lib', shell, ['NPM_TOKEN'])),
      expectPass(),
    );
  });

  it('passes on other wraps entirely', () => {
    assertDecision(
      decide(ruleCtx('gh', 'gh api /user', '/home/me/oss/my-lib', shell, ['NPM_TOKEN'])),
      expectPass(),
    );
  });

  it('denies a publish from an agent session, even inside the root', () => {
    assertDecision(
      decide(
        ruleCtx(
          'npm',
          'npm publish',
          '/home/me/oss/my-lib',
          [caller('node', 'node /usr/local/bin/claude'), caller('zsh', '-zsh')],
          ['NPM_TOKEN'],
        ),
      ),
      expectDeny('npm publish from an AI-agent session is never auto-approved (caller: node)'),
    );
  });

  it('finds the agent anywhere in the caller chain, not just nearest', () => {
    assertDecision(
      decide(
        ruleCtx(
          'npm',
          'npm publish',
          '/home/me/oss/my-lib',
          [
            caller('zsh', '-zsh'),
            caller('Claude', '/Applications/Claude.app/Contents/MacOS/Claude'),
          ],
          ['NPM_TOKEN'],
        ),
      ),
      expectDeny('npm publish from an AI-agent session is never auto-approved (caller: Claude)'),
    );
  });
});
