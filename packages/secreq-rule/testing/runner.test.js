'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');

const { contextJson, runCases, runRule, sandboxPosture } = require('./index.js');

const FIXTURES = path.join(__dirname, '..', '..', 'secreq', 'tests', 'fixtures', 'wasm_rules');

test('compiled runner decodes approve, pass, prompt, and deny reasons', () => {
  const approveIf = path.join(FIXTURES, 'approve_if.wasm');
  const caller = {
    name: 'Cursor',
    command: '/Applications/Cursor.app/Contents/MacOS/Cursor',
    exe: '/Applications/Cursor.app/Contents/MacOS/Cursor',
  };
  assert.deepEqual(
    runCases(approveIf, [
      {
        name: 'positive',
        context: { wrap: 'gh', joinedArgv: 'gh api --get /user', callers: [caller] },
        expected: 'approve',
      },
      {
        name: 'pass',
        context: { wrap: 'gh', joinedArgv: 'gh repo delete x', callers: [caller] },
        expected: 'pass',
      },
    ]),
    ['approve', 'pass'],
  );
  assert.deepEqual(runRule(path.join(FIXTURES, 'prompts.wasm'), { wrap: 'npm' }), {
    prompt: 'needs a human for wrap=npm',
  });
  assert.deepEqual(
    runRule(path.join(FIXTURES, 'deny_echo.wasm'), {
      wrap: 'gh',
      joinedArgv: 'gh api --field body=line one\nline two',
      cwd: '/work/project',
      callers: [caller, { name: 'zsh', command: '-zsh' }],
      subjects: ['GITHUB_TOKEN', 'GH_HOST'],
    }),
    {
      deny:
        'wrap=gh|argv=gh api --field body=line one\nline two|cwd=/work/project' +
        '|callers=Cursor:/Applications/Cursor.app/Contents/MacOS/Cursor,zsh:-zsh' +
        '|secrets=GITHUB_TOKEN,GH_HOST',
    },
  );
});

test('context encoder uses the real snake_case ABI and preserves multiline argv', () => {
  assert.deepEqual(
    contextJson({
      wrap: 'brain',
      joinedArgv: 'brain task add\n--body line',
      callers: [{ name: 'node', command: 'node tool', exe: '/usr/bin/node' }],
      cwd: '/work',
      subjects: ['A', 'B'],
    }),
    {
      wrap: 'brain',
      joined_argv: 'brain task add\n--body line',
      callers: [{ name: 'node', command: 'node tool', exe: '/usr/bin/node' }],
      cwd: '/work',
      secrets: ['A', 'B'],
    },
  );
  assert.equal(sandboxPosture.fuelMetered, false);
  assert.deepEqual(sandboxPosture.imports, ['env.abort']);
});

test('table failures name every case', () => {
  assert.throws(
    () =>
      runCases(path.join(FIXTURES, 'always_pass.wasm'), [
        { name: 'first policy row', context: {}, expected: 'approve' },
        { name: 'second policy row', context: {}, expected: { deny: 'no' } },
      ]),
    (error) => {
      assert.equal(error.errors.length, 2);
      assert.match(error.errors[0].message, /first policy row/);
      assert.match(error.errors[1].message, /second policy row/);
      return true;
    },
  );
});
