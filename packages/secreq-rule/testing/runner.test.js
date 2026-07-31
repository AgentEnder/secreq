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
  assert.equal(sandboxPosture.memoryConstrainedDuringCall, false);
  assert.equal(sandboxPosture.importSignaturesChecked, false);
  assert.deepEqual(sandboxPosture.imports, ['env.abort']);
});

test('context encoder rejects misspelled ABI fields instead of silently dropping them', () => {
  assert.throws(
    () => contextJson({ wrap: 'gh', argv: 'gh api /user' }),
    /rule context has unknown key\(s\): argv/,
  );
  assert.throws(
    () => contextJson({ callers: [{ name: 'node', argv: 'node tool' }] }),
    /caller has unknown key\(s\): argv/,
  );
});

test('compiled runner gives host-shaped errors for guest aborts and invalid decisions', () => {
  assert.throws(
    () => runRule(path.join(FIXTURES, 'aborts.wasm'), { wrap: 'gh' }),
    /rule decide failed: rule called abort\(\)/,
  );
  assert.throws(
    () => runRule(path.join(FIXTURES, 'bad_decision.wasm'), { wrap: 'gh' }),
    /unrecognized decision JSON: {"maybe":"perhaps"}/,
  );
});

test('compiled runner names the required decide signature', () => {
  // memory + alloc(i32)->i32 + deliberately-wrong decide(i32,i32)->i32.
  const wrongDecideSignature = Uint8Array.from([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x02, 0x60, 0x01, 0x7f, 0x01, 0x7f,
    0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x03, 0x03, 0x02, 0x00, 0x01, 0x05, 0x03, 0x01, 0x00, 0x01,
    0x07, 0x1b, 0x03, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x05, 0x61, 0x6c, 0x6c,
    0x6f, 0x63, 0x00, 0x00, 0x06, 0x64, 0x65, 0x63, 0x69, 0x64, 0x65, 0x00, 0x01, 0x0a, 0x0b, 0x02,
    0x04, 0x00, 0x41, 0x00, 0x0b, 0x04, 0x00, 0x41, 0x00, 0x0b,
  ]);

  assert.throws(
    () => runRule(wrongDecideSignature, {}),
    /rule decide must have signature decide\(i32, i32\) -> i64/,
  );
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
