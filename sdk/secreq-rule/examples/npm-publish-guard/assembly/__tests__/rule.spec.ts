// as-pect spec for the npm-publish-guard rule. Runs with `npm test`.
//
// These tests exercise `decide` directly, compiled to wasm by as-pect —
// the same compiler and language semantics as the deployed module, minus
// the secreq ABI glue (which `secreq-rule-build` generates and secreq's
// own test suite covers). secreq never runs this spec: you test locally,
// secreq only ever loads the compiled `rule.wasm`.

import { RuleCtx, Caller, DecisionKind } from "secreq-rule";
import { decide } from "../rule";

function caller(name: string, command: string): Caller {
  const c = new Caller();
  c.name = name;
  c.command = command;
  return c;
}

function ctx(wrap: string, joinedArgv: string, cwd: string): RuleCtx {
  const c = new RuleCtx();
  c.wrap = wrap;
  c.joinedArgv = joinedArgv;
  c.cwd = cwd;
  c.callers = [caller("zsh", "-zsh")];
  c.requestedSecretNames = ["NPM_TOKEN"];
  return c;
}

describe("npm-publish-guard", () => {
  it("approves a publish from inside the publish root", () => {
    const d = decide(ctx("npm", "npm publish", "/home/me/oss/my-lib"));
    expect(d.kind).toBe(DecisionKind.Approve);
  });

  it("approves at the publish root itself", () => {
    const d = decide(ctx("npm", "npm publish --access public", "/home/me/oss"));
    expect(d.kind).toBe(DecisionKind.Approve);
  });

  it("passes on a publish from outside the publish root", () => {
    const d = decide(ctx("npm", "npm publish", "/tmp/scratch-clone"));
    expect(d.kind).toBe(DecisionKind.Pass);
  });

  it("does not treat a prefix-sibling directory as inside the root", () => {
    // /home/me/oss-scratch shares the string prefix but not the subtree.
    const d = decide(ctx("npm", "npm publish", "/home/me/oss-scratch"));
    expect(d.kind).toBe(DecisionKind.Pass);
  });

  it("passes on npm commands that are not a publish", () => {
    const d = decide(ctx("npm", "npm install", "/home/me/oss/my-lib"));
    expect(d.kind).toBe(DecisionKind.Pass);
  });

  it("does not match `npm publish-please` on the prefix", () => {
    const d = decide(ctx("npm", "npm publish-please", "/home/me/oss/my-lib"));
    expect(d.kind).toBe(DecisionKind.Pass);
  });

  it("passes on other wraps entirely", () => {
    const d = decide(ctx("gh", "gh api /user", "/home/me/oss/my-lib"));
    expect(d.kind).toBe(DecisionKind.Pass);
  });

  it("denies a publish from an agent session, even inside the root", () => {
    const c = ctx("npm", "npm publish", "/home/me/oss/my-lib");
    c.callers = [
      caller("node", "node /usr/local/bin/claude"),
      caller("zsh", "-zsh"),
    ];
    const d = decide(c);
    expect(d.kind).toBe(DecisionKind.Deny);
    expect(d.reason).toBe(
      "npm publish from an AI-agent session is never auto-approved (caller: node)",
    );
  });

  it("finds the agent anywhere in the caller chain, not just nearest", () => {
    const c = ctx("npm", "npm publish", "/home/me/oss/my-lib");
    c.callers = [
      caller("zsh", "-zsh"),
      caller("Claude", "/Applications/Claude.app/Contents/MacOS/Claude"),
    ];
    expect(decide(c).kind).toBe(DecisionKind.Deny);
  });
});
