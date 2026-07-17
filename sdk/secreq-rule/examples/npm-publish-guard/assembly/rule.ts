// npm-publish-guard — a worked example of a programmable secreq rule.
//
// Policy: `npm publish` is auto-approved only from checkouts under
// PUBLISH_ROOT, and never when an AI-agent session appears anywhere in
// the caller chain. Every other npm invocation is none of this rule's
// business — it passes, and secreq falls through to declarative rules
// and the interactive consent prompt.
//
// Compile with `npm run build` (secreq-rule-build), test with
// `npm test` (as-pect). See docs/wasm-rules.md at the repo root for the
// full authoring guide.

import { RuleCtx, Decision, approve, pass, deny } from "secreq-rule";

/** Publishes are only auto-approved from checkouts under this tree. */
const PUBLISH_ROOT = "/home/me/oss/";

/** Case-insensitive needle for agent sessions in the caller chain. */
const AGENT_NEEDLE = "claude";

export function decide(ctx: RuleCtx): Decision {
  // Only the npm wrap, only `npm publish …`. Anything else is not this
  // rule's call to make.
  if (ctx.wrap != "npm") return pass();
  const argv = ctx.joinedArgv;
  if (argv != "npm publish" && !argv.startsWith("npm publish ")) {
    return pass();
  }

  // Hard stop: an unattended agent session never publishes on a rule's
  // say-so. Deny (not pass) so a matching declarative approve can't win
  // either — deny always beats approve.
  for (let i = 0; i < ctx.callers.length; i++) {
    const c = ctx.callers[i];
    if (
      c.name.toLowerCase().includes(AGENT_NEEDLE) ||
      c.command.toLowerCase().includes(AGENT_NEEDLE)
    ) {
      return deny(
        "npm publish from an AI-agent session is never auto-approved " +
          "(caller: " +
          c.name +
          ")",
      );
    }
  }

  // Publishes from the canonical checkout tree ride through silently.
  if (ctx.cwd == "/home/me/oss" || ctx.cwd.startsWith(PUBLISH_ROOT)) {
    return approve();
  }

  // A publish from anywhere else is unusual but not forbidden — no
  // opinion, let the human decide at the prompt.
  return pass();
}
