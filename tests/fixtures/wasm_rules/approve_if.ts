// Fixture: conditional approve — exercises ctx field access and branching.
// Approves `gh api --get ...` asks coming from under Cursor.app; passes on
// everything else.
import {
  RuleCtx,
  Decision,
  approve,
  pass,
} from "../../../sdk/secreq-rule/assembly";

export function decide(ctx: RuleCtx): Decision {
  if (ctx.wrap != "gh") return pass();
  if (!ctx.joinedArgv.startsWith("gh api --get ")) return pass();
  for (let i = 0; i < ctx.callers.length; i++) {
    if (ctx.callers[i].command.includes("Cursor.app")) return approve();
  }
  return pass();
}
