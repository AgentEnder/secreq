// Fixture: always deny, echoing every ctx field into the reason. The host
// test asserts on the echoed string, proving the full ctx marshals across
// the ABI intact (including non-ASCII and quote characters).
import { RuleCtx, Decision, deny } from "../../../../secreq-rule/assembly";

export function decide(ctx: RuleCtx): Decision {
  let callers = "";
  for (let i = 0; i < ctx.callers.length; i++) {
    if (i > 0) callers += ",";
    callers += ctx.callers[i].name + ":" + ctx.callers[i].command;
  }
  return deny(
    "wrap=" +
      ctx.wrap +
      "|argv=" +
      ctx.joinedArgv +
      "|cwd=" +
      ctx.cwd +
      "|callers=" +
      callers +
      "|secrets=" +
      ctx.secrets.join(",")
  );
}
