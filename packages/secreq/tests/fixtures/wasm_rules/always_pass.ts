// Fixture: a rule with no opinion — always falls through.
import { RuleCtx, Decision, pass } from "../../../../secreq-rule/assembly";

export function decide(ctx: RuleCtx): Decision {
  return pass();
}
