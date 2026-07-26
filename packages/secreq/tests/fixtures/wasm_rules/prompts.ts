// Fixture: always mandate the consent prompt, echoing the wrap into the
// reason. Exercises the decision that neither approves nor denies — it
// removes the option of an auto-approve and hands the ask to the user.
import { RuleCtx, Decision, prompt } from '../../../../secreq-rule/assembly';

export function decide(ctx: RuleCtx): Decision {
  return prompt('needs a human for wrap=' + ctx.wrap);
}
