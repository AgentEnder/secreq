// Fixture: an infinite loop. The host's fuel budget must interrupt it and
// turn the runaway into a clean error.
import { RuleCtx, Decision, pass } from "../../../../secreq-rule/assembly";

export function decide(ctx: RuleCtx): Decision {
  let spin = 0;
  while (true) {
    spin++;
  }
  return pass();
}
