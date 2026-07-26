// Fixture: the rule aborts (AssemblyScript's `env.abort`) instead of
// returning a decision. The host must surface a clean error, not a panic.
import { RuleCtx, Decision, pass } from '../../../../secreq-rule/assembly';

export function decide(ctx: RuleCtx): Decision {
  abort('rule exploded on purpose');
  return pass(); // unreachable — asc requires a return on all paths
}
