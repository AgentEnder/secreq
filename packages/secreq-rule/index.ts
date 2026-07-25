// Package entry for asc's node_modules-style resolution: a consumer's
// `import { ... } from "secreq-rule"` resolves to `<pkg>/index.ts` (asc
// 0.28 does not consult `ascMain` for bare specifiers). Re-exports the
// authoring surface from assembly/index.ts — keep the two in lock-step.
export { Caller, RuleCtx } from "./assembly/ctx";
export { Decision, DecisionKind, approve, pass, deny } from "./assembly/decision";
