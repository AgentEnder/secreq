// Public surface for rule authors. A rule is a single AssemblyScript file:
//
//   import { RuleCtx, Decision, approve, pass, deny } from "secreq-rule";
//
//   export function decide(ctx: RuleCtx): Decision {
//     if (ctx.wrap == "gh" && ctx.joinedArgv.startsWith("gh api ")) {
//       return approve();
//     }
//     return pass();
//   }
//
// Compile it with `secreq-rule-build` (see ../bin/build.js), which layers
// the wasm ABI glue from ./abi.ts around the author's `decide`.

export { Caller, RuleCtx } from "./ctx";
export { Decision, DecisionKind, approve, pass, deny } from "./decision";
