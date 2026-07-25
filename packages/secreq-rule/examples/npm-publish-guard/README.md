# npm-publish-guard — worked example

A complete programmable secreq auto-rule, from source to registered
module. The policy: `npm publish` is auto-approved only from checkouts
under `/home/me/oss/`, hard-denied when an AI-agent session appears in
the caller chain, and everything else falls through to the interactive
consent prompt.

The full authoring guide is [`docs/wasm-rules.md`](../../../../docs/wasm-rules.md)
at the repo root — this directory is the guide's running example.

## Layout

- `assembly/rule.ts` — the rule: one exported `decide(ctx)` function.
- `assembly/__tests__/rule.spec.ts` — as-pect spec covering all three
  decisions. **secreq never runs these tests** — you test locally,
  secreq only loads the compiled module.
- `rule.wasm` — the compiled module, checked in (same convention as
  `tests/fixtures/wasm_rules/`). Rebuild with `npm run build` after
  editing the rule.
- `as-pect.config.js` / `as-pect.asconfig.json` — test-runner wiring
  (scaffolded by `npx asp --init`, trimmed).

## Run it

```sh
npm install        # assemblyscript + as-pect + the secreq-rule SDK
npm test           # as-pect: 9 specs, approve/pass/deny
npm run build      # secreq-rule-build → rule.wasm
```

This in-repo copy pulls the SDK from `file:../..` so it always builds
against the checked-out source. In your own package, depend on the
published SDK instead — `npm install --save-dev secreq-rule`.

Then register the module (the daemon vets it, copies it into
`~/.secreq/rules/`, and pins it by sha256):

```sh
secreq rules add-wasm rule.wasm --name "npm publish guard" --secret NPM_TOKEN
```
