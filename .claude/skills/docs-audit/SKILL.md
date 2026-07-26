---
name: docs-audit
description: Audit and clean up secreq's published prose — docs/*.md, README, CONTRIBUTING, the SDK README, and the dev-docs harness READMEs. Finds redundancy across pages, claims that contradict the source, and committed screenshot/transcript fixtures no page shows. Use when asked to review, trim, tidy, de-duplicate or fact-check the docs, when adding a page, or when a CLI/UI change needs the docs caught up.
---

# Auditing secreq's docs

Three failure modes recur here, in descending order of how much they cost a
reader:

1. **A claim that is wrong.** Prose asserting a path, a platform, or a verb
   that the source contradicts. Always the first thing to hunt.
2. **A picture described in words.** A rendered, captioned, committed fixture
   exists and the page paraphrases it instead.
3. **One topic explained on five pages.** Each copy then rots independently.

## Quick start

```sh
mise run docs-audit   # redundancy, stale claims, unused fixtures, voice
mise run docs         # Vale: the mechanical prose rules
```

The audit is advisory and always exits 0; it finds candidates, you verify
them. Vale fails only on `error`-level findings, and its rules live in
`.vale/styles/Secreq/`. The two do not overlap: Vale matches tokens, the audit
cross-references files.

## Workflow

Track these as todos — skipping step 2 is how a "cleanup" ships a new wrong
claim.

1. **Sweep.** Run the script. Read every section.
2. **Verify each factual finding against source, never against another page.**
   `REFERENCE.md` maps claim types to the file that settles them. Two pages
   agreeing means nothing; they may have been copied from each other.
3. **Pick the canonical home for each repeated topic**, then replace the other
   copies with links. Prefer the page whose _subject_ it is over the page that
   happens to mention it.
4. **Wire up unused fixtures.** For each one the script lists, find the page
   describing that state and put the fixture there. If nothing describes it,
   that is a documentation gap, not a spare image.
5. **Cut, then check voice.** See "Voice" below, and run `mise run docs`.
6. **Verify.** `cargo test` (the guards in `REFERENCE.md`), then
   `cd docs-site && pnpm run build`, then
   `pnpm --filter @secreq/docs-site run typecheck-docs`.

## Never hand-write what a generator owns

- `docs/cli-reference.md` ← the clap tree. A flag table on any other page is
  a bug unless it covers `--sq-` options, which clap never sees.
- `docs/wraps.schema.json`, `docs/auto-rules.schema.json` ← the Rust types.
- A `::shot` / `::term` caption ← the fixture's own `layout.json` / recording
  JSON. Never restate a caption in the page body.

**The fix for a defect in generated prose is upstream.** A clumsy sentence in
`cli-reference.md` is a doc comment in `packages/secreq/src/cli.rs`; editing
the markdown just loses your work at the next regen.

## Voice: the repo's habits are not a style

**Most prose here was written by agents**, so its patterns are what a model
produces by default, not what anyone chose. Never justify a construction by
how common it already is in this tree; that reasoning is circular.

Real CLI docs (ripgrep, `gh`, aws-vault) use **3–4 em dashes per document**,
8–18 word sentences, and end sections at the last fact with no recap. Measure
against them, not against us.

The short list, in the order it shows up here:

- **Em dashes.** Default to a comma, colon, parentheses, or full stop. Any
  bracketing pair (`— an aside —`) is a defect.
- **Editorialising adverbs.** _deliberately, precisely, genuinely, actually,
  exactly._ If a choice was deliberate, the reason shows it.
- **The rule of three.** Three items is what a model writes when it doesn't
  know how many there are.
- **"Not just X, but Y"** and other parallel contrasts used to sound profound.
- **The safe conclusion.** A closing paragraph that recaps and commits to
  nothing. Delete it; end on the last useful sentence or a link.
- **Metronome rhythm.** Consecutive paragraphs of equal length opening the
  same way.
- **Hype with no fact** attached: _seamless, powerful, robust_.

Full marker list, the sampled comparison, and worked rewrites:
[VOICE.md](VOICE.md).

## Writing for a reader, not a reviewer

Contributor-facing notes (what a fixture exercises, why a guard exists) belong
in `dev-docs/*/README.md`. The published caption and the guide belong to
someone _using_ secreq. The two intentionally read differently — do not
harmonise them.

See [REFERENCE.md](REFERENCE.md) for the verification map, the existing
guards, and the fixture traps.
