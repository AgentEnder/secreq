---
name: docs-audit
description: Audit and clean up secreq's published prose — docs/*.md, README, CONTRIBUTING, the SDK README, and the dev-docs harness READMEs. Finds pages longer than anyone will read, redundancy across pages, claims that contradict the source, and committed screenshot, transcript or browser-recording fixtures no page shows. Use when asked to review, trim, shorten, tidy, de-duplicate, de-slop or fact-check the docs, when prose reads as AI-written, when adding a page, or when a CLI/UI change needs the docs caught up.
---

# Auditing secreq's docs

Five failure modes recur here, in descending order of how much they cost a
reader:

1. **A claim that is wrong.** Prose asserting a path, a platform, or a verb
   that the source contradicts. Always the first thing to hunt. Overstating a
   limitation counts: "Windows depends on facilities it does not have" was
   false, since every facility has a counterpart. "Not yet" and "impossible"
   are different claims.
2. **A picture described in words.** A rendered, captioned, committed fixture
   exists and the page paraphrases it instead.
3. **A page longer than anyone will read.** The most common complaint about
   this tree, and the hardest to fix, because rearranging it feels like fixing
   it. See "Cutting" below.
4. **Content whose audience is elsewhere.** Contributor material on a user
   page. Nobody who installed with `curl | sh` will run `cargo run`; that
   paragraph belongs in `CONTRIBUTING.md`, and porting notes belong in brain.
5. **One topic explained on five pages.** Each copy then rots independently.

## Quick start

```sh
npx nx run docs:audit   # redundancy, stale claims, unused fixtures, voice
npx nx run docs:vale         # Vale: the mechanical prose rules
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
5. **Cut, then check voice.** See "Cutting" and "Voice" below, and run
   `npx nx run docs:vale`.
6. **Verify.** `cargo test` (the guards in `REFERENCE.md`), then
   `npx nx build docs-site`, then
   `npx nx run docs-site:typecheck-docs`.

## Cutting

Reformatting reads as editing and is not. Unbulleting a list, splitting a
sentence, swapping a dash for a comma: the page holds the same material
afterwards. A pass that moved 72, 8 and 20 words across three pages was
reported as a cleanup, and the reader would have noticed nothing.

**Measure.** `npx nx run docs:audit` prints prose words per page. Record the
number before and after. Under about 10% and you rearranged the page; the
cuts that worked ran 22–32%.

Volume lives in four places, and none of them is punctuation:

- **A section narrating the figure beneath it.** The `::shot` or `::term` is
  already showing the reader. Keep only what the picture cannot state.
- **The same fact in two sections.** `ssh-agent.md` said "first sign prompts"
  and "listing is free" under both "What it does" and "Behavior".
- **Onboarding for a command the recording demonstrates.** 831 words of
  launchd and op-discovery mechanics sat above a `::term` that ran the thing.
- **A section written for a different audience.** Move it rather than delete
  it, and see the warning about splitting a move below.

**A move is one commit.** Cutting a paragraph from one page and adding it to
another is two edits that must land together. Half of one landed once, and a
warning that a dev build can corrupt `~/.secreq` existed nowhere in the repo
until it was noticed. The same applies to a change spanning the Rust harness
and the docs-site player.

## Never hand-write what a generator owns

- `docs/cli-reference.md` ← the clap tree. A flag table on any other page is
  a bug unless it covers `--sq-` options, which clap never sees.
- `docs/wraps.schema.json`, `docs/auto-rules.schema.json` ← the Rust types.
- A `::shot` / `::term` caption ← the fixture's own `layout.json` / recording
  JSON. Never restate a caption in the page body.
- The command a `::term` ran ← the recording. `::term` renders with
  `prompt: true`, so the player types the command as a shell line before the
  output. A fenced block above the directive prints it twice.

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
- **Bulleted paragraphs.** Every item a bolded sentence plus a paragraph.
  Fix by cutting the item down, never by converting the list to prose —
  same words, no gain. `npx nx run docs:audit` flags these; hits in
  `README.md` and the contributor pages are usually the conventional
  short-label feature list and can stand.
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
someone _using_ secreq. The two read differently; do not harmonise them.

See [REFERENCE.md](REFERENCE.md) for the verification map, the existing
guards, and the fixture traps.
