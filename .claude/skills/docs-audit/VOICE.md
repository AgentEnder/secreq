# Voice

## Why this file exists

Most prose in this repo was written by agents. Its habits are therefore
evidence of what a model reaches for by default, **not** of a style anyone
chose. Never justify a construction by pointing at how common it already is
here; that reasoning is circular, and it is how these patterns accumulated.

Calibrate against real documentation instead.

## What real CLI docs actually do

Sampled from ripgrep's `GUIDE.md`, the `gh` manual, and aws-vault's README —
two of which secreq's own `overview.md` names as comparables.

| Trait           | Them                                                                    | Our default drift                                     |
| --------------- | ----------------------------------------------------------------------- | ----------------------------------------------------- |
| Em dashes       | 3–4 in an entire document                                               | 30 on a page                                          |
| Sentence length | 8–18 words                                                              | median 16, but a long tail past 30                    |
| Section endings | Stop at the last fact. No recap.                                        | A summarising closer that restates the section        |
| Caveats         | Plain: "Note:", a conditional clause, a table                           | Dramatised with dashes and emphasis                   |
| Tradeoffs       | A comparison table                                                      | Persuasive prose                                      |
| Mood            | Imperative for instructions ("Run `gh auth login`")                     | "You can run…", "You'll want to…"                     |
| Bold            | Rare; reserved for a critical negation ("will never modify your files") | Bold on every list item's first phrase                |
| Editorialising  | Absent. Facts, then stop.                                               | "deliberately", "on purpose", "precisely", "actually" |

Representative of the target register:

> "ripgrep is a command line tool that searches your files for patterns that
> you give it."
> "These expire in a short period of time, so the risk of leaking credentials
> is reduced."

Both state a fact and stop. Neither tells you the fact is important.

## The markers to remove

**Vocabulary.** delve, tapestry, paramount, pivotal, leverage, showcase,
underscore, seamless, robust, crucial, vital, landscape, realm. Also the
self-congratulatory adverbs: _deliberately, precisely, genuinely, exactly,
carefully, thoughtfully_. If a design choice was deliberate, the reason
demonstrates it; saying "deliberately" is asking to be believed instead.

These words are not banned, and the script only flags them for a look. "You
open it deliberately and close it yourself" contrasts with a window that
appears on its own, so the adverb is carrying meaning. "The re-prompt is
deliberately cheap" is not: delete the word and nothing is lost.

**Forced transitions.** Moreover, Furthermore, Consequently, Additionally at
the head of consecutive sentences. Usually deletable with no loss.

**The rule of three.** "fast, reliable, and secure." Three is what a model
produces when it does not know how many there are. Say two if there are two,
or five if there are five.

**"Not just X, but Y."** Also "X isn't about A, it's about B." Parallel
contrast used to sound profound. State the claim.

**Hype without a fact.** "powerful", "elegant", "seamless" attached to
nothing measurable. Replace with the number, the constraint, or nothing.

**Metronome rhythm.** Paragraphs of near-identical length, each opening the
same way (four consecutive `**BOLD** — gloss` paragraphs, say). Vary or merge.

**Bulleted paragraphs.** A list where every item is a bolded sentence
followed by three or four lines of explanation. The bold is not the problem —
a feature list with short labels is ordinary README form, and an error-message
list should bold the error. The problem is that each item has grown into a
paragraph, so the section is delivering prose while presenting as a summary.

**Do not fix this by deleting the hyphens.** Converting the bullets to
paragraphs moves the same words around and changes nothing; measure the
word count before and after and you will see it. These sections are long
because they say too much. Find the fact each item exists to state, keep
that, and drop the rest. Two useful questions:

- **Is it describing the screenshot below it?** The `::shot` is already
  showing the reader that. Cut the paraphrase, keep the fact the picture
  cannot state.
- **Is another section saying it too?** `wasm-rules.md` explained sha256
  pinning and error-fallthrough in both "The security model" and
  "Operational notes". One of the two is the canonical home.

**The safe conclusion.** A closing paragraph that summarises what was just
said and commits to nothing. Real docs end at the last useful sentence, or on
a link. Delete the recap.

**Emotional flatline.** Uniformly upbeat and formal. Where something is
genuinely a downgrade, a limitation, or a footgun, say so in the plain words
a colleague would use.

## Rewrites from this repo

| Before                                                             | After                                                              |
| ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| `` `aws-vault` — AWS only.``                                       | `` `aws-vault`: AWS only.``                                        |
| The manager never holds a decision — that's the prompt's job — so… | The manager never holds a decision (that is the prompt's job), so… |
| Splitting them is the point: the window that interrupts you…       | They are split so the window that interrupts you…                  |
| not because typing is nicer but because the flow checks its work   | Prefer this path. The flow checks its work:                        |
| `3` and `1` are distinct on purpose. A denial is final —           | `3` and `1` are distinct. A denial is final, so                    |

## Where the register legitimately differs

`dev-docs/*/README.md` and source comments are written for whoever changes
the code, and they carry rationale a user page should not. They may be
discursive. They are still subject to everything above; being internal is not
a licence for three-clause sentences.

A published `::shot` caption is the tightest register in the repo: one or two
sentences, present tense, describing what the reader is looking at.
