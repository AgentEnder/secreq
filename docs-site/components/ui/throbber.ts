/**
 * The spinner glyph cycles, and the one thing on this site that is drawn
 * from knowledge rather than from a recording.
 *
 * ## Why this exists at all
 *
 * A pty recording is a series of photographs, and a spinner is the one
 * subject photography is bad at. `tests/cli_transcripts.rs` captures the
 * wait indicator by naming the glyph it wants — `expect_spinner` waits for
 * `⠋…`, then `⠙…`, and so on — because timing the captures would leave the
 * committed bytes at the mercy of where each poll landed inside the
 * indicator's 100ms window. That gives a recording that is *exact* and a
 * playback that is *slow*: `<secreq-terminal>` dwells on every frame it is
 * handed, so four photographs of a 100ms spinner replay as four 620ms
 * stills. The thing a wait indicator exists to say — this command is alive,
 * something is happening elsewhere — is precisely what does not survive
 * being played back at a sixth of speed.
 *
 * So the throbber is the one cell on the site that is animated rather than
 * replayed. The recording says **where** it is and **which glyph it started
 * on**; this module says what the rest of the revolution looks like.
 *
 * ## What that costs, stated plainly
 *
 * [`term-markup.ts`](../../term-markup.ts) opens with the site's rule —
 * nothing below the prompt is synthesised, a session that says secreq asked
 * something is a session in which secreq really asked it. This is the second
 * exception to it, and a narrower one than the prompt: the glyphs below are
 * a copy of `SPINNER_FRAMES` in `src/daemon/client.rs`, and the cadence is a
 * copy of `SPINNER_TICK` beside it. Every glyph the animation draws is one
 * the binary really paints, in the order it really paints them — but it is
 * this file saying so, not the recording.
 *
 * **The copy is the risk, so it is kept to one copy.** Both halves of the
 * feature import from here: the build-time collapse in `term-markup.ts` uses
 * [`throbberCycleFrom`] to *recognise* a spinner cell, and
 * `secreq-terminal-element.ts` plays the sequence it produced. Nothing in
 * this module touches the DOM or registers anything, which is what lets the
 * build step import it — `secreq-terminal-element.ts` defines a custom
 * element on import and can only ever be a type-only dependency there.
 *
 * If the spinner in `client.rs` is ever restyled, the failure mode is mild
 * and self-announcing rather than silent: an unrecognised glyph is not a
 * throbber, so nothing collapses, and the recording replays frame by frame
 * exactly as it did before this module existed. The animation can stop
 * being available; it cannot start disagreeing with the frames underneath
 * it.
 */

/**
 * The braille dots cycle — the cliclack/ora house style, and what secreq's
 * own wait indicator paints. Mirrors `SPINNER_FRAMES` in
 * `src/daemon/client.rs`.
 */
const BRAILLE_DOTS = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/** The heavier braille cycle, as used by several other CLI spinners. */
const BRAILLE_BLOCKS = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'];

/** The quadrant cycle, as used by cliclack's own progress spinner. */
const CIRCLE_QUADRANTS = ['◐', '◓', '◑', '◒'];

/**
 * Every cycle a recorded cell may be recognised as.
 *
 * Deliberately only unambiguous, non-ASCII families. An ASCII spinner
 * (`|/-\`) would be recognisable too, but `|` and `-` are also what a cell
 * of ordinary output holds, and a false positive here does not degrade —
 * it animates a character that was never spinning. A missed spinner does
 * degrade, into the frame-by-frame playback that is the status quo, so the
 * asymmetry says to be strict.
 */
const CYCLES = [BRAILLE_DOTS, BRAILLE_BLOCKS, CIRCLE_QUADRANTS];

/**
 * How often the animation advances a glyph, in ms. A copy of `SPINNER_TICK`
 * in `src/daemon/client.rs` — the real indicator's redraw cadence, which is
 * the whole point of animating rather than replaying.
 */
export const THROBBER_TICK_MS = 100;

/**
 * The full revolution `glyph` belongs to, rotated to begin with it — or
 * `null` if it is not a throbber glyph at all.
 *
 * Rotated, rather than returned as written, so the caller never has to
 * carry a starting offset alongside the sequence: the animation is always
 * `glyphs[i % glyphs.length]` from `i = 0`, and it always begins on the
 * glyph the recording actually photographed first.
 */
export function throbberCycleFrom(glyph: string): string[] | null {
  for (const cycle of CYCLES) {
    const start = cycle.indexOf(glyph);
    if (start !== -1) return [...cycle.slice(start), ...cycle.slice(0, start)];
  }
  return null;
}

/** Whether `glyph` is a spinner frame from any cycle above. */
export function isThrobberGlyph(glyph: string): boolean {
  return CYCLES.some((cycle) => cycle.includes(glyph));
}
