/**
 * The markup for a CLI → GUI flow: a session, and the window it blocked on.
 *
 * Both halves already exist and neither knows about the other. A recording
 * carries `gui` markers — the seam where the pty stopped being able to
 * photograph what was happening — and `<secreq-terminal>` dispatches each
 * one as an event and draws nothing. A `<secreq-window>` is a consent
 * window rebuilt from the geometry the screenshot harness measured. This
 * module is the composition: it puts the two on one stage and lets the
 * recording's own markers drive the window.
 *
 * ## Why it wraps rather than re-emits
 *
 * `termHtml` and `windowHtml` are called verbatim, exactly as `::term` and
 * `::shot` call them. That is the whole degradation story again: with no
 * JavaScript, or before the elements upgrade, a reader gets the finished
 * transcript *and* the published screenshot of the window — the same bytes
 * the guides already show — because that is literally what this emits.
 * Nothing is a fallback for anything; the choreography is the part that is
 * added, not the part that is replaced.
 *
 * ## Why the author does not name the window
 *
 * `::flow{term=run-gh}` is the whole directive. The screenshot id lives in
 * the recording, in `{"kind":"gui","action":"show","id":"02-single-pending"}`,
 * and `gui_ids_name_real_screenshot_fixtures` in `tests/cli_transcripts.rs`
 * already guarantees it names a fixture that exists. An author repeating it
 * in the markdown would be a second place for it to be wrong, and the only
 * one nothing checks.
 */

import { type FlowDefinition, flowDefinition } from './flow-defs';
import { termCaption, termGuiMarkers, termHtml } from './term-markup';
import { windowHtml } from './window-markup';

export interface FlowMarkupOptions {
  /** Overrides the recording's caption. Pass `''` to drop it entirely. */
  caption?: string;
}

/**
 * The pointer that takes the decision, borrowed wholesale from the hero.
 *
 * Same arrow, same reason. `pages/interception.css` puts it best: a button
 * that merely dims at the four-second mark does not say a person was in the
 * loop — it reads as the dialog timing out. Something has to arrive and
 * press it. Here the something also has to arrive at a *measured* place, so
 * the markup carries no coordinates at all; `<secreq-window>` finds the
 * label in the geometry and `<secreq-flow>` writes the answer into
 * `--flow-press-x` / `--flow-press-y`.
 *
 * `aria-hidden` throughout: the pointer and the ring it throws off restate a
 * decision the caption already makes in words.
 */
const CURSOR_MARKUP = [
  '<span class="flow-tap" aria-hidden="true"></span>',
  '<span class="flow-cursor" aria-hidden="true">',
  '<svg viewBox="0 0 12 17" width="14" height="19" aria-hidden="true">',
  '<path d="M1 1.2 10.4 9.6 6.2 10.1 8.6 14.8 6.7 15.8 4.3 11.1 1 13.9z" ',
  'fill="currentColor" stroke="var(--sq-panel)" stroke-width="1.1" stroke-linejoin="round" />',
  '</svg>',
  '</span>',
].join('');

/**
 * The fixture ids a recording raises, first one first.
 *
 * Also the validation pass, and it is deliberately strict about two things
 * the player cannot recover from at runtime:
 *
 * - **No markers at all.** A flow with no window in it is a `::term`, and
 *   silently rendering an empty stage below the session would look like a
 *   screenshot that failed to load.
 * - **Markers that do not pair up.** The terminal announces beats, not the
 *   end of the session, so a recording that shows a window and never hides
 *   it leaves that window standing over the finished transcript until the
 *   reader hits Replay. Requiring show/hide to alternate and to finish
 *   closed makes the stuck state unreachable rather than handled.
 */
function windowIds(termId: string): string[] {
  const markers = termGuiMarkers(termId);
  if (markers.length === 0) {
    throw new Error(
      `[docs-site] ::flow{term=${termId}} has no gui markers, so there is no window to ` +
        'raise. Use ::term for a recording that never blocks on consent, or record the ' +
        'markers in tests/cli_transcripts.rs.',
    );
  }

  const ids: string[] = [];
  let up: string | null = null;
  for (const marker of markers) {
    if (marker.action === 'show') {
      if (up) {
        throw new Error(
          `[docs-site] ::flow{term=${termId}} shows "${marker.id}" while "${up}" is still up. ` +
            'gui markers have to alternate show/hide.',
        );
      }
      up = marker.id;
      if (!ids.includes(marker.id)) ids.push(marker.id);
    } else {
      if (up !== marker.id) {
        throw new Error(
          `[docs-site] ::flow{term=${termId}} hides "${marker.id}", which is not the window ` +
            `that is up (${up ?? 'none'}). gui markers have to alternate show/hide.`,
        );
      }
      up = null;
    }
  }
  if (up) {
    throw new Error(
      `[docs-site] ::flow{term=${termId}} ends with "${up}" still up. A recording has to ` +
        'take its window down, or it stays over the finished transcript.',
    );
  }

  return ids;
}

/**
 * The recording's presses, checked against the windows it actually raises.
 *
 * Both directions matter and they fail for different reasons. A window with
 * no entry is an author who did not decide — the flow would raise it, drop
 * it, and say nothing about why. An entry naming a fixture the recording
 * never shows is an author who decided about the wrong thing: a rename in
 * `tests/cli_transcripts.rs`, or a copied definition whose fixture id came
 * along with it. Neither has any symptom at runtime beyond a cursor that
 * does not appear, which is precisely the state this whole change exists to
 * get rid of.
 */
function pressesFor(termId: string, ids: string[], definition: FlowDefinition): void {
  for (const id of ids) {
    if (!(id in definition.press)) {
      throw new Error(
        `[docs-site] ::flow{term=${termId}} raises "${id}", which docs-site/flow-defs.ts ` +
          'says nothing about. Name the control the reader presses in it, or null if the ' +
          'window resolves without anyone touching it.',
      );
    }
  }
  for (const id of Object.keys(definition.press)) {
    if (!ids.includes(id)) {
      throw new Error(
        `[docs-site] docs-site/flow-defs.ts says "${id}" is pressed in ::flow{term=${termId}}, ` +
          `but that recording never raises it. It raises ${ids.map((i) => `"${i}"`).join(', ')}.`,
      );
    }
  }
}

function escapeAttr(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
}

/**
 * Render the flow for the recording `termId`.
 *
 * ## The window opens from nothing, and the page gives it the room
 *
 * The stage is the terminal, and under it a shell that is exactly as tall
 * as the window standing in it — which at rest is not at all. An earlier
 * version reserved the window's full height permanently so the page could
 * never move, and paid 318px of empty figure for it: a reader who never
 * scrolled past the moment the window was up saw a transcript with a hole
 * under it. The reserve is gone, the shell opens on a `0fr -> 1fr` grid row
 * exactly as the hero's ask does, and the page reflows twice per playback —
 * which is affordable only because `<secreq-flow>` guarantees that at most
 * one flow on the page is ever moving. `pages/flow.css` is where the layout
 * is spelled out; `components/ui/secreq-flow-element.ts` is where the
 * one-at-a-time rule is.
 *
 * Both inner figures give up their captions, and the flow carries the
 * recording's own. Two captions inside one figure would be two claims about
 * one demonstration, and the terminal's would land in the gap between the
 * halves — reading as a caption for the session alone, which is the half
 * the flow exists to say is not the whole story.
 */
export function flowHtml(termId: string, options: FlowMarkupOptions = {}): string {
  const ids = windowIds(termId);
  const definition = flowDefinition(termId);
  pressesFor(termId, ids, definition);
  const caption = options.caption ?? termCaption(termId);

  // The map travels on the host because a flow stepping through several
  // windows has to re-aim between them, and the element is the only thing
  // that knows which one is up. The first window also gets its label
  // directly, so its geometry is located during the initial draw rather than
  // in the instant after the recording says it rose — a pointer that has to
  // be told where to go after the reach has started is a pointer that
  // reaches for the middle of the window first.
  const pressed = definition.press[ids[0]];
  const cursor = Object.values(definition.press).some(Boolean) ? CURSOR_MARKUP : '';

  // Seeded with the first fixture the recording raises. A flow that steps
  // through several changes only the `shot` attribute as it plays, which is
  // a case `<secreq-window>` already handles — but the screenshot underneath
  // stays the first one, because that is the window a reader with no
  // JavaScript is being told about.
  return [
    `<secreq-flow data-press="${escapeAttr(JSON.stringify(definition.press))}">`,
    '<figure class="flow">',
    '<div class="flow-stage">',
    // `prompt` is the one thing a flow asks the terminal to draw that a
    // bare `::term` does not. A flow's whole subject is the seam between a
    // command and the window that stopped it, and the recording opens on
    // the far side of that seam — the pty was handed the binary directly,
    // so there is no shell in it and no prompt to have typed into. Without
    // the line the figure asks a reader to take the first half of its own
    // claim on faith. `term-markup.ts` sets out what the line is
    // reconstructed from; it is the recording's own `command`, and the
    // title bar gives it up in exchange.
    //
    // `manual` is the other thing a flow asks of it, and it is the price of
    // the rule above: a terminal that starts itself the moment it is half on
    // screen is a flow that starts itself, and two figures moving the page at
    // once is exactly what a reserved stage used to make impossible. Inside a
    // flow the session plays when the flow's turn comes; a bare `::term`
    // elsewhere on the page is untouched and still starts itself.
    `<div class="flow-term">${termHtml(termId, { caption: '', prompt: true, manual: true })}</div>`,
    // Three boxes, and each one is load-bearing — see `pages/flow.css`. The
    // shell is the grid row that opens; the clip is what makes a collapsed
    // row actually collapse without shearing the window's shadow; the window
    // is the only one of the three whose height is the window's, which is
    // what lets the pointer be placed in percentages of it.
    '<div class="flow-shell">',
    '<div class="flow-clip">',
    '<div class="flow-window">',
    windowHtml(ids[0], { caption: '', press: pressed ?? undefined }),
    cursor,
    '</div>',
    '</div>',
    '</div>',
    '</div>',
    caption ? `<figcaption>${caption}</figcaption>` : '',
    '</figure>',
    '</secreq-flow>',
  ].join('');
}
