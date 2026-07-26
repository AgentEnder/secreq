/**
 * What a reader *does* in each flow.
 *
 * A `::flow` is otherwise derived end to end. The author writes
 * `::flow{term=run-gh}` and nothing else; the recording names the window it
 * blocked on, and that window's captured geometry says where every word in
 * it is painted. Exactly one fact is in neither harness's output, because
 * neither could have captured it: which control the person on the other side
 * of the pty pressed. The transcript saw a command resume. The screenshot
 * harness rendered a window nobody had touched yet. The decision happened in
 * the seam between them, and it is the whole point of the figure.
 *
 * So it is declared here — once per recording, beside nothing else, because
 * there is nothing else about a flow that is not already recorded somewhere.
 * Not in the markdown, for the same reason the fixture id is not in the
 * markdown: a page is the wrong place to keep a fact about a recording, and
 * it is the one place nothing would check it.
 *
 * ## Why a label rather than a position
 *
 * `'Approve'` is the word the window paints. `<secreq-window>` finds it in
 * the geometry it has already fetched, and that is the only form of this
 * fact that survives the chrome matrix: Approve is bottom-right on macOS,
 * bottom-**left** on Windows, and one half of a full-width action bar on
 * GNOME. A coordinate written down here would be wrong on four of the six
 * desktops the day it was written, and wrong on all six the next time a
 * padding constant moves.
 */

/** What a reader presses in each window one recording raises. */
export interface FlowDefinition {
  /**
   * Fixture id → the label of the control that is pressed, as the window
   * paints it. `null` says nothing is pressed and means it: a window that
   * resolves on its own — an auto-deny, a rule that fired, a wrap that died
   * — gets no pointer, and the flow reads as the window standing down by
   * itself, which is what happened.
   *
   * Every window the recording raises has to appear here. A window that
   * simply stops being drawn, with no cause on screen, is exactly the
   * failure the hero's cursor exists to avoid — it reads as the dialog
   * timing out — so "nobody pressed anything" is a claim an author makes
   * rather than a gap an author leaves.
   */
  press: Record<string, string | null>;
}

/**
 * Every flow the site publishes, keyed by the recording it plays.
 *
 * Small on purpose. If this table ever grows a second field that is not
 * about what the reader did, it has probably strayed into describing the
 * recording — which the recording describes.
 */
export const FLOWS: Record<string, FlowDefinition> = {
  'run-gh': {
    press: { '02-single-pending': 'Approve' },
  },
};

/**
 * The definition for `termId`, or a build failure.
 *
 * An unregistered recording stops the build rather than rendering a window
 * that rises and falls untouched. The author of a new flow has to say what
 * the reader did in it, even if the answer is `null`.
 */
export function flowDefinition(termId: string): FlowDefinition {
  const definition = FLOWS[termId];
  if (!definition) {
    throw new Error(
      `[docs-site] ::flow{term=${termId}} has no entry in docs-site/flow-defs.ts. Add one ` +
        'saying which control the reader presses in each window the recording raises — ' +
        `e.g. { press: { '<fixture-id>': 'Approve' } }, or null for a window nobody touches.`,
    );
  }
  return definition;
}
