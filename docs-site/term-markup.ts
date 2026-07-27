/**
 * The single renderer for a terminal session.
 *
 * The counterpart to `shot-markup.ts`, and it exists for the same reason:
 * both the `<Term />` React component and the `::term{id=…}` markdown
 * directive emit this exact HTML, so a session shown on the landing page and
 * one shown inside a guide cannot drift apart in markup, styling or
 * behaviour. Playback needs no separate step: the markup wraps the figure
 * in `<secreq-terminal>`, which the browser upgrades wherever it lands.
 *
 * Everything a terminal knows about itself is generated.
 * `.generated/terms.json` is built by the `secreq-copy-repo-assets` Vite
 * plugin from the recordings `tests/cli_transcripts.rs` writes by driving
 * the real binary on a real pty. There is no hand-maintained transcript
 * anywhere in this site — a session that says secreq asks something is a
 * session in which secreq really asked it.
 *
 * ## What gets rendered
 *
 * A recording is a list of steps: `frame` (the screen after a redraw),
 * `type` (text the user typed, and where), `key` (a bare keypress). All of
 * it is rendered server-side into one static block per frame, stacked and
 * shown one at a time. That means the terminal is complete and readable
 * with JavaScript disabled, with `prefers-reduced-motion: reduce`, and in
 * the instant before hydration — the final frame is simply the one on top.
 *
 * ## The one line that is not a frame
 *
 * [`prompt`](TermMarkupOptions.prompt) draws the recording's `command` as a
 * shell line above the frames. That is the single exception to the
 * invariant above, and it is worth being precise about what it does and
 * does not claim, because "there is no hand-maintained transcript" has to
 * keep meaning what it says.
 *
 * The string is not invented: `command` is recorded metadata, written by
 * the fixture that ran the binary, and it is already published — every
 * `::term` puts it in the title bar. What is synthesised is the *shell
 * line* around it: the `$`, and the fact that a person typed it. The
 * harness could not have recorded either, because it execs the binary on a
 * pty directly and there is no shell on the other end to have a prompt at
 * all. So a recording of a wrapped command opens on the command already
 * running, and a reader is left to take on faith the one thing the figure
 * exists to demonstrate — that they typed something ordinary.
 *
 * The frames are the pty's, and this line is drawn as its own row above
 * them rather than mixed into one, so the seam between what was recorded
 * and what was reconstructed is a seam you can see.
 *
 * ## The one cell that is not a photograph
 *
 * The second exception, and the only one that lives *inside* a frame.
 *
 * A wait indicator repaints every 100ms and `cli_transcripts.rs`
 * photographs it a glyph at a time, deliberately — timing the captures
 * would put the committed bytes at the mercy of where each poll landed. The
 * player then dwells on every frame it is handed, so those photographs come
 * back as a spinner running at a sixth of speed and giving up before it has
 * turned once. A wait indicator that does not move is a wait indicator that
 * has failed.
 *
 * So [`planSteps`] collapses a run of frames that differ only in their
 * spinner cell down to the frame they share, and emits an `s` step naming
 * that cell; `<secreq-terminal>` redraws it at the real cadence. The frame
 * underneath is untouched — glyph included — so this is an overlay on a
 * photograph rather than an edit to one, and with JavaScript off the
 * recording is exactly what it always was.
 *
 * What is borrowed from outside the recording is the rest of the
 * revolution: the recording establishes that a spinner is here and which
 * glyph it started on, and `components/ui/throbber.ts` supplies the other
 * nine. That file is the single place the borrowing happens and says at
 * length what it costs.
 */

import generated from './.generated/terms.json';
// Type-only: this module runs at build time and the element registers a custom
// element on import, so the value side must not come along.
import type { ScriptStep } from './components/ui/secreq-terminal-element';
// Value-side, and safe to be: `throbber.ts` is constants and two pure
// functions, with none of the custom-element registration that keeps the
// import above type-only.
import { isThrobberGlyph, throbberCycleFrom } from './components/ui/throbber';

/** One styled run of characters, as recorded by the harness. */
interface Run {
  t: string;
  /** Foreground: `"0".."15"` palette index, or `"#rrggbb"`. */
  f?: string;
  b?: string;
  /** Bitfield: 1 bold, 2 dim, 4 italic, 8 underline, 16 inverse. */
  s?: number;
}

type Line = Run[];

interface FrameStep {
  kind: 'frame';
  lines: Line[];
  /** Extra dwell in ms, for a beat where the real command was working. */
  hold?: number;
}

interface TypeStep {
  kind: 'type';
  text: string;
  row: number;
  col: number;
}

/**
 * Text the user pasted rather than typed, and the cell it landed in.
 *
 * A pty cannot tell the two apart, so the fixture records which one it meant;
 * see `Step::Paste` in `tests/cli_transcripts.rs`. The player draws this one
 * as a clipboard shortcut followed by the whole string arriving at once,
 * because that is what pasting looks like and because a secret reference is
 * something you copy out of your store, never something you retype.
 */
interface PasteStep {
  kind: 'paste';
  text: string;
  row: number;
  col: number;
}

interface KeyStep {
  kind: 'key';
  key: string;
}

/**
 * The consent window rose or fell at this beat, and `id` is the screenshot
 * fixture that shows it — a directory under `dev-docs/ui-screenshots/`.
 *
 * The only step that describes something the terminal never displayed. A
 * recorded session that blocks on consent is a session in which the
 * interesting half happens in a window the pty cannot photograph, so the
 * harness records where the seam is and leaves the pairing to the page.
 */
export interface GuiStep {
  kind: 'gui';
  action: 'show' | 'hide';
  id: string;
}

type Step = FrameStep | TypeStep | PasteStep | KeyStep | GuiStep;

interface TermEntry {
  id: string;
  /** The command being demonstrated. Shown in the title bar. */
  command: string;
  /** The figcaption, authored on the fixture. Always emitted by the recorder. */
  caption: string;
  cols: number;
  steps: Step[];
}

const TERMS = generated as unknown as Record<string, TermEntry>;

/** Every transcript id available to the site, in filename order. */
export function allTermIds(): string[] {
  return Object.keys(TERMS).sort();
}

/**
 * The recording named `id`, or a build failure.
 *
 * Every entry point into this module goes through here, so a guide that
 * claims to show a session which was never recorded stops the build no
 * matter which directive it used to claim it.
 */
function requireTerm(id: string): TermEntry {
  const entry = TERMS[id];
  if (!entry) {
    throw new Error(
      `[docs-site] No CLI transcript named "${id}". Expected a fixture of that name in ` +
        'tests/cli_transcripts.rs — record it with ' +
        '`cargo test --test cli_transcripts -- --ignored --test-threads=1`.',
    );
  }
  return entry;
}

/**
 * The figcaption a recording carries, before any per-page override.
 *
 * Exported for `flow-markup.ts`, which composes the terminal with a window
 * and therefore has to hoist the caption out of the terminal's own figure —
 * a caption stranded between the two halves would read as belonging to the
 * terminal alone, which in a flow it does not.
 */
export function termCaption(id: string): string {
  return requireTerm(id).caption ?? '';
}

/**
 * The `gui` markers in a recording, in the order they play.
 *
 * The pairing of a session with the window it blocked on is the recording's
 * to declare, not an author's to repeat: `::flow{term=run-gh}` names the
 * session and nothing else, and this is where the fixture ids come from.
 */
export function termGuiMarkers(id: string): GuiStep[] {
  return requireTerm(id).steps.filter((step): step is GuiStep => step.kind === 'gui');
}

const STYLE_CLASS: [number, string][] = [
  [1, 'b'],
  [2, 'd'],
  [4, 'i'],
  [8, 'u'],
  [16, 'v'],
];

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Render one run.
 *
 * Palette indices become classes rather than colours: `term.css` resolves
 * `.f3` differently in light and dark, because "ANSI yellow" that reads on
 * a dark panel is illegible on a white one. Only true-colour cells — which
 * a program asked for by exact value — get an inline style.
 */
function runHtml(run: Run): string {
  const classes: string[] = [];
  let style = '';

  if (run.f) {
    if (run.f.startsWith('#')) style += `color:${run.f};`;
    else classes.push(`f${run.f}`);
  }
  if (run.b) {
    if (run.b.startsWith('#')) style += `background:${run.b};`;
    else classes.push(`g${run.b}`);
  }
  for (const [bit, cls] of STYLE_CLASS) {
    if ((run.s ?? 0) & bit) classes.push(cls);
  }

  const text = escapeHtml(run.t);
  if (classes.length === 0 && style === '') return text;

  const attrs = [
    classes.length ? ` class="${classes.join(' ')}"` : '',
    style ? ` style="${style}"` : '',
  ].join('');
  return `<span${attrs}>${text}</span>`;
}

function lineHtml(line: Line): string {
  // An empty line still has to occupy a row, or a session with breathing
  // room in it collapses to a solid block of text.
  if (line.length === 0) return '<span class="term-line"> </span>';
  return `<span class="term-line">${line.map(runHtml).join('')}</span>`;
}

function frameHtml(frame: FrameStep, index: number): string {
  return [
    `<div class="term-frame" data-frame="${index}"${frame.hold ? ` data-hold="${frame.hold}"` : ''}>`,
    frame.lines.map(lineHtml).join(''),
    '</div>',
  ].join('');
}

/** One rendered character, with the styling that reached it. */
interface Cell {
  ch: string;
  /** Everything about the run this came from except its text. */
  style: string;
}

function styleKey(run: Run): string {
  return `${run.f ?? ''}|${run.b ?? ''}|${run.s ?? 0}`;
}

/**
 * Flatten a line's styled runs into the grid the terminal actually draws.
 *
 * Comparing runs directly would make two identical screens look different
 * for having been painted in a different number of writes, which is exactly
 * what happens either side of a spinner repaint.
 */
function lineCells(line: Line): Cell[] {
  const cells: Cell[] = [];
  for (const run of line) {
    const style = styleKey(run);
    // By code point: a glyph is one cell, and indexing by UTF-16 unit would
    // put the column count out by one for anything outside the BMP.
    for (const ch of run.t) cells.push({ ch, style });
  }
  return cells;
}

/** Where two frames disagreed, when they disagreed about exactly one cell. */
interface ThrobberCell {
  row: number;
  col: number;
}

/**
 * The cell `b` spun on relative to `a`, or `null` if `b` is not simply `a`
 * with its wait indicator advanced.
 *
 * The test is deliberately severe, because a false positive animates a
 * character that was never moving while a false negative merely leaves the
 * playback as it was before any of this existed:
 *
 * - **Exactly one cell** may differ. A spinner is one cell by construction;
 *   two cells is a redraw that happens to contain a spinner, and a redraw
 *   is a frame the reader is meant to see.
 * - Both sides of it must be **throbber glyphs**, and from the same cycle —
 *   `⠋` becoming `x` is a program printing something, not a spinner turning.
 * - The **styling must match**, so a cell that changed colour is a frame in
 *   its own right even if the glyph stayed put.
 * - Identical frames return `null` rather than an empty diff: two
 *   photographs of a screen that did not change are a deliberate beat (see
 *   `wrap-gh`'s held pair), and collapsing them would spend it.
 */
function throbberDiff(a: FrameStep, b: FrameStep): ThrobberCell | null {
  if (a.lines.length !== b.lines.length) return null;

  let found: ThrobberCell | null = null;

  for (let row = 0; row < a.lines.length; row += 1) {
    const left = lineCells(a.lines[row]);
    const right = lineCells(b.lines[row]);
    if (left.length !== right.length) return null;

    for (let col = 0; col < left.length; col += 1) {
      if (left[col].ch === right[col].ch && left[col].style === right[col].style) continue;
      if (found) return null;
      if (left[col].style !== right[col].style) return null;
      if (!isThrobberGlyph(left[col].ch) || !isThrobberGlyph(right[col].ch)) return null;
      found = { row, col };
    }
  }

  return found;
}

/** The frames that reach the DOM, and the script that drives them. */
interface Plan {
  frames: FrameStep[];
  script: ScriptStep[];
}

/**
 * Decide what to render and what to play, in one pass.
 *
 * The two used to be worked out independently — a `filter` for the frames
 * and a walk for the script — which was safe only because both visited the
 * steps in the same order and counted the same things. Collapsing a spinner
 * run drops frames from the DOM, so the frame indices in the script are no
 * longer the recording's; deriving both from one walk is what keeps them
 * from being able to disagree.
 *
 * The collapse itself: a maximal run of consecutive frames, each of which is
 * the last with its wait indicator advanced by one glyph on the *same* cell,
 * becomes the first frame plus one `s` step. See
 * `components/ui/throbber.ts` for why a spinner is animated rather than
 * replayed, and what that borrows from the binary.
 */
function planSteps(steps: Step[]): Plan {
  const frames: FrameStep[] = [];
  // Typed as what the player parses rather than `unknown[]`: this runs at
  // build time and the consumer runs in the browser, so a mismatch between
  // them has no way to surface except as a step that quietly does nothing.
  const script: ScriptStep[] = [];

  for (let i = 0; i < steps.length; i += 1) {
    const step = steps[i];

    if (step.kind === 'type') {
      script.push({ k: 't', text: step.text, row: step.row, col: step.col });
      continue;
    }
    if (step.kind === 'paste') {
      script.push({ k: 'p', text: step.text, row: step.row, col: step.col });
      continue;
    }
    if (step.kind === 'gui') {
      script.push({ k: 'g', action: step.action, id: step.id });
      continue;
    }
    if (step.kind === 'key') {
      script.push({ k: 'k', key: step.key });
      continue;
    }

    const index = frames.length;
    frames.push(step);

    // How far does the spinner run from here? Every extension has to spin
    // on the cell the run started on — a wait indicator does not migrate,
    // and a second cell taking over is a different screen.
    let cell: ThrobberCell | null = null;
    let end = i;
    while (end + 1 < steps.length) {
      const next = steps[end + 1];
      if (next.kind !== 'frame') break;
      const diff = throbberDiff(steps[end] as FrameStep, next);
      if (!diff) break;
      if (cell && (diff.row !== cell.row || diff.col !== cell.col)) break;
      cell = diff;
      end += 1;
    }

    const glyphs = cell ? throbberCycleFrom(lineCells(step.lines[cell.row])[cell.col].ch) : null;

    if (!cell || !glyphs) {
      script.push({ k: 'f', i: index, hold: step.hold });
      continue;
    }

    // The holds come along rather than being dropped with their frames: a
    // hold is the fixture saying the real command genuinely waited here,
    // which is a statement about the beat, not about the photograph.
    let hold = 0;
    for (let held = i; held <= end; held += 1) hold += (steps[held] as FrameStep).hold ?? 0;

    script.push({
      k: 's',
      i: index,
      row: cell.row,
      col: cell.col,
      glyphs,
      beats: end - i + 1,
      ...(hold ? { hold } : {}),
    });

    i = end;
  }

  return { frames, script };
}

/**
 * Serialise the script for the player.
 *
 * Frames are already in the DOM; what the player cannot infer is what
 * happened *between* them. This emits that as one JSON attribute rather
 * than a script tag, so the markup stays a single self-contained element
 * that markdown can drop anywhere.
 */
function scriptJson(script: ScriptStep[]): string {
  return escapeHtml(JSON.stringify(script));
}

export interface TermMarkupOptions {
  /** Overrides the recording's caption. Pass `''` to drop it entirely. */
  caption?: string;
  /**
   * Draw the recording's command as a shell line above the frames — typed,
   * during playback — instead of as a label in the title bar.
   *
   * The two are alternatives rather than additions: the command is one
   * fact, and a title bar repeating a line the body has just typed out
   * reads as a rendering bug. See the note at the head of this module for
   * what the prompt claims and what it does not.
   */
  prompt?: boolean;
  /**
   * Hand the decision about *when* this session plays to whatever is around
   * it, instead of the terminal starting itself as it scrolls into view.
   *
   * Set by `::flow` and by nothing else. A flow moves the page when its
   * window opens, so the page can only afford one of them playing at a
   * time — and a terminal that starts itself is a flow that starts itself.
   * The attribute is what `<secreq-terminal>` reads to stay still until
   * `start()` is called; see `components/ui/secreq-flow-element.ts` for who
   * calls it and in what order.
   */
  manual?: boolean;
}

const REPLAY_ICON =
  '<svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" ' +
  'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<path d="M14 8a6 6 0 1 1-1.8-4.3M14 2v4h-4" /></svg>';

/**
 * Render the terminal for `id`.
 *
 * Throws on an unknown id, exactly as `shotHtml` does: a guide that claims
 * to show a session which was never recorded should stop the build, not
 * publish a hole where the demonstration was meant to be.
 */
export function termHtml(id: string, options: TermMarkupOptions = {}): string {
  const entry = requireTerm(id);

  const caption = options.caption ?? entry.caption ?? '';
  const { frames, script } = planSteps(entry.steps);

  // A `<span>`, not a `<div>`, and the sigil is a separate element with its
  // trailing space inside it. Both are load-bearing:
  //
  // - `terminal.css` falls back to `.term-frame:last-of-type` when no frame
  //   is marked, which counts among the *divs* in `.term-body`. A div here
  //   would put a second type in that count for a rule that has already
  //   rendered every terminal on a page blank once.
  // - The player reads the sigil's own length to know which column the
  //   command starts at, so the caret it parks after each character lands
  //   on the same monospace grid the frames are drawn on. Written down
  //   twice, it would be wrong in the one place nothing renders.
  const prompt = options.prompt
    ? [
        '<span class="term-prompt">',
        '<span class="term-prompt-sigil">$ </span>',
        `<span class="term-prompt-cmd">${escapeHtml(entry.command)}</span>`,
        '</span>',
      ].join('')
    : '';

  // `<secreq-terminal>` is the outermost element so it can reach every part
  // it drives — the replay button in the title bar as well as the frames.
  // The browser upgrades it wherever this string lands, which is why the
  // React component and the markdown directive need nothing in common
  // beyond emitting it.
  return [
    `<secreq-terminal${options.manual ? ' manual' : ''}>`,
    `<figure class="term" style="--term-cols: ${entry.cols}">`,
    '<div class="term-frame-wrap">',
    '<div class="term-bar">',
    prompt ? '' : `<span class="term-cmd">${escapeHtml(entry.command)}</span>`,
    '<button type="button" class="term-replay">',
    REPLAY_ICON,
    'Replay',
    '</button>',
    '</div>',
    `<div class="term-body" data-script="${scriptJson(script)}">`,
    prompt,
    frames.map(frameHtml).join(''),
    // The caret is positioned during playback and is inert until then.
    '<span class="term-caret" aria-hidden="true"></span>',
    '</div>',
    // Keypress markers stack here. Outside `.term-body` on purpose: that
    // element scrolls horizontally on a narrow screen, and markers inside
    // it would slide out of the corner they are meant to be pinned to.
    // `aria-hidden` because they re-state an input the transcript already
    // shows — decoration, not content.
    '<div class="term-keys" aria-hidden="true"></div>',
    '</div>',
    caption ? `<figcaption>${caption}</figcaption>` : '',
    '</figure>',
    '</secreq-terminal>',
  ].join('');
}
