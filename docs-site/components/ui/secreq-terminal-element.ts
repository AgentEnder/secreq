/**
 * `<secreq-terminal>` — a recorded terminal session that plays itself.
 *
 * ## Why a custom element
 *
 * This component has two callers that cannot share a React tree: the
 * `<Term />` component, and the server-rendered HTML the `::term{id=…}`
 * markdown directive injects into `.prose-content` via
 * `dangerouslySetInnerHTML`. React cannot own the second one, so anything
 * React-only would need a parallel DOM layer to serve it — a hydrate
 * function, an "already wired" flag, a map of per-element state, and a
 * `useEffect` in every page that might contain one.
 *
 * A custom element is the primitive that removes all of it. The browser
 * upgrades this tag wherever it appears, from either caller, with no
 * hydration pass and no bookkeeping:
 *
 * - `connectedCallback` replaces `hydrateTerms()` and its `data-playerReady`
 *   guard — an element is upgraded once, by definition.
 * - `disconnectedCallback` replaces nothing that existed, which was the
 *   bug: a client-side navigation used to leave a playback running against
 *   detached nodes. Teardown is now part of the lifecycle.
 * - Playback state is instance state, not a `WeakMap` keyed on a `<div>`.
 *
 * Deliberately **no shadow DOM**. The frames are server-rendered light-DOM
 * children — they must stay visible to the page's stylesheet (theme
 * variables, the ANSI palette in `terminal.css`), to Pagefind's indexer,
 * and to a reader with JavaScript disabled, for whom the finished session
 * is simply the last frame.
 *
 * ## What playback adds
 *
 * The frames are already in the DOM, stacked; the element only animates
 * *between* them. Frames cut, because that is what a TUI redraw does — a
 * cliclack prompt does not fade in. Typing is drawn character by character
 * at the cell the harness recorded, because that is the part a reader is
 * meant to read as *their* input rather than the program's output.
 */

import { THROBBER_TICK_MS } from './throbber';

/**
 * One entry of the recorded script, as `term-markup.ts` serialises it.
 *
 * Exported so the producer can be typed against the same union it will be
 * parsed back into. The two halves used to agree only by inspection —
 * `scriptJson` built an `unknown[]` — which meant a step emitted with a
 * missing field type-checked cleanly and then did nothing at all when the
 * player reached it. Adding a variant should break the producer, not the
 * playback.
 */
export type ScriptStep =
  | { k: 'f'; i: number; hold?: number }
  | { k: 't'; text: string; row: number; col: number }
  | { k: 'p'; text: string; row: number; col: number }
  | { k: 'k'; key: string }
  | { k: 'g'; action: 'show' | 'hide'; id: string }
  | {
      k: 's';
      /** The frame to show underneath — the first of the collapsed run. */
      i: number;
      row: number;
      col: number;
      /** One full revolution, already rotated to start where the recording did. */
      glyphs: string[];
      /** How many frames were collapsed. The beat is this many frame dwells. */
      beats: number;
      hold?: number;
    };

/**
 * The event a `g` step raises: the consent window went up, or came down,
 * and `id` is the screenshot fixture that shows it.
 *
 * Named as a constant because the listener is somewhere else entirely — a
 * page that wants to put a window beside the terminal — and a string typed
 * twice in two files is a listener that silently never fires.
 */
export const GUI_EVENT = 'secreq-gui';

export interface GuiEventDetail {
  action: 'show' | 'hide';
  /** A directory under `dev-docs/ui-screenshots/`. */
  id: string;
}

/**
 * The session played to its last frame.
 *
 * Only a **driven** terminal has anyone to tell, but it is announced by
 * every terminal for the same reason `gui` is: what happened is the
 * element's to report and what to do about it is the page's. A run that was
 * superseded or stopped says nothing — the thing that superseded it is the
 * thing that will end.
 */
export const TERM_END_EVENT = 'secreq-term-end';

/**
 * Replay was pressed on a terminal that does not start itself.
 *
 * A driven terminal hands the button to its owner rather than acting on it,
 * because "when does this play" has exactly one answer per page and it is
 * not this element's. A terminal that starts itself keeps the button
 * entirely to itself and raises nothing.
 */
export const TERM_REPLAY_EVENT = 'secreq-term-replay';

/** Milliseconds a frame rests before the next step. */
const FRAME_DWELL = 620;
/** Milliseconds per typed character. Fast enough to read, slow enough to see. */
const TYPE_SPEED = 42;
/** Beat after a keypress, standing in for the moment before a screen reacts. */
const KEY_BEAT = 180;

/**
 * How a recorded key name is drawn on the keycap.
 *
 * Named keys become their glyph so the cap stays one square regardless of
 * how long the name is; anything absent falls through to the key itself,
 * which is what makes a literal answer like `y` render as `y`. The map is
 * keyed on the names `cli_transcripts.rs` records, so a new key it learns
 * to send shows up as its bare name rather than as nothing.
 */
const KEY_GLYPHS: Record<string, string> = {
  Enter: '\u23ce',
  Up: '\u2191',
  Down: '\u2193',
  Left: '\u2190',
  Right: '\u2192',
  Tab: '\u21e5',
  Escape: 'esc',
  Backspace: '\u232b',
  Space: '\u2423',
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

/**
 * Exported because a `::flow` asks the same question about itself, and the
 * answer has to be the same one: a flow that decided it was on screen by a
 * different rule than the terminal it drives would start sessions the
 * terminal would not have started.
 */
export function prefersReducedMotion(): boolean {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/**
 * Thresholds every tenth, rather than the single 0.5 the rule below is
 * about.
 *
 * An observer only reports when a listed threshold is crossed. A terminal
 * taller than the window can never reach a ratio of 0.5, so with 0.5 as
 * the only entry it would be reported once on the way in, fail the test,
 * and never be asked about again. The steps keep it being asked as it
 * scrolls.
 */
export const VISIBILITY_STEPS = Array.from({ length: 11 }, (_, i) => i / 10);

/**
 * Whether enough of the terminal is on screen to be worth animating:
 * half of it — or, for one taller than the window where half of it never
 * can be, half the window filled by it.
 */
/**
 * How long a recording has to stay on screen before it starts playing.
 *
 * Being on screen is not the same as being looked at. A reader scrolling
 * through a page crosses every figure on it, and starting a session at the
 * moment one passes the halfway mark means starting it behind them — three
 * terminals on a docs page all playing to an empty seat, and for a `::flow`,
 * the page growing under a scroll that is still in progress. So the gate is
 * a *dwell*: half of the figure on screen, continuously, for this long, with
 * the timer thrown away the moment it drops back out rather than banked
 * against the next visit.
 *
 * 600ms, and the arithmetic is worth writing down because it is the only
 * thing that says whether the number is any good. A figure shorter than the
 * viewport is at least half on screen across exactly one viewport's worth of
 * scrolling — the entering and leaving halves cancel — so the dwell survives
 * any scroll faster than one viewport per 600ms, about 1500px/s in a laptop
 * window. Flicking through this page measures 2000–5000px/s and starts
 * nothing; a deliberate read-as-you-go scroll is well under it and starts
 * everything, which is the right way round. Shorter than about 300ms and a
 * flick trips it two screens back; much longer and a reader who has stopped
 * in front of the figure is left wondering whether it is a still.
 *
 * Exported because a `::flow` waits out the same dwell before it so much as
 * joins the queue — the terminal it drives would otherwise be the only
 * thing on the page that was patient.
 */
export const DWELL_MS = 600;

export function isHalfInView(entry: IntersectionObserverEntry): boolean {
  if (entry.intersectionRatio >= 0.5) return true;
  const viewport = entry.rootBounds?.height ?? window.innerHeight;
  return viewport > 0 && entry.intersectionRect.height >= viewport / 2;
}

export class SecreqTerminal extends HTMLElement {
  /**
   * Which playback is allowed to touch the DOM.
   *
   * Replay must interrupt a session already in flight, and the losing run
   * is always parked on a timer inside its own call stack. Bumping the
   * token is the whole cancellation mechanism: a superseded run wakes,
   * sees the token moved on, and returns without writing. Nothing is
   * thrown, so a cancellation can never be mistaken for a failure.
   */
  #run = 0;
  #observer: IntersectionObserver | null = null;
  /** The pending [`DWELL_MS`] timer, or `0` for none. */
  #dwell = 0;

  /**
   * The command on the prompt row, as the server rendered it.
   *
   * Kept because playback erases it to type it back, so the DOM stops being
   * the record of what it said. Captured once — a re-entered element may
   * have been pulled out mid-keystroke, and re-reading a half-typed
   * command would make the truncation permanent.
   */
  #command: string | null = null;

  connectedCallback() {
    const replay = this.querySelector<HTMLButtonElement>('.term-replay');
    replay?.addEventListener('click', this.#onReplay);

    const cmd = this.#promptCmd;
    if (cmd && this.#command === null) this.#command = cmd.textContent ?? '';

    // Reduced motion gets the finished session and no playback at all — a
    // complete, readable transcript rather than a stalled opening frame.
    if (prefersReducedMotion()) {
      this.#showFrame(this.#frames.length - 1);
      replay?.setAttribute('hidden', '');
      return;
    }

    // Rest on the finished session until playback actually begins. Parking
    // on frame 0 would mean a terminal the observer never fires for — one
    // already scrolled past on load — sits forever showing an opening
    // prompt, looking like a session that died halfway.
    this.#showFrame(this.#frames.length - 1);

    // A driven terminal watches for nothing. Its owner — today, only
    // `<secreq-flow>` — is watching for it, because the thing that has to
    // be on screen is the whole figure and the thing that has to take its
    // turn is the whole figure. Every line above this one still runs: the
    // finished session, the replay button and the reduced-motion rest state
    // are the terminal's regardless of who says when it plays.
    if (this.#driven) return;

    // Play once, on arrival, and not before half of it has been on screen
    // for [`DWELL_MS`]: a session that plays while the terminal is peeking
    // in at the bottom of the window spends itself where nobody is reading,
    // and the reader scrolls down to a finished transcript wondering what
    // the Replay button is for. The dwell is the same thought carried one
    // step further — a figure the reader is scrolling *past* is no more
    // being read than one below the fold — and it is what keeps a docs page
    // with three terminals from starting all three behind them.
    this.#observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (isHalfInView(entry)) this.#arm();
          else this.#disarm();
        }
      },
      { threshold: VISIBILITY_STEPS },
    );
    this.#observer.observe(this);
  }

  /**
   * Start the dwell, unless it is already running.
   *
   * Already running is the common case — the observer reports every
   * threshold a scroll crosses — and re-arming on each of them would push
   * the start further away the more of the terminal came into view.
   */
  #arm() {
    if (this.#dwell) return;
    this.#dwell = window.setTimeout(() => {
      this.#dwell = 0;
      this.#observer?.disconnect();
      this.#observer = null;
      this.#start();
    }, DWELL_MS);
  }

  /** Throw the dwell away. A terminal that comes back waits out a fresh one. */
  #disarm() {
    window.clearTimeout(this.#dwell);
    this.#dwell = 0;
  }

  disconnectedCallback() {
    // Invalidates any run in flight. Without this, a client-side navigation
    // away from a docs page leaves a playback writing into detached nodes
    // until its script runs out.
    this.#run += 1;
    this.#disarm();
    this.#observer?.disconnect();
    this.#observer = null;
    this.querySelector('.term-replay')?.removeEventListener('click', this.#onReplay);
    // Whatever was on screen when the element was pulled, the command is
    // whole again — a detached terminal has no playback to finish typing it.
    this.#restoreCommand();
  }

  /**
   * A driven terminal asks; every other one just goes.
   *
   * Replay is the one input in this system a reader gives on purpose, so it
   * is never swallowed — but inside a flow it has to travel the same road as
   * an automatic start, or a reader could put two flows on the page at once
   * with two clicks. What the owner does with it is the owner's business;
   * `<secreq-flow>` treats it as a request that outranks the queue.
   */
  #onReplay = () => {
    if (this.#driven) {
      this.dispatchEvent(new CustomEvent(TERM_REPLAY_EVENT, { bubbles: true, composed: true }));
      return;
    }
    this.#start();
  };

  /** Whether something outside this element says when it plays. */
  get #driven(): boolean {
    return this.hasAttribute('manual');
  }

  /**
   * Play from the top, on someone else's say-so.
   *
   * The public half of the `manual` contract. Deliberately not gated on the
   * attribute: a caller that has gone to the trouble of holding a reference
   * to this element and calling this means it, and a method that silently
   * did nothing on an ungoverned terminal would be a debugging afternoon.
   */
  start() {
    this.#start();
  }

  /**
   * Abandon whatever is playing and rest on the finished session.
   *
   * Every bit of it is state some run left behind: the token bump is what
   * makes the run in flight return without writing, and the rest is the
   * screen it would have tidied on its way out. No [`TERM_END_EVENT`] —
   * this session did not end, it was called off, and the caller calling it
   * off is the one thing that already knows.
   */
  stop() {
    this.#run += 1;
    this.#reset();
    this.#clearKeys();
    this.#restoreCommand();
    this.#showFrame(this.#frames.length - 1);
  }

  get #body(): HTMLElement | null {
    return this.querySelector<HTMLElement>('.term-body');
  }

  get #frames(): HTMLElement[] {
    return [...this.querySelectorAll<HTMLElement>('.term-frame')];
  }

  get #promptCmd(): HTMLElement | null {
    return this.querySelector<HTMLElement>('.term-prompt-cmd');
  }

  /**
   * How far down the body the recording's own row 0 sits.
   *
   * A prompt row pushes every frame down by one line, and the caret and the
   * typing overlay are positioned in absolute body rows — so a recording
   * with typing in it would draw its characters one line above the text
   * they belong to. One place to add it, applied to the recorded rows only:
   * the prompt types on body row 0, which is where it is.
   */
  get #frameRow(): number {
    return this.#promptCmd ? 1 : 0;
  }

  #restoreCommand() {
    const cmd = this.#promptCmd;
    if (cmd && this.#command !== null) cmd.textContent = this.#command;
  }

  /**
   * Show exactly one frame.
   *
   * **Exactly one** is the invariant the whole element rests on, so it is
   * enforced here rather than trusted: the index is clamped, and inactive
   * frames have the attribute *removed* rather than set to `"false"`.
   *
   * That distinction is what stops the terminal going blank. A `"false"`
   * value was something the stylesheet had to match and hide, and it beat
   * the `:last-of-type` fallback on source order — so any instant where no
   * frame held `"true"` painted an empty panel at full height, with
   * nothing thrown to explain it. With the attribute simply absent,
   * "nothing is marked" falls back to the finished session, which is also
   * the no-JavaScript rendering.
   *
   * A **negative** index is the one state where no frame shows: the moment
   * before the command has been entered, when the screen below the prompt
   * is genuinely empty. It is spelled as an attribute the player sets and
   * every other call here clears, rather than as a gap in the marking,
   * precisely because of the failure above — "no frame is showing" has to
   * be something the DOM says on purpose, so that the accident of nothing
   * being marked keeps meaning "show the finished session".
   */
  #showFrame(index: number) {
    const frames = this.#frames;
    if (frames.length === 0) return;
    const body = this.#body;

    if (index < 0) {
      frames.forEach((frame) => delete frame.dataset.active);
      if (body) body.dataset.blank = 'true';
      return;
    }
    if (body) delete body.dataset.blank;

    const target = Math.min(index, frames.length - 1);
    frames.forEach((frame, i) => {
      if (i === target) frame.dataset.active = 'true';
      else delete frame.dataset.active;
    });
  }

  /**
   * Clear anything a previous *frame* overlaid — typed text, and a wait
   * indicator still turning over a frame that is about to be replaced.
   *
   * A spinner left running is the one of those two that would keep *writing*
   * rather than merely sitting there, so this is also what stops a beat
   * abandoned by [`stop`] from painting a glyph onto its successor's screen.
   *
   * Deliberately does **not** touch the keycaps. This runs on every frame
   * step, and a cap is raised one key beat — 180ms — before the frame it
   * causes; clearing here would delete each cap almost the moment it
   * appeared, which is the whole thing the stack exists to avoid. Caps are
   * per-run state, cleared by [`#clearKeys`].
   */
  #reset() {
    this.querySelectorAll('.term-typed, .term-spin').forEach((node) => node.remove());
    const caret = this.querySelector<HTMLElement>('.term-caret');
    if (caret) delete caret.dataset.on;
  }

  /** Drop every keycap still on screen. Per-run, not per-frame. */
  #clearKeys() {
    this.querySelectorAll('.term-key').forEach((cap) => cap.remove());
  }

  /**
   * Raise a keycap for a recorded keystroke.
   *
   * The frames cannot carry this: a keypress is the one part of the
   * session the program never echoes, so between two frames the screen
   * simply changes and a reader is left to infer what did it.
   *
   * Each press gets its own node so a quick run of keys stacks instead of
   * flickering through one box, and each carries its whole life in a CSS
   * animation — so removal needs no timer to track, and no run token to
   * check when that timer wakes.
   */
  #showKey(key: string) {
    const stack = this.querySelector<HTMLElement>('.term-keys');
    if (!stack) return;
    // Two nodes because a keycap is two surfaces: `.term-key` is the
    // skirt, `.term-key-face` the top plate sitting proud of it. Drawn on
    // one element the cap reads as a flat rounded rectangle — the emoji
    // keycap idiom — rather than as a moulded object.
    const cap = document.createElement('span');
    cap.className = 'term-key';
    const face = document.createElement('span');
    face.className = 'term-key-face';
    face.textContent = KEY_GLYPHS[key] ?? key;
    cap.appendChild(face);
    cap.addEventListener('animationend', () => cap.remove(), { once: true });
    stack.appendChild(cap);
  }

  /**
   * Park the caret over a cell of the visible frame.
   *
   * Positions are in `ch` units against the same monospace grid the frames
   * are drawn on, which is why the recording stores cell coordinates
   * rather than pixel offsets — the font size is the page's to choose.
   */
  #placeCaret(row: number, col: number) {
    const caret = this.querySelector<HTMLElement>('.term-caret');
    if (!caret) return;
    caret.style.setProperty('--row', String(row));
    caret.style.setProperty('--col', String(col));
    caret.dataset.on = 'true';
  }

  /**
   * Announce that the consent window rose or fell at this beat.
   *
   * Deliberately renders nothing. The terminal's job here is to say *when*,
   * not to draw the window: the window is a screenshot fixture living in
   * another directory, owned by another harness, and a page may well want it
   * somewhere this element has no business reaching. Raising an event and
   * stopping there is what keeps a recording with markers in it replayable
   * on a page that has nowhere to put one — with no listener, the marker is
   * a beat and nothing more.
   *
   * `composed` so it escapes any shadow root a host may have wrapped the
   * terminal in, and `bubbles` so a listener can sit on a common ancestor
   * rather than on every terminal on the page.
   */
  #announceGui(step: Extract<ScriptStep, { k: 'g' }>) {
    const detail: GuiEventDetail = { action: step.action, id: step.id };
    this.dispatchEvent(new CustomEvent(GUI_EVENT, { bubbles: true, composed: true, detail }));
  }

  #start() {
    this.#run += 1;
    void this.#play(this.#run);
  }

  /**
   * Say the session is over — once, for the run that is actually current.
   *
   * In a `finally`, because the listener is a queue: a recording whose
   * script will not parse, or a step that throws on the way through, has to
   * end the turn it took or nothing else on the page ever plays again. A
   * broken flow should be a broken flow, not a broken page.
   */
  #announceEnd(run: number) {
    if (this.#run !== run || !this.isConnected) return;
    this.dispatchEvent(new CustomEvent(TERM_END_EVENT, { bubbles: true, composed: true }));
  }

  async #play(run: number) {
    try {
      await this.#playScript(run);
    } finally {
      this.#announceEnd(run);
    }
  }

  async #playScript(run: number) {
    const body = this.#body;
    if (!body) return;

    const script: ScriptStep[] = JSON.parse(body.dataset.script || '[]');
    this.#reset();
    // A superseded run leaves its caps behind — they are the one overlay
    // `#reset` no longer owns, so clearing them is this run's job.
    this.#clearKeys();

    // Before the first recorded frame, because the first recorded frame is
    // the command already running. Nothing is waited out between the last
    // character and the script: the recording's own opening beat — the
    // window rising, the spinner appearing — is what Enter caused, and a
    // pause inserted here would read as the shell thinking about it.
    if (this.#promptCmd) {
      await this.#typeCommand(run);
      if (this.#run !== run) return;
    }

    for (const step of script) {
      if (this.#run !== run) return;

      if (step.k === 'f') {
        // A new frame supersedes whatever was typed onto the last one —
        // the real screen has just been redrawn with that text baked in.
        this.#reset();
        this.#showFrame(step.i);
        await sleep(step.hold ? FRAME_DWELL + step.hold : FRAME_DWELL);
      } else if (step.k === 't') {
        await this.#type(step, run);
        await sleep(KEY_BEAT);
      } else if (step.k === 'p') {
        await this.#paste(step, run);
        await sleep(KEY_BEAT);
      } else if (step.k === 's') {
        // Carries its own frame and its own beat — see `#spin`.
        await this.#spin(step, run);
      } else if (step.k === 'g') {
        this.#announceGui(step);
        await sleep(KEY_BEAT);
      } else {
        // The cap outlives this beat on purpose — see `.term-keys`.
        this.#showKey(step.key);
        await sleep(KEY_BEAT);
      }
    }

    // Only the current run gets to declare the session over. A superseded
    // run reaching here would wipe its replacement's overlays and yank it
    // to the last frame mid-playback.
    if (this.#run !== run) return;
    this.#reset();
    this.#showFrame(this.#frames.length - 1);
  }

  /**
   * Turn the wait indicator, over a frame that holds still.
   *
   * The one step that draws something the recording did not photograph, and
   * the only place on the site where that is true below the prompt line.
   * `components/ui/throbber.ts` sets out why at length; the short version is
   * that a 100ms spinner photographed frame by frame and replayed at a frame
   * dwell each is not a slow spinner, it is a series of stills — and a wait
   * indicator that does not move fails at the one thing it exists to say.
   *
   * So `term-markup.ts` collapses the photographs into the frame they share,
   * and this redraws the single cell they disagreed about, at the cadence
   * the real indicator redraws it.
   *
   * **The beat is the collapsed frames' own.** `beats` is how many
   * photographs went in, so the wait lasts exactly as long as it did when
   * each was dwelt on in turn — which matters beyond taste: a `::flow`
   * anchors its pointer-press to the recording's `hide` marker, and the gap
   * before it is how long the consent window stands there being read. The
   * fixture still sets that length by how many glyphs it photographs, which
   * is what `cli_transcripts.rs` already says it does.
   *
   * Like [`#type`], it writes into an overlay rather than into the frame:
   * the frame stays exactly as the pty painted it, glyph and all, so a
   * replay needs no repair and a reader with JavaScript off still sees a
   * real photograph of a real spinner.
   */
  async #spin(step: Extract<ScriptStep, { k: 's' }>, run: number) {
    this.#reset();
    this.#showFrame(step.i);

    const body = this.#body;
    if (!body) return;

    const cell = document.createElement('span');
    cell.className = 'term-spin';
    cell.style.setProperty('--row', String(step.row + this.#frameRow));
    cell.style.setProperty('--col', String(step.col));
    cell.textContent = step.glyphs[0];
    body.appendChild(cell);

    const beat = step.beats * FRAME_DWELL + (step.hold ?? 0);
    const ticks = Math.max(1, Math.round(beat / THROBBER_TICK_MS));

    for (let i = 1; i <= ticks; i += 1) {
      await sleep(THROBBER_TICK_MS);
      // A superseded run leaves the cell where it is: whatever replaced it
      // has already called `#reset`, and reaching into the DOM after losing
      // the token is how a replacement's first frame gets a hole in it.
      if (this.#run !== run) return;
      cell.textContent = step.glyphs[i % step.glyphs.length];
    }

    cell.remove();
  }

  /**
   * Type text into the visible frame at the recorded cell.
   *
   * Characters go into an overlay rather than into the frame, so the frame
   * stays exactly as recorded and a replay needs no repair.
   */
  async #type(step: Extract<ScriptStep, { k: 't' }>, run: number) {
    const body = this.#body;
    if (!body) return;

    const row = step.row + this.#frameRow;
    const overlay = document.createElement('span');
    overlay.className = 'term-typed';
    overlay.style.setProperty('--row', String(row));
    overlay.style.setProperty('--col', String(step.col));
    body.appendChild(overlay);

    this.#placeCaret(row, step.col);

    for (let i = 1; i <= step.text.length; i += 1) {
      await sleep(TYPE_SPEED);
      // Checked after waking and before writing: a run superseded while
      // this timer was pending must not paint a character onto the frame
      // its replacement is now showing.
      if (this.#run !== run) return;
      overlay.textContent = step.text.slice(0, i);
      this.#placeCaret(row, step.col + i);
    }
  }

  /**
   * Paste text into the visible frame at the recorded cell.
   *
   * The same overlay as [`#type`], filled in one go rather than a character
   * at a time, behind a keycap naming the shortcut. That is the whole visual
   * difference, and it is the right one: typing is a rhythm, pasting is an
   * event, and a reader who sees a secret reference appear whole understands
   * they were meant to copy it rather than transcribe it.
   *
   * The shortcut follows the reader's declared desktop, the same
   * `<html data-os>` the screenshots and `<secreq-window>` follow, because a
   * Windows reader shown `⌘V` has been handed an instruction they cannot
   * carry out.
   */
  async #paste(step: Extract<ScriptStep, { k: 'p' }>, run: number) {
    const body = this.#body;
    if (!body) return;

    this.#showKey(document.documentElement.dataset.os === 'macos' ? 'Cmd+V' : 'Ctrl+V');
    await sleep(KEY_BEAT);
    if (this.#run !== run) return;

    const row = step.row + this.#frameRow;
    const overlay = document.createElement('span');
    overlay.className = 'term-typed';
    overlay.style.setProperty('--row', String(row));
    overlay.style.setProperty('--col', String(step.col));
    overlay.textContent = step.text;
    body.appendChild(overlay);
    this.#placeCaret(row, step.col + step.text.length);
  }

  /**
   * Type the command onto the prompt row.
   *
   * The same character-by-character write, at the same speed and under the
   * same caret, as a recorded `type` step — deliberately, because the point
   * of drawing this line at all is that a reader recognises it as the thing
   * they do. A `steps()` animation would have been less code and would have
   * moved at a different rhythm from the answers typed into the prompts two
   * sections up the page, which is the one comparison a reader is going to
   * make.
   *
   * It writes into the element rather than into a `.term-typed` overlay:
   * there is no frame underneath to leave intact, and the row has to hold
   * the whole command when nothing ever plays.
   */
  async #typeCommand(run: number) {
    const cmd = this.#promptCmd;
    if (!cmd || this.#command === null) return;

    // Nothing has been entered yet, so nothing has been printed yet. The
    // finished session hanging under a half-typed command would read as
    // output that arrived before its command.
    this.#showFrame(-1);

    // Straight off the sigil, so the caret sits on the monospace grid even
    // if the prompt is ever drawn with a different one.
    const col = this.querySelector('.term-prompt-sigil')?.textContent?.length ?? 0;
    cmd.textContent = '';
    this.#placeCaret(0, col);

    for (let i = 1; i <= this.#command.length; i += 1) {
      await sleep(TYPE_SPEED);
      if (this.#run !== run) return;
      cmd.textContent = this.#command.slice(0, i);
      this.#placeCaret(0, col + i);
    }
  }
}

// Reached only through `secreq-terminal.ts`, which imports this module
// dynamically in the browser — so `HTMLElement` above is always defined by
// the time this file is evaluated. The `get` check keeps a hot reload from
// re-defining, which would throw.
if (!customElements.get('secreq-terminal')) {
  customElements.define('secreq-terminal', SecreqTerminal);
}
