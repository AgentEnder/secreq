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

/** One entry of the recorded script, as `term-markup.ts` serialises it. */
type ScriptStep =
  | { k: 'f'; i: number; hold?: number }
  | { k: 't'; text: string; row: number; col: number }
  | { k: 'k'; key: string };

/** Milliseconds a frame rests before the next step. */
const FRAME_DWELL = 620;
/** Milliseconds per typed character. Fast enough to read, slow enough to see. */
const TYPE_SPEED = 42;
/** Beat after a keypress, standing in for the moment before a screen reacts. */
const KEY_BEAT = 180;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

function prefersReducedMotion(): boolean {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
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

  connectedCallback() {
    const replay = this.querySelector<HTMLButtonElement>('.term-replay');
    replay?.addEventListener('click', this.#onReplay);

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

    // Play once, on arrival. A docs page with three terminals should not
    // have three animations competing above the fold.
    this.#observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          this.#observer?.disconnect();
          this.#observer = null;
          this.#start();
        }
      },
      { rootMargin: '0px 0px -20% 0px' }
    );
    this.#observer.observe(this);
  }

  disconnectedCallback() {
    // Invalidates any run in flight. Without this, a client-side navigation
    // away from a docs page leaves a playback writing into detached nodes
    // until its script runs out.
    this.#run += 1;
    this.#observer?.disconnect();
    this.#observer = null;
    this.querySelector('.term-replay')?.removeEventListener('click', this.#onReplay);
  }

  #onReplay = () => this.#start();

  get #body(): HTMLElement | null {
    return this.querySelector<HTMLElement>('.term-body');
  }

  get #frames(): HTMLElement[] {
    return [...this.querySelectorAll<HTMLElement>('.term-frame')];
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
   * the `:last-child` fallback on source order — so any instant where no
   * frame held `"true"` painted an empty panel at full height, with
   * nothing thrown to explain it. With the attribute simply absent,
   * "nothing is marked" falls back to the finished session, which is also
   * the no-JavaScript rendering.
   */
  #showFrame(index: number) {
    const frames = this.#frames;
    if (frames.length === 0) return;

    const target = Math.min(Math.max(index, 0), frames.length - 1);
    frames.forEach((frame, i) => {
      if (i === target) frame.dataset.active = 'true';
      else delete frame.dataset.active;
    });
  }

  /** Clear anything a previous run overlaid on the frames. */
  #reset() {
    this.querySelectorAll('.term-typed').forEach((node) => node.remove());
    const caret = this.querySelector<HTMLElement>('.term-caret');
    if (caret) delete caret.dataset.on;
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

  #start() {
    this.#run += 1;
    void this.#play(this.#run);
  }

  async #play(run: number) {
    const body = this.#body;
    if (!body) return;

    const script: ScriptStep[] = JSON.parse(body.dataset.script || '[]');
    this.#reset();

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
      } else {
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
   * Type text into the visible frame at the recorded cell.
   *
   * Characters go into an overlay rather than into the frame, so the frame
   * stays exactly as recorded and a replay needs no repair.
   */
  async #type(step: Extract<ScriptStep, { k: 't' }>, run: number) {
    const body = this.#body;
    if (!body) return;

    const overlay = document.createElement('span');
    overlay.className = 'term-typed';
    overlay.style.setProperty('--row', String(step.row));
    overlay.style.setProperty('--col', String(step.col));
    body.appendChild(overlay);

    this.#placeCaret(step.row, step.col);

    for (let i = 1; i <= step.text.length; i += 1) {
      await sleep(TYPE_SPEED);
      // Checked after waking and before writing: a run superseded while
      // this timer was pending must not paint a character onto the frame
      // its replacement is now showing.
      if (this.#run !== run) return;
      overlay.textContent = step.text.slice(0, i);
      this.#placeCaret(step.row, step.col + i);
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
