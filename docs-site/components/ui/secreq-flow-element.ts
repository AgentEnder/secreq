/**
 * `<secreq-flow>` — the listener a recording's `gui` markers were waiting
 * for, and the doorman that decides which flow on the page is allowed to
 * move it.
 *
 * ## How little it does with the window
 *
 * `<secreq-terminal>` already knows *when* the consent window rose and fell;
 * it says so and draws nothing, on purpose, so that a recording with markers
 * in it stays replayable on a page with nowhere to put a window.
 * `<secreq-window>` already knows how to draw any fixture it is pointed at,
 * and — given a label — where any control in it sits. The only thing missing
 * was something standing over both of them, and this is it: it hears two
 * kinds of announcement, and turns them into three attributes and two custom
 * properties.
 *
 * | It hears                | It sets                                   |
 * | ----------------------- | ----------------------------------------- |
 * | `gui` show              | `data-up`, and re-aims the window          |
 * | `gui` hide              | `data-up` off, `data-pressed` on           |
 * | a located press target  | `data-aimed`, `--flow-press-x/y`           |
 *
 * Everything visible is CSS (see `pages/flow.css`), for the same reason the
 * hero's interception is: the rest state has to be the *finished*
 * composition, so that a reader with reduced motion — for whom the terminal
 * never plays and this class therefore never hears a thing — gets the window
 * standing, not a stage the choreography abandoned before it started.
 *
 * ## Why the press is anchored to the hide and not to the show
 *
 * The pointer arrives when the window rises and then waits, hand on the
 * button, for as long as the recording waits — and presses at the instant
 * the recording says the window went away. That ordering is the truthful
 * one, and it is the only one that survives the recording changing: the gap
 * between the two markers is however many frames the real command spent
 * spinning, which nothing here knows and nothing here should have to. A
 * pointer that pressed on a fixed delay after the show would sit beside a
 * window it had supposedly already dismissed for the rest of the spinner.
 *
 * The event bubbles, so one listener on the host covers both children
 * wherever inside the figure they sit. Deliberately no shadow DOM, for the
 * reasons `secreq-terminal-element.ts` sets out at length.
 *
 * ## The other half: one flow moves the page at a time
 *
 * A flow's window used to open into a reserved box, so the page never moved
 * and it did not matter how many of them played at once. It is not reserved
 * any more — the figure is the terminal at rest and grows by the height of a
 * consent window while one is up — and the whole reason that is affordable
 * is the rule this class enforces: **at most one flow on the page is ever
 * playing.** Two figures shoving the same paragraph in opposite directions
 * is what makes reflow unbearable; one figure growing under the reader's eye,
 * while they are looking at it, is a thing happening rather than the page
 * misbehaving.
 *
 * Before any of that there is a dwell: a flow does not so much as ask for a
 * turn until half of it has been on screen, continuously, for `DWELL_MS`.
 * A page that reflows under a scroll still in progress is a page fighting
 * the reader for the scrollbar, and the figure they were actually heading
 * for arrives already playing. See `DWELL_MS` for why that long.
 *
 * The queue below is what "wait your turn" means, and it is deliberately
 * three states rather than two — waiting, holding, done — because the
 * interesting cases are all about a flow that is no longer where it was when
 * it asked:
 *
 * - **A turn arrives at a flow that has scrolled away.** It does not play
 *   and it does not lose anything: [`takeTurn`] returns `false`, the turn
 *   passes straight to the next flow in line, and the observer keeps
 *   watching, so the flow asks again the next time it is half on screen.
 *   Playing it anyway would spend the figure where nobody is reading —
 *   the very thing the visibility gate exists to prevent — and holding the
 *   turn *for* it would stall a flow the reader is actually looking at.
 * - **The reader leaves mid-playback.** The flow stands down: the session
 *   stops, the window comes down, the figure animates back to the terminal's
 *   own height, and the turn goes back to the queue. The collapse is
 *   deliberately the thing that happens off screen — see `standDown`.
 * - **A flow errors, or is pulled out of the document, mid-playback.**
 *   Nothing may wedge the queue, so the turn is given back on three
 *   independent paths: the terminal announces the end of a run from a
 *   `finally`, so a script that throws still ends its turn;
 *   `disconnectedCallback` releases it when the element goes away; and
 *   [`TURN_LIMIT_MS`] is the last resort for a run that somehow does neither.
 *
 * A flow plays **once**, automatically, and then rests on the finished
 * transcript with Replay offered — it does not play again when it scrolls
 * back into view. That is what every other recording on the site does, and
 * here it is also the thing that keeps the queue honest: a flow that replayed
 * on every re-entry would move the page every time it crossed the fold, and
 * on a page with several of them a reader scrolling up and down would keep
 * the queue permanently occupied by figures they are scrolling past. So the
 * queue only ever handles first plays and Replays.
 *
 * The two pieces of state that sound alike are deliberately unrelated:
 * `#played` is a one-shot for the life of the element that only Replay
 * re-arms, and `data-up` is the window's height, which goes up and down as
 * often as the reader scrolls. The composition a flow rests in is the same
 * one before its turn and after it — the terminal, its finished transcript,
 * and no window — so there is one rest state to reason about rather than a
 * before and an after.
 */

import {
  DWELL_MS,
  GUI_EVENT,
  TERM_END_EVENT,
  TERM_REPLAY_EVENT,
  VISIBILITY_STEPS,
  isHalfInView,
  prefersReducedMotion,
  type GuiEventDetail,
  type SecreqTerminal,
} from './secreq-terminal-element';
import { PRESS_EVENT, type PressEventDetail } from './secreq-window-element';

/**
 * How long after a session ends before the next flow may start.
 *
 * The recording's own `hide` marker is usually several frames from the end,
 * so by the time a session finishes its window came down long ago and this
 * costs nothing. It is here for the recording that ends *on* the hide: the
 * window's close is the last movement of one figure, and the next figure's
 * first movement should not land inside it. Kept a shade longer than the
 * close in `pages/flow.css`.
 */
const SETTLE_MS = 700;

/**
 * The longest a flow may hold the turn before the queue takes it back.
 *
 * A last resort and nothing else — every ordinary end, stop, teardown and
 * error already releases the turn on its own path. This exists so that a
 * failure nobody predicted costs one figure rather than every figure below
 * it on the page. Five times the longest recording the site publishes
 * (`wrap-gh`, about eleven seconds), so a flow can only hit this if
 * something has genuinely gone wrong.
 */
const TURN_LIMIT_MS = 60_000;

/** The flow allowed to play right now, page-wide. */
let holder: SecreqFlow | null = null;
/** Flows that asked while another was playing, in the order they asked. */
const waiting: SecreqFlow[] = [];

function holdsTurn(flow: SecreqFlow): boolean {
  return holder === flow;
}

function joinQueue(flow: SecreqFlow) {
  if (holder === flow || waiting.includes(flow)) return;
  waiting.push(flow);
  if (!holder) offerTurn();
}

/**
 * Give up the turn, or a place in the queue, or both.
 *
 * Every path out of playback ends here, which is what makes "the queue can
 * never wedge" a property of one function rather than of every caller.
 */
function leaveQueue(flow: SecreqFlow) {
  const place = waiting.indexOf(flow);
  if (place >= 0) waiting.splice(place, 1);
  if (holder !== flow) return;
  holder = null;
  offerTurn();
}

/**
 * Hand the turn down the line until somebody takes it.
 *
 * A loop rather than a single hand-off because stepping aside is an ordinary
 * outcome: a reader who scrolls past three flows in a second queues all
 * three, and the two that are no longer on screen when their turn comes
 * decline it. The loop terminates because every iteration removes one flow
 * from a queue nothing adds to while it runs.
 */
function offerTurn() {
  while (!holder) {
    const next = waiting.shift();
    if (!next) return;
    holder = next;
    if (next.takeTurn()) return;
    holder = null;
  }
}

/**
 * Take the turn out of turn — Replay, and only Replay.
 *
 * A reader who presses Replay is asking for this figure, now, and a button
 * that answered in ten seconds' time would read as a broken button. So the
 * queue yields: whatever was playing stands down, and this flow takes over.
 *
 * The claim is staked *before* the incumbent is stood down, because standing
 * it down releases its turn — and a release with the turn unclaimed would
 * hand it to whichever flow happened to be at the head of the queue, which
 * is not the flow the reader just clicked.
 */
function claimTurn(flow: SecreqFlow) {
  const held = holder;
  holder = flow;
  const place = waiting.indexOf(flow);
  if (place >= 0) waiting.splice(place, 1);
  if (held && held !== flow) held.standDown();
}

export class SecreqFlow extends HTMLElement {
  /**
   * Whether enough of the figure is on screen to be worth playing — and,
   * when its turn comes, whether it still is.
   */
  #onScreen = false;
  /** Whether this flow has already had its one automatic turn. */
  #played = false;
  #observer: IntersectionObserver | null = null;
  /** See [`TURN_LIMIT_MS`], [`SETTLE_MS`] and `DWELL_MS`. `0` is "not armed". */
  #watchdog = 0;
  #settle = 0;
  #dwell = 0;

  connectedCallback() {
    this.addEventListener(GUI_EVENT, this.#onGui);
    this.addEventListener(PRESS_EVENT, this.#onPressTarget);
    this.addEventListener(TERM_END_EVENT, this.#onEnd);
    this.addEventListener(TERM_REPLAY_EVENT, this.#onReplay);

    // Nothing plays, so nothing queues. The window is already standing in
    // the figure — `pages/flow.css` keeps every collapse rule inside
    // `prefers-reduced-motion: no-preference` — and a reader who asked for
    // stillness is looking at the finished composition, not at a stage
    // waiting for a turn that would move the page under them.
    if (prefersReducedMotion()) return;

    // Deferred until the terminal's definition has landed: the whole of
    // this flow's contribution is calling `start()` on it, and an element
    // that has not been upgraded has no such method. The two definitions
    // are imported from the same module graph, so in practice this resolves
    // in the same task — it is the guarantee that is worth having, not the
    // wait.
    void customElements.whenDefined('secreq-terminal').then(() => {
      if (!this.isConnected || this.#observer) return;
      this.#observer = new IntersectionObserver(this.#onIntersect, {
        threshold: VISIBILITY_STEPS,
      });
      this.#observer.observe(this);
    });
  }

  disconnectedCallback() {
    this.removeEventListener(GUI_EVENT, this.#onGui);
    this.removeEventListener(PRESS_EVENT, this.#onPressTarget);
    this.removeEventListener(TERM_END_EVENT, this.#onEnd);
    this.removeEventListener(TERM_REPLAY_EVENT, this.#onReplay);
    this.#observer?.disconnect();
    this.#observer = null;
    this.#onScreen = false;
    // The turn goes back even if this element was pulled out mid-playback —
    // a client-side navigation away from a page with a flow on it must not
    // take the next page's flows down with it.
    this.#release();
    // A client-side navigation mid-playback would otherwise leave the flow
    // reattached elsewhere in whatever state it was in when it was pulled —
    // a window standing over a transcript that had already finished, or a
    // pointer withdrawing from a press nobody saw.
    delete this.dataset.up;
    delete this.dataset.pressed;
  }

  /**
   * Take the turn, or decline it.
   *
   * Called by the queue and by nothing else; `true` means the session has
   * started and the turn is spoken for until this flow gives it back.
   * Declining is not a failure — see the note on off-screen turns at the
   * head of this module.
   */
  takeTurn(): boolean {
    if (!this.#onScreen) return false;
    return this.#begin();
  }

  /**
   * Stop playing and put the figure back the way it rests.
   *
   * Three things, in the order a reader sees them: the session stops on its
   * finished transcript, the window comes down — which is what collapses the
   * shell back to the terminal's own height — and the turn goes back to the
   * queue.
   *
   * ## `unseen`, and the one way this could be worse than the reserve
   *
   * A flow stands down when it leaves the viewport, so the height it gives
   * back is usually given back where nobody is looking. That is fine when it
   * left past the *bottom* edge: everything the collapse moves is below the
   * fold. It is not fine when it left past the **top**, because shrinking a
   * box above the reader pulls the entire page up under them — which is
   * precisely the "content jumping" that reserving the window's space used
   * to make impossible, arriving by another door.
   *
   * The browser is supposed to handle this: scroll anchoring exists for
   * exactly this shape of change. Measured on this page, it does not — the
   * flow collapses by 319px above the viewport, `scrollY` stays where it
   * was, and every paragraph below jumps 319px up the screen. So this does
   * not rely on it. When the figure is above the reader the collapse is not
   * animated at all — there is nobody to animate it *to* — it is shut in a
   * single frame and exactly as much is taken off the scroll offset, so the
   * page under the reader does not move by a pixel.
   *
   * @param unseen the figure has left past the top edge, so the collapse is
   *   invisible and the height it releases has to be paid back to the scroll
   *   offset. Callers that can still be seen — a Replay elsewhere on the
   *   page pre-empting this one — leave it off and get the animation.
   */
  standDown(unseen = false) {
    this.#terminal?.stop();
    if (unseen) this.#shutWithoutMoving();
    else delete this.dataset.up;
    this.#release();
  }

  /**
   * Collapse in one frame, and give the scroll offset the same distance.
   *
   * The forced layout read between the two writes is the point of the whole
   * function: `data-shut` suppresses the transition, so the second
   * measurement is the *settled* height rather than the first frame of an
   * animation, and the difference is exactly what the page is about to lose.
   * `behavior: 'instant'` because the site scrolls smoothly by default, and
   * a smooth correction is a correction the reader would watch happen.
   */
  #shutWithoutMoving() {
    const stage = this.querySelector<HTMLElement>('.flow-stage');
    if (!stage) {
      delete this.dataset.up;
      return;
    }
    const before = stage.getBoundingClientRect().height;
    this.dataset.shut = 'now';
    delete this.dataset.up;
    const after = stage.getBoundingClientRect().height;
    window.scrollBy({ top: after - before, behavior: 'instant' });
    // Given back on the next frame: the suppression is for this one write,
    // and a flow the reader scrolls back to should animate like any other.
    requestAnimationFrame(() => {
      delete this.dataset.shut;
    });
  }

  get #terminal(): SecreqTerminal | null {
    const term = this.querySelector('secreq-terminal');
    // A `<secreq-terminal>` that has not been upgraded is an ordinary
    // unknown element with no `start` on it. Answering "no terminal" is what
    // makes the caller decline its turn rather than throw inside the queue.
    return term && typeof (term as SecreqTerminal).start === 'function'
      ? (term as SecreqTerminal)
      : null;
  }

  /** Start the session, and arm the last-resort release. `false` if it could not. */
  #begin(): boolean {
    const term = this.#terminal;
    if (!term) return false;
    this.#played = true;
    window.clearTimeout(this.#watchdog);
    this.#watchdog = window.setTimeout(() => this.standDown(), TURN_LIMIT_MS);
    term.start();
    return true;
  }

  /** Give the turn back, and disarm the timers that would have. */
  #release() {
    this.#disarm();
    window.clearTimeout(this.#watchdog);
    this.#watchdog = 0;
    window.clearTimeout(this.#settle);
    this.#settle = 0;
    leaveQueue(this);
  }

  /**
   * Two thresholds and a clock, and all three are doing different work.
   *
   * A flow becomes *eligible* when *half* of it is on screen — the
   * terminal's own rule, deliberately reused so a flow never starts a
   * session the terminal would have declined to start — and it only asks for
   * a turn once it has stayed that way for `DWELL_MS`, so that a reader
   * scrolling through the page does not leave a trail of started figures
   * behind them. It stands down only when it is **entirely** gone: a figure
   * taller than the viewport, or one sitting at its edge while the reader
   * nudges the page, would otherwise stop and start itself.
   *
   * The dwell and the queue are two waits and they compose the only way they
   * can: dwell first, queue second, and `takeTurn` asks about visibility
   * again at the moment the turn arrives. A flow can satisfy the dwell, be
   * put in the queue, and be two screens away by the time its turn comes
   * round — so the answer that matters is the one at the end.
   */
  #onIntersect = (entries: IntersectionObserverEntry[]) => {
    for (const entry of entries) {
      const eligible = isHalfInView(entry);
      if (eligible !== this.#onScreen) {
        this.#onScreen = eligible;
        if (eligible) this.#arm();
        else this.#disarm();
      }
      // The one thing that is about leaving rather than arriving, and it is
      // deliberately a different threshold: give the page its height back,
      // but only once there is nobody left to see it happen. Which edge it
      // left by decides how — see `standDown`.
      if (entry.intersectionRatio === 0) {
        const above = entry.boundingClientRect.bottom <= (entry.rootBounds?.top ?? 0);
        if (holdsTurn(this)) this.standDown(above);
        else this.#release();
      }
    }
  };

  /** Start the dwell that ends in a request for a turn. */
  #arm() {
    if (this.#dwell || this.#played) return;
    this.#dwell = window.setTimeout(() => {
      this.#dwell = 0;
      if (!this.#played) joinQueue(this);
    }, DWELL_MS);
  }

  /** Throw the dwell away. A flow that comes back waits out a fresh one. */
  #disarm() {
    window.clearTimeout(this.#dwell);
    this.#dwell = 0;
  }

  /**
   * The session ran out. The turn is this flow's until the window has
   * finished closing — see [`SETTLE_MS`].
   */
  #onEnd = () => {
    if (!holdsTurn(this)) return;
    window.clearTimeout(this.#settle);
    this.#settle = window.setTimeout(() => this.#release(), SETTLE_MS);
  };

  #onReplay = () => {
    claimTurn(this);
    if (!this.#begin()) this.#release();
  };

  /**
   * Which control is pressed in each window, as `flow-defs.ts` declares it.
   *
   * Read fresh rather than parsed once: this is a handful of keys read twice
   * per playback, and caching it would be one more thing to invalidate when
   * the element is reattached with a different flow's markup around it.
   */
  get #presses(): Record<string, string | null> {
    try {
      return JSON.parse(this.dataset.press || '{}');
    } catch {
      return {};
    }
  }

  #onGui = (event: Event) => {
    const detail = (event as CustomEvent<GuiEventDetail>).detail;
    const window = this.querySelector('secreq-window');
    if (!window) return;

    if (detail.action === 'show') {
      // Aimed before it is raised, and raised before it is shown: a flow
      // stepping through several fixtures redraws and re-locates the one it
      // is about to show rather than flipping the previous one over in full
      // view. Same id twice is free — `<secreq-window>` remembers what it
      // has drawn, and answers the aim from the geometry it kept.
      const label = this.#presses[detail.id];
      if (label) window.setAttribute('press', label);
      else window.removeAttribute('press');

      window.setAttribute('shot', detail.id);
      delete this.dataset.pressed;
      this.dataset.up = 'true';
    } else {
      // The `shot` attribute stays on the last fixture shown: the window
      // that stood down is the window that was up, and it is the one still
      // closing on the stage. `data-pressed` outlives the animation for the
      // same reason — the pointer ends its own withdrawal invisible, so
      // there is nothing to clean up, and clearing it on a timer would be a
      // timer racing the replay button.
      delete this.dataset.up;
      if (this.dataset.aimed) this.dataset.pressed = 'true';
    }
  };

  /**
   * A control was found, so the pointer knows where to go.
   *
   * Percentages of the figure rather than points, because the window is
   * built at its captured point size and scaled to the column: a fraction is
   * the one form of this that stays true through a resize, and it costs the
   * pointer no knowledge of the capture at all.
   */
  #onPressTarget = (event: Event) => {
    const detail = (event as CustomEvent<PressEventDetail>).detail;
    this.style.setProperty('--flow-press-x', `${(detail.x * 100).toFixed(3)}%`);
    this.style.setProperty('--flow-press-y', `${(detail.y * 100).toFixed(3)}%`);
    // The gate for the pointer existing at all. A window whose label could
    // not be found — a rename, a fixture that never rendered — plays without
    // one rather than sending it to the middle of the window.
    this.dataset.aimed = 'true';
  };
}

// Reached only through `secreq-flow.ts`, which imports this module
// dynamically in the browser, so `HTMLElement` is always defined by the time
// this file is evaluated.
if (!customElements.get('secreq-flow')) {
  customElements.define('secreq-flow', SecreqFlow);
}
