/**
 * `<secreq-shot>` — a product screenshot that can ask to be enlarged.
 *
 * The element deliberately does **not** own the viewer. It knows one thing:
 * that this screenshot was activated, and which image and caption that
 * means. It announces that as a bubbling event and stops there.
 *
 * That split is what lets the two halves of this site cooperate. A
 * screenshot can arrive as raw HTML inside a markdown page, where React has
 * no reach — so the *thumbnail* has to be a custom element. But the viewer
 * is one app-level dialog shared by every screenshot on the page, which is
 * exactly what React and a portal are for. The event is the seam: light-DOM
 * custom elements upgrade themselves wherever they land, `<ShotLightbox />`
 * listens once at the root, and neither knows how the other is built.
 */

import { SHOT_OPEN_EVENT, type ShotOpenDetail, type ShotScene } from './shot-events';

interface SceneHost extends HTMLElement {
  sceneForViewer(): ShotScene | null;
}

/**
 * How far the pointer may travel between press and release and still be a
 * click. A drag across a line of the window's text covers far more than
 * this; a deliberate click covers a pixel or two of hand jitter.
 */
const DRAG_SLOP_PX = 4;

export class SecreqShot extends HTMLElement {
  /** Where the pointer went down, when it went down on this figure. */
  #pressedAt: { x: number; y: number } | null = null;

  connectedCallback() {
    this.addEventListener('pointerdown', this.#onPointerDown);
    this.addEventListener('click', this.#onClick);
  }

  disconnectedCallback() {
    this.removeEventListener('pointerdown', this.#onPointerDown);
    this.removeEventListener('click', this.#onClick);
  }

  #onPointerDown = (event: PointerEvent) => {
    this.#pressedAt = (event.target as HTMLElement | null)?.closest('.shot-zoom')
      ? { x: event.clientX, y: event.clientY }
      : null;
  };

  #onClick = (event: MouseEvent) => {
    const button = (event.target as HTMLElement | null)?.closest('.shot-zoom');
    if (!button) return;

    const pressedAt = this.#pressedAt;
    this.#pressedAt = null;

    // A `<secreq-window>` standing in this figure is real text, and text
    // gets selected by dragging across it — which ends in a click on this
    // button. Opening the viewer on top of the words someone just
    // highlighted is not what they asked for.
    //
    // What separates that drag from a click is how far the pointer
    // travelled, not whether a selection exists. Asking the document the
    // latter answered for the whole page: a paragraph highlighted anywhere,
    // or the reader's own last drag still standing, left the figure refusing
    // to open at all and giving no reason. A press that never moved is a
    // click, and a press that never happened — the keyboard — is one too.
    if (pressedAt) {
      const travelled = Math.hypot(event.clientX - pressedAt.x, event.clientY - pressedAt.y);
      if (travelled > DRAG_SLOP_PX) return;
    }

    const image = this.#enlargeable();
    if (!image) return;
    const sceneHost = this.closest<SceneHost>('secreq-window');

    this.dispatchEvent(
      new CustomEvent<ShotOpenDetail>(SHOT_OPEN_EVENT, {
        detail: {
          source: image,
          caption: this.querySelector('figcaption')?.innerHTML ?? '',
          // The shot and window implementations load independently. The tag
          // name can match before the window custom element has upgraded.
          scene:
            typeof sceneHost?.sceneForViewer === 'function' ? sceneHost.sceneForViewer() : null,
        },
        bubbles: true,
        composed: true,
      }),
    );
  };

  /**
   * The render to enlarge: whichever one the reader is actually looking at.
   *
   * Normally that is simply the visible one — the figure carries one render
   * per cell of the chrome matrix and CSS shows the reader's. When a
   * `<secreq-window>` has rebuilt the window as DOM, none of them is
   * visible, and the element that drew the scene has marked the render it
   * stands in front of. `data-fallback` catches the remaining case: a
   * reader on a desktop the harness never rendered, where the figure was
   * already showing the fallback cell.
   */
  #enlargeable(): HTMLImageElement | null {
    const renders = [...this.querySelectorAll<HTMLImageElement>('.shot-img')];
    return (
      renders.find((candidate) => candidate.offsetParent !== null) ??
      renders.find((candidate) => candidate.dataset.standing === 'true') ??
      renders.find((candidate) => candidate.dataset.fallback === 'true') ??
      null
    );
  }
}

if (!customElements.get('secreq-shot')) {
  customElements.define('secreq-shot', SecreqShot);
}
