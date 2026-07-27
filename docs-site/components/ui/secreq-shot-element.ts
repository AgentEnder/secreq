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

import { SHOT_OPEN_EVENT, type ShotOpenDetail } from './shot-events';

export class SecreqShot extends HTMLElement {
  connectedCallback() {
    this.addEventListener('click', this.#onClick);
  }

  disconnectedCallback() {
    this.removeEventListener('click', this.#onClick);
  }

  #onClick = (event: Event) => {
    const button = (event.target as HTMLElement | null)?.closest('.shot-zoom');
    if (!button) return;

    // A `<secreq-window>` standing in this figure is real text, and text
    // gets selected by dragging across it — which ends in a click on this
    // button. Opening the viewer on top of the words someone just
    // highlighted is not what they asked for.
    if (!document.getSelection()?.isCollapsed) return;

    const image = this.#enlargeable();
    if (!image) return;

    this.dispatchEvent(
      new CustomEvent<ShotOpenDetail>(SHOT_OPEN_EVENT, {
        detail: {
          source: image,
          caption: this.querySelector('figcaption')?.innerHTML ?? '',
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
