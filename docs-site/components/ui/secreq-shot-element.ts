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

    // The figure carries one render per OS appearance and hides the rest,
    // so the visible one is the only one worth enlarging.
    const image = [...this.querySelectorAll<HTMLImageElement>('.shot-img')].find(
      (candidate) => candidate.offsetParent !== null,
    );
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
}

if (!customElements.get('secreq-shot')) {
  customElements.define('secreq-shot', SecreqShot);
}
