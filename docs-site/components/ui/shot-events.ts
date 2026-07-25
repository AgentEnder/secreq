/**
 * The contract between a screenshot and the viewer.
 *
 * Its own module, with no DOM class in it, so both sides can import it
 * safely: `<secreq-shot>` extends `HTMLElement` and therefore cannot be
 * loaded during pre-render, while `<ShotLightbox />` renders on the server
 * like any other component. A shared constant is the only thing they
 * actually need to agree on.
 */

/** Everything the viewer needs to show a screenshot. */
export interface ShotOpenDetail {
  source: HTMLImageElement;
  caption: string;
}

export const SHOT_OPEN_EVENT = 'secreq:shot-open';

declare global {
  interface DocumentEventMap {
    [SHOT_OPEN_EVENT]: CustomEvent<ShotOpenDetail>;
  }
}
