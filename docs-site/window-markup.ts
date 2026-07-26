/**
 * The markup for a consent window rebuilt as DOM.
 *
 * A `<secreq-window>` **is** a `::shot` — the same figure, from the same
 * generated index, with the same caption and the same frame — that
 * replaces its own screenshot with the DOM the screenshot is a picture of,
 * once the browser has fetched the geometry and the app's fonts.
 *
 * Wrapping rather than reimplementing is deliberate, and is the whole
 * degradation story in one line. There is no second way to render this
 * figure that could drift from the first, no separate caption to keep in
 * step, and nothing to decide about the no-JavaScript case: what a reader
 * without scripting sees is not a *fallback* for a window, it is the
 * published screenshot of that window, unchanged.
 *
 * @see `components/ui/secreq-window-element.ts` for what the browser then
 *      does with it.
 */

import { shotHtml, type ShotMarkupOptions } from './shot-markup';

export interface WindowMarkupOptions extends ShotMarkupOptions {
  /**
   * Draw one cell of the chrome matrix regardless of the reader's own
   * desktop — `macos-dark`, `gnome-light`. Left off, the window follows
   * `<html data-os>` and `<html data-theme>` the way the screenshots do,
   * and is rebuilt when either moves.
   */
  variant?: string;
  /**
   * A control in this window to locate and announce — `Approve`, `Deny` —
   * by the label the window paints, so that something outside the figure can
   * point at it. The element finds the word in the geometry it drew from and
   * raises `secreq-window-press` with the answer; see `::flow`, which is the
   * only caller that has anywhere to put a pointer.
   */
  press?: string;
}

/**
 * Render the window figure for `id`.
 *
 * Throws on an id with no fixture, by way of `shotHtml` — a window that
 * silently 404s in a guide is worse than a build that stops.
 */
export function windowHtml(id: string, options: WindowMarkupOptions = {}): string {
  const { variant, press, ...shot } = options;
  const pin = variant ? ` variant="${variant.replace(/"/g, '&quot;')}"` : '';
  const aim = press ? ` press="${press.replace(/"/g, '&quot;')}"` : '';
  return `<secreq-window shot="${id.replace(/"/g, '&quot;')}"${pin}${aim}>${shotHtml(id, shot)}</secreq-window>`;
}
