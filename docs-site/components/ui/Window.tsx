import { windowHtml, type WindowMarkupOptions } from '../../window-markup';
import './secreq-shot';
import './secreq-window';

/**
 * A captured consent window, rebuilt as DOM rather than shown as a picture.
 *
 * The React counterpart to `::flow`'s window and the sibling of `<Shot />`:
 * same fixture, same index, same caption, same frame — `windowHtml` wraps
 * the exact figure `shotHtml` emits, so this degrades to that screenshot
 * with scripting off or before the geometry lands.
 *
 * Prefer this over `<Shot />` wherever a reader might want to read the
 * window rather than glance at it. The reconstruction is text: selectable,
 * searchable, and read aloud by a screen reader, and it stays sharp at
 * whatever size the column gives it. It is also the cheaper of the two on
 * the wire by roughly an order of magnitude — one cell of geometry is a
 * kilobyte or two compressed against tens of kilobytes of PNG — and
 * because the renders are lazy, a window below the fold usually draws
 * before its screenshot is ever requested.
 *
 *   <Window id="03-nested-tree" />
 */
export function Window({ id, ...options }: { id: string } & WindowMarkupOptions) {
  return <div dangerouslySetInnerHTML={{ __html: windowHtml(id, options) }} />;
}
