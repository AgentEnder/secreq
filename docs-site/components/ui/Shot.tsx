import { shotHtml, type ShotMarkupOptions } from '../../shot-markup';
import './secreq-shot';

/**
 * A product screenshot, framed as the window it actually is.
 *
 * No `useEffect` and nothing to hydrate: the markup contains a
 * `<secreq-shot>`, which the browser upgrades on insertion — the same path
 * a screenshot placed by `::shot{id=…}` inside a guide takes. Clicking one
 * raises an event that `<ShotLightbox />` answers from the layout.
 *
 *   <Shot id="02-single-pending" />
 */
export function Shot({ id, ...options }: { id: string } & ShotMarkupOptions) {
  return <div dangerouslySetInnerHTML={{ __html: shotHtml(id, options) }} />;
}
