import { termHtml, type TermMarkupOptions } from '../../term-markup';
import './secreq-terminal';

/**
 * A recorded terminal session, replayed.
 *
 * There is no `useEffect` here and nothing to hydrate: the markup contains
 * a `<secreq-terminal>`, and the browser upgrades it on insertion. That is
 * the same path a session placed by `::term{id=…}` inside a guide takes, so
 * the two cannot behave differently — this component's only job is to put
 * the shared markup on the page.
 *
 * The `import './secreq-terminal'` is load-bearing: it registers the
 * element. Pages that only ever get terminals from markdown pick the
 * definition up through the `components/ui` barrel.
 *
 *   <Term id="wrap-gh" />
 */
export function Term({ id, ...options }: { id: string } & TermMarkupOptions) {
  return <div dangerouslySetInnerHTML={{ __html: termHtml(id, options) }} />;
}
