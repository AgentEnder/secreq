import { join } from 'node:path';
import {
  buildNavigation,
  scanAndRenderDocs,
  type DocPage,
  type NavigationItem,
} from '../server/utils/docs';

// Vike invokes cumulative onCreateGlobalContext hooks concurrently, and its
// production entry starts initialization without awaiting it. Do the async
// filesystem/rendering work while this server module loads so the hook itself
// is synchronous: prerendering can never observe a half-populated context.
const docsDir = join(process.cwd(), '..', 'docs');
const docs = await scanAndRenderDocs(docsDir);
const navigation = buildNavigation(docs);

export function onCreateGlobalContext(context: Partial<GlobalContextServer>): void {
  (context as Record<string, unknown>).docs = Object.fromEntries(docs.map((d) => [d.slug, d]));
  (context as Record<string, unknown>).navigation = navigation;
}

type GlobalContextServer = {
  docs: Record<string, DocPage>;
  navigation: NavigationItem[];
};

declare global {
  namespace Vike {
    interface GlobalContextServer {
      docs: Record<string, DocPage>;
      navigation: NavigationItem[];
    }
    interface GlobalContextClient {
      navigation: NavigationItem[];
    }
  }
}
