import type { PageContextServer } from 'vike/types';
import type { DocPage } from '../../server/utils/docs';
import { DOCS_NAV } from '../../docs.nav';

export interface DocsSection {
  section: string;
  docs: Array<{ slug: string; label: string; title: string }>;
}

export type DocsData = { sections: DocsSection[] };

export function data(pageContext: PageContextServer): DocsData {
  const docsMap: Record<string, DocPage> = pageContext.globalContext.docs;

  const sections: DocsSection[] = DOCS_NAV.map((section) => ({
    section: section.section,
    docs: section.docs
      .filter((d) => docsMap[d.slug])
      .map((d) => ({
        slug: d.slug,
        label: d.label,
        title: docsMap[d.slug].title,
      })),
  }));

  return { sections };
}
