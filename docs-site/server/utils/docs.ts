import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DOCS_NAV } from '../../docs.nav';
import { extractH1, renderMarkdown, stripH1 } from './markdown';

export interface TocEntry {
  id: string;
  text: string;
  level: number;
}

export interface DocPage {
  slug: string;
  /** On-page title, derived from the doc's own `# H1`. */
  title: string;
  /** Short sidebar label, from the nav manifest. */
  label: string;
  /** Section this doc belongs to, from the nav manifest. */
  section: string;
  order: number;
  renderedHtml: string;
  headings: TocEntry[];
}

export interface NavigationItem {
  title: string;
  path?: string;
  children?: NavigationItem[];
}

/**
 * Extract h2 and h3 headings (with id attributes) from rendered HTML.
 */
export function extractHeadings(html: string): TocEntry[] {
  const headings: TocEntry[] = [];
  const regex = /<h([23])\s[^>]*id="([^"]*)"[^>]*>([\s\S]*?)<\/h\1>/gi;
  for (const match of html.matchAll(regex)) {
    const level = parseInt(match[1], 10);
    const id = match[2];
    const text = match[3].replace(/<[^>]+>/g, '').trim();
    headings.push({ id, text, level });
  }
  return headings;
}

/**
 * Read each doc named in the nav manifest from `docsDir`, render it, and derive
 * a page title from its `# H1`. Order + grouping + label all come from the
 * manifest — the markdown files themselves carry no metadata.
 */
export async function scanAndRenderDocs(docsDir: string): Promise<DocPage[]> {
  const pages: DocPage[] = [];
  let order = 0;

  for (const section of DOCS_NAV) {
    for (const navDoc of section.docs) {
      // Both failures below used to be `console.warn` and carry on, which
      // made every guard downstream of them advisory. A `::flow` naming a
      // fixture that does not exist, a `::term` naming a missing recording,
      // a marker pointing at a renamed screenshot — each throws, and each
      // throw was caught here and turned into a page that built green and
      // shipped a blank section. A warning in a build log that already runs
      // to hundreds of lines is not a signal; it is a place for a bug to
      // live. These are static pages, so anything wrong with one is knowable
      // now, and the only useful time to find out is before it is published.
      const filePath = join(docsDir, `${navDoc.slug}.md`);
      let raw: string;
      try {
        raw = await readFile(filePath, 'utf-8');
      } catch (err) {
        throw new Error(
          `[docs-site] Missing doc for nav entry "${navDoc.slug}": expected ${filePath}.\n` +
            `Either add that file or remove the entry from docs.nav.ts.\n` +
            `Cause: ${(err as Error).message}`,
        );
      }

      const title = extractH1(raw) ?? navDoc.label;

      let renderedHtml: string;
      try {
        renderedHtml = stripH1(await renderMarkdown(raw));
      } catch (err) {
        throw new Error(
          `[docs-site] Markdown rendering failed for "${navDoc.slug}" (${filePath}).\n` +
            `This is usually a directive naming something that is not there — ` +
            `a ::shot or ::flow with an unknown fixture id, or a ::term with an ` +
            `unknown recording.\n` +
            `Cause: ${(err as Error).message}`,
        );
      }

      pages.push({
        slug: navDoc.slug,
        title,
        label: navDoc.label,
        section: section.section,
        order: order++,
        renderedHtml,
        headings: extractHeadings(renderedHtml),
      });
    }
  }

  return pages;
}

/**
 * Build the grouped sidebar navigation from the manifest, appending a synthetic
 * "Schemas" entry that links to the schema-viewer page.
 *
 * The TypeDoc-generated `secreq-rule` SDK reference lives at `/api` (rendered by
 * `vike-plugin-typedoc`, not a markdown doc). It is surfaced as an "SDK API
 * reference" link inside the "Advanced" section, right beside "Programmable
 * rules" — the wasm-rules doc that sends authors to it.
 */
export function buildNavigation(docs: DocPage[]): NavigationItem[] {
  const bySlug = new Map(docs.map((d) => [d.slug, d]));

  const nav: NavigationItem[] = DOCS_NAV.map((section) => ({
    title: section.section,
    children: section.docs
      .filter((d) => bySlug.has(d.slug))
      .map((d) => ({
        title: d.label,
        path: `/docs/${d.slug}`,
      })),
  }));

  const apiLink: NavigationItem = { title: 'SDK API reference', path: '/api' };
  const advanced = nav.find((item) => item.title === 'Advanced');
  if (advanced?.children) {
    const wasmIdx = advanced.children.findIndex((c) => c.path === '/docs/wasm-rules');
    advanced.children.splice(wasmIdx >= 0 ? wasmIdx + 1 : advanced.children.length, 0, apiLink);
  } else {
    nav.push({ title: 'Advanced', children: [apiLink] });
  }

  nav.push({ title: 'Schemas', path: '/schemas' });

  return nav;
}
