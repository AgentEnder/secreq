import { useEffect, useState } from 'react';
import { useData } from 'vike-react/useData';
import { Breadcrumb } from '../../../components/Breadcrumb';
import { Link } from '../../../components/Link';
import { sectionAnchor } from '../../../docs.nav';
import '../../../components/ui';
import type { DocDetailData } from './+data';

export default function DocDetailPage() {
  const { doc } = useData<DocDetailData>();

  useEffect(() => {
    if (!doc) return;
    const root = document.querySelector('.prose-content');
    if (!root) return;

    // Screenshots and terminals need no hydration — `<secreq-shot>` and
    // `<secreq-terminal>` upgrade themselves wherever markdown injected
    // them. What's left here is decoration applied to plain markdown
    // output, which owns no element of its own.
    wrapTables(root);
    addCopyButtons(root);
  }, [doc?.slug]);

  const activeHeading = useScrollSpy(doc?.headings.map((h) => h.id) ?? []);

  if (!doc) {
    return (
      <div className="py-24 text-center">
        <h1 className="t-title mb-3">No such page</h1>
        <p className="text-sm text-text-3 mb-6">
          That documentation page does not exist. It may have been renamed.
        </p>
        <Link href="/docs" className="btn btn-quiet no-underline">
          Browse the docs
        </Link>
      </div>
    );
  }

  return (
    <div className="flex gap-12">
      <article className="flex-1 min-w-0" style={{ viewTransitionName: 'doc-article' }}>
        <Breadcrumb
          className="mb-7"
          trail={[
            { label: 'Docs', href: '/docs' },
            { label: doc.section, href: `/docs#${sectionAnchor(doc.section)}` },
            { label: doc.label },
          ]}
        />

        <h1 className="t-title mb-8">{doc.title}</h1>

        <div
          className="prose-content"
          data-pagefind-body
          dangerouslySetInnerHTML={{ __html: doc.renderedHtml }}
        />

        <div
          data-pagefind-ignore
          className="mt-16 pt-7 border-t border-hairline flex items-center justify-between gap-4"
        >
          <Link href="/docs" className="text-sm text-text-3 no-underline hover:text-text">
            ← All documentation
          </Link>
          <a
            href={`https://github.com/AgentEnder/secreq/edit/main/docs/${doc.slug}.md`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-text-3 no-underline hover:text-text"
          >
            Edit this page
          </a>
        </div>
      </article>

      {doc.headings.length > 0 && (
        <aside data-pagefind-ignore className="hidden xl:block w-52 shrink-0">
          <div className="sticky top-24">
            <p className="t-eyebrow mb-3">On this page</p>
            <nav>
              {doc.headings.map((heading) => (
                <a
                  key={heading.id}
                  href={`#${heading.id}`}
                  className="toc-link"
                  data-level={heading.level}
                  data-active={activeHeading === heading.id}
                >
                  {heading.text}
                </a>
              ))}
            </nav>
          </div>
        </aside>
      )}
    </div>
  );
}

/**
 * Track which heading the reader is currently under.
 *
 * Watches a narrow band across the upper third of the viewport rather than the
 * whole thing: with a full-height root margin, a short section sandwiched
 * between two long ones never wins, and the marker skips over it entirely.
 */
function useScrollSpy(ids: string[]): string | null {
  const [active, setActive] = useState<string | null>(null);
  const key = ids.join(',');

  useEffect(() => {
    if (ids.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActive(visible[0].target.id);
      },
      { rootMargin: '-80px 0px -66% 0px' }
    );

    for (const id of ids) {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    }
    return () => observer.disconnect();
  }, [key]);

  return active;
}

/** Long tables need to scroll on their own rather than widening the page. */
function wrapTables(root: ParentNode) {
  root.querySelectorAll<HTMLTableElement>('table').forEach((table) => {
    if (table.parentElement?.classList.contains('table-scroll')) return;
    const wrapper = document.createElement('div');
    wrapper.className = 'table-scroll';
    table.parentNode?.insertBefore(wrapper, table);
    wrapper.appendChild(table);
  });
}

function addCopyButtons(root: ParentNode) {
  root.querySelectorAll<HTMLPreElement>('pre').forEach((pre) => {
    if (pre.querySelector('.copy-btn')) return;

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'copy-btn';
    button.textContent = 'Copy';
    button.addEventListener('click', async () => {
      await navigator.clipboard.writeText((pre.querySelector('code') ?? pre).innerText);
      button.textContent = 'Copied';
      button.dataset.copied = 'true';
      setTimeout(() => {
        button.textContent = 'Copy';
        delete button.dataset.copied;
      }, 1600);
    });
    pre.appendChild(button);
  });
}
