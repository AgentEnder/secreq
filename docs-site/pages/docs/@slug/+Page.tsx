import { memo, useEffect, useRef, useState } from 'react';
import { useData } from 'vike-react/useData';
import { Breadcrumb } from '../../../components/Breadcrumb';
import { Link } from '../../../components/Link';
import { sectionAnchor } from '../../../docs.nav';
import '../../../components/ui';
import type { DocDetailData } from './+data';

export default function DocDetailPage() {
  const { doc } = useData<DocDetailData>();

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

        <ProseContent html={doc.renderedHtml} />

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
 * The rendered markdown, and the only thing on this page allowed to write it.
 *
 * `memo` here is load-bearing, not an optimisation. React compares
 * `dangerouslySetInnerHTML` by the identity of the `{__html}` object, which JSX
 * rebuilds every render — so an unmemoised parent re-render re-runs
 * `innerHTML = html` and replaces this whole subtree with a byte-identical copy.
 * That silently detaches every node anything else on the page is holding: the
 * table wrappers and copy buttons below, and every heading the scroll spy
 * observes. The spy would then set the marker exactly once, destroy its own
 * observation targets in the resulting render, and freeze there forever.
 *
 * Memoising on the html string means the parent's `activeHeading` state can
 * change freely without the article underneath it being rebuilt.
 */
const ProseContent = memo(function ProseContent({ html }: { html: string }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const root = ref.current;
    if (!root) return;

    // Screenshots and terminals need no hydration — `<secreq-shot>` and
    // `<secreq-terminal>` upgrade themselves wherever markdown injected
    // them. What's left here is decoration applied to plain markdown
    // output, which owns no element of its own.
    wrapTables(root);
    addCopyButtons(root);
  }, [html]);

  return (
    <div
      ref={ref}
      className="prose-content"
      data-pagefind-body
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
});

/**
 * Where a heading comes to rest when the reader jumps to its anchor — the
 * `scroll-margin-top: 5.5rem` the prose headings carry, clearing the 56px
 * sticky header. Using the same line to decide "the reader is under this
 * heading" is what makes clicking a link in the list agree with scrolling to
 * the same place by hand.
 */
const HEADING_REST_LINE = 88;

/**
 * A heading parked by `scrollIntoView` lands a fraction either side of the rest
 * line — 88.31 one time, 87.73 the next — because the prose above it lays out on
 * subpixel boundaries. Testing the line exactly would let that noise decide
 * whether a link the reader just clicked marks itself or its predecessor.
 */
const REST_LINE_TOLERANCE = 1;

/**
 * Track which heading the reader is currently under: the last one to have
 * crossed the line where an anchor jump would park it.
 *
 * Deliberately reads geometry rather than reacting to intersection events. An
 * observer only reports the targets whose visibility *changed*, so the answer
 * it can give is "of the headings that just moved, which is highest" — which is
 * not the same question. Two short headings crossing together are reported once
 * and the second never gets its turn, and any discontinuous jump (a link in
 * this list, End, Page Down, restoring a hash on load) moves the page without
 * any heading passing through the trigger zone at all, leaving the marker on
 * whatever section the reader has long since left.
 */
function useScrollSpy(ids: string[]): string | null {
  const [active, setActive] = useState<string | null>(null);
  const key = ids.join(',');

  useEffect(() => {
    if (ids.length === 0) return;

    let frame = 0;
    const measure = () => {
      frame = 0;

      // The last section is usually too short to ever reach the line — the page
      // runs out of scroll first — so at the end of the document it is the
      // answer by definition, whatever the geometry says.
      //
      // This is why a heading in the final screenful marks the last one instead
      // of itself: every one of them shares a single scroll position, the
      // document's maximum, so no rule reading scroll position can tell a
      // reader who jumped to one from a reader who reached the end.
      const doc = document.documentElement;
      if (window.scrollY + window.innerHeight >= doc.scrollHeight - 2) {
        setActive(ids[ids.length - 1]);
        return;
      }

      let current: string | null = null;
      for (const id of ids) {
        const el = document.getElementById(id);
        if (el && el.getBoundingClientRect().top <= HEADING_REST_LINE + REST_LINE_TOLERANCE) {
          current = id;
        }
      }
      setActive(current);
    };

    // Coalesce to one measurement per frame: scroll fires far more often than
    // the page paints, and each pass reads a rect per heading.
    const schedule = () => {
      if (!frame) frame = requestAnimationFrame(measure);
    };

    measure();
    window.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', schedule);
    return () => {
      if (frame) cancelAnimationFrame(frame);
      window.removeEventListener('scroll', schedule);
      window.removeEventListener('resize', schedule);
    };
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
