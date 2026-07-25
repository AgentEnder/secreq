import { useEffect } from 'react';
import { useData } from 'vike-react/useData';
import { Link } from '../../../components/Link';
import type { DocDetailData } from './+data';

export default function DocDetailPage() {
  const { doc } = useData<DocDetailData>();

  // Wrap each table in a scrollable container for narrow viewports.
  useEffect(() => {
    document
      .querySelectorAll<HTMLTableElement>('.prose-content table')
      .forEach((table) => {
        if (!table.parentElement?.classList.contains('table-scroll')) {
          const wrapper = document.createElement('div');
          wrapper.className = 'table-scroll';
          table.parentNode?.insertBefore(wrapper, table);
          wrapper.appendChild(table);
        }
      });
  }, [doc?.slug]);

  // Attach copy buttons to every <pre> inside prose-content.
  useEffect(() => {
    document.querySelectorAll<HTMLPreElement>('.prose-content pre').forEach((pre) => {
      if (pre.querySelector('.copy-btn')) return;
      const btn = document.createElement('button');
      btn.className = 'copy-btn';
      btn.textContent = 'Copy';
      btn.addEventListener('click', async () => {
        const code = pre.querySelector('code');
        const text = (code ?? pre).innerText;
        await navigator.clipboard.writeText(text);
        btn.textContent = 'Copied!';
        setTimeout(() => {
          btn.textContent = 'Copy';
        }, 1500);
      });
      pre.appendChild(btn);
    });
  }, [doc?.slug]);

  if (!doc) {
    return (
      <div className="text-center py-24 animate-fade-in">
        <h1
          className="text-switch-text-bright mb-2"
          style={{
            fontFamily: "'Bebas Neue', sans-serif",
            fontSize: '2rem',
            letterSpacing: '0.08em',
          }}
        >
          Page Not Found
        </h1>
        <p className="text-switch-text-dim mb-6 text-sm">
          The requested documentation page could not be found.
        </p>
        <Link
          href="/docs"
          className="inline-flex items-center gap-2 text-switch-accent hover:text-switch-accent-bright transition-colors text-sm uppercase tracking-wider"
          style={{ letterSpacing: '0.06em' }}
        >
          Back to Documentation
        </Link>
      </div>
    );
  }

  return (
    <div className="flex gap-10 animate-fade-in">
      <article className="flex-1 min-w-0">
        {/* Breadcrumb */}
        <nav
          data-pagefind-ignore
          className="inline-flex items-center gap-2 text-[11px] text-switch-text-dim mb-8 px-3 py-1.5 border border-switch-border bg-switch-bg-surface uppercase tracking-wider"
          style={{ letterSpacing: '0.06em' }}
        >
          <span className="status-dot blue" />
          <Link href="/docs" className="hover:text-switch-accent transition-colors">
            Docs
          </Link>
          <svg
            className="w-3 h-3 text-switch-border-light"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
          <span className="text-switch-text font-medium">{doc.title}</span>
        </nav>

        <h1
          className="text-switch-text-bright mb-2"
          style={{
            fontFamily: "'Bebas Neue', sans-serif",
            fontSize: 'clamp(2rem, 5vw, 3rem)',
            letterSpacing: '0.08em',
          }}
        >
          {doc.title}
        </h1>

        <div
          className="h-px mb-10"
          style={{
            background:
              'linear-gradient(to right, #d4920a 0%, rgba(212,146,10,0.15) 40%, transparent 100%)',
          }}
        />

        <div
          className="prose-content"
          data-pagefind-body
          dangerouslySetInnerHTML={{ __html: doc.renderedHtml }}
        />

        {/* Bottom navigation */}
        <div
          data-pagefind-ignore
          className="mt-16 pt-8 border-t border-switch-border flex items-center justify-between"
        >
          <Link
            href="/docs"
            className="inline-flex items-center gap-2 text-sm text-switch-text-dim hover:text-switch-accent transition-colors uppercase tracking-wider"
            style={{ letterSpacing: '0.06em' }}
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M11 17l-5-5m0 0l5-5m-5 5h12"
              />
            </svg>
            All docs
          </Link>
          <div className="telem-cell text-right">
            <span className="telem-key">Section</span>
            <span className="telem-val blue">{doc.section}</span>
          </div>
        </div>
      </article>

      {doc.headings.length > 0 && (
        <aside
          data-pagefind-ignore
          className="hidden xl:block w-48 shrink-0"
          style={{ paddingTop: '0.25rem' }}
        >
          <div className="sticky top-20">
            <div className="flex items-center gap-2 mb-4">
              <span className="w-4 h-px bg-switch-accent/40" />
              <span className="telem-key">On this page</span>
            </div>
            <nav className="space-y-0.5">
              {doc.headings.map((heading) => (
                <a
                  key={heading.id}
                  href={`#${heading.id}`}
                  className={`toc-link block text-xs py-1 transition-colors ${
                    heading.level === 3
                      ? 'pl-5 text-switch-text-dim/70 hover:text-switch-accent'
                      : 'text-switch-text-dim hover:text-switch-accent'
                  }`}
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
