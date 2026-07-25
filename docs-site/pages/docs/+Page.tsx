import { useData } from 'vike-react/useData';
import { Link } from '../../components/Link';
import { StatusDot } from '../../components/ui';
import type { DocsData } from './+data';

export default function DocsPage() {
  const { sections } = useData<DocsData>();
  const total = sections.reduce((n, s) => n + s.docs.length, 0);

  return (
    <div className="animate-fade-in-up">
      {/* Page header */}
      <div className="flex items-start gap-4 mb-10">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <StatusDot color="blue" />
            <span className="telem-key">Documentation</span>
          </div>
          <h1
            className="text-switch-text-bright mb-1"
            style={{
              fontFamily: "'Bebas Neue', sans-serif",
              fontSize: '2.5rem',
              letterSpacing: '0.08em',
            }}
          >
            Reference
          </h1>
          <p className="text-switch-text-dim text-sm leading-relaxed max-w-xl">
            Guides and references for installing, wrapping CLIs with, and operating secreq.
          </p>
        </div>
        <div className="ml-auto hidden md:block">
          <div className="telem-cell text-right">
            <span className="telem-key">Pages</span>
            <span className="telem-val">{total} LOADED</span>
          </div>
        </div>
      </div>

      {sections.map((section) => (
        <section key={section.section} className="mb-10">
          <div className="flex items-center gap-3 mb-4">
            <span className="status-dot amber" />
            <h2
              className="text-switch-text-dim"
              style={{
                fontSize: '0.7rem',
                fontWeight: 700,
                letterSpacing: '0.25em',
                textTransform: 'uppercase',
              }}
            >
              {section.section}
            </h2>
            <div className="flex-1 h-px bg-switch-border" />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {section.docs.map((doc) => (
              <Link key={doc.slug} href={`/docs/${doc.slug}`} className="block no-underline">
                <div className="card-glow border border-switch-border p-5 bg-switch-bg-raised/20 h-full transition-all">
                  <div className="flex items-start gap-3">
                    <span className="status-dot blue mt-1 shrink-0" />
                    <div>
                      <h3
                        className="text-sm font-semibold text-switch-text-bright mb-1 uppercase tracking-wider"
                        style={{ letterSpacing: '0.06em' }}
                      >
                        {doc.label}
                      </h3>
                      <p className="text-sm text-switch-text-dim leading-relaxed">{doc.title}</p>
                    </div>
                    <svg
                      className="w-4 h-4 text-switch-text-dim/40 shrink-0 ml-auto mt-0.5"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </section>
      ))}

      {/* Schemas callout */}
      <section className="mb-6">
        <div className="flex items-center gap-3 mb-4">
          <span className="status-dot green" />
          <h2
            className="text-switch-text-dim"
            style={{ fontSize: '0.7rem', fontWeight: 700, letterSpacing: '0.25em', textTransform: 'uppercase' }}
          >
            Schemas
          </h2>
          <div className="flex-1 h-px bg-switch-border" />
        </div>
        <Link href="/schemas" className="block no-underline">
          <div className="card-glow border border-switch-border p-5 bg-switch-bg-raised/20 transition-all">
            <h3
              className="text-sm font-semibold text-switch-text-bright mb-1 uppercase tracking-wider"
              style={{ letterSpacing: '0.06em' }}
            >
              JSON Schemas
            </h3>
            <p className="text-sm text-switch-text-dim leading-relaxed">
              Point your editor at the <code>wraps.json5</code> and auto-rules schemas for
              completion and validation.
            </p>
          </div>
        </Link>
      </section>
    </div>
  );
}
