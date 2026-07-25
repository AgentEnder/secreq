import type { LinkedApiExport } from 'vike-plugin-typedoc';
import { Link } from '../Link';

export interface ApiExportPageProps {
  apiExport: LinkedApiExport;
}

/** Render a type string as linked HTML when available, else plain text. */
function TypeText({ html, text }: { html?: string; text: string }) {
  if (html && html !== text) {
    return <span dangerouslySetInnerHTML={{ __html: html }} />;
  }
  return <>{text}</>;
}

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <h2
      className="text-switch-accent-bright mb-3 text-xs font-semibold uppercase"
      style={{ letterSpacing: '0.16em' }}
    >
      {children}
    </h2>
  );
}

export function ApiExportPage({ apiExport }: ApiExportPageProps) {
  return (
    <div>
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
        <svg className="w-3 h-3 text-switch-border-light" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>
        <Link href="/api" className="hover:text-switch-accent transition-colors">
          API
        </Link>
        <svg className="w-3 h-3 text-switch-border-light" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>
        <span className="text-switch-text font-medium">{apiExport.name}</span>
      </nav>

      {/* Header */}
      <div className="flex items-center gap-3 mb-2">
        <h1
          className="text-switch-text-bright font-mono"
          style={{ fontSize: 'clamp(1.6rem, 4vw, 2.2rem)' }}
        >
          {apiExport.name}
        </h1>
        <span
          className="inline-block px-2 py-0.5 border border-switch-border text-[10px] uppercase text-switch-accent-bright"
          style={{ letterSpacing: '0.14em' }}
        >
          {apiExport.kind}
        </span>
      </div>

      <div
        className="h-px mb-8"
        style={{
          background:
            'linear-gradient(to right, #d4920a 0%, rgba(212,146,10,0.15) 40%, transparent 100%)',
        }}
      />

      {apiExport.comment?.deprecated && (
        <div className="mb-6 border border-switch-signal-red/40 bg-switch-signal-red/10 px-3 py-2 text-sm text-switch-text">
          <strong className="text-switch-signal-red">Deprecated:</strong>{' '}
          {apiExport.comment.deprecated}
        </div>
      )}

      {/* Signature */}
      {apiExport.signature && (
        <div className="mb-8">
          <SectionHeading>Signature</SectionHeading>
          {apiExport.signatureCodeHtml ? (
            <div
              className="prose-content"
              dangerouslySetInnerHTML={{ __html: apiExport.signatureCodeHtml }}
            />
          ) : (
            <pre className="border border-switch-border bg-switch-bg-surface px-4 py-3 overflow-x-auto">
              <code className="text-sm text-switch-text-bright font-mono">
                {apiExport.signature}
              </code>
            </pre>
          )}
        </div>
      )}

      {/* Description */}
      {(apiExport.descriptionHtml || apiExport.description) && (
        <div className="mb-8">
          {apiExport.descriptionHtml ? (
            <div
              className="prose-content"
              dangerouslySetInnerHTML={{ __html: apiExport.descriptionHtml }}
            />
          ) : (
            <p className="text-switch-text leading-relaxed">{apiExport.description}</p>
          )}
        </div>
      )}

      {/* Parameters */}
      {apiExport.parameters && apiExport.parameters.length > 0 && (
        <div className="mb-8">
          <SectionHeading>Parameters</SectionHeading>
          <div className="table-scroll">
            <table className="w-full text-sm border border-switch-border">
              <thead>
                <tr className="border-b border-switch-border">
                  <th className="text-left px-4 py-2.5 text-switch-accent-bright text-[11px] uppercase" style={{ letterSpacing: '0.1em' }}>Name</th>
                  <th className="text-left px-4 py-2.5 text-switch-accent-bright text-[11px] uppercase" style={{ letterSpacing: '0.1em' }}>Type</th>
                  <th className="text-left px-4 py-2.5 text-switch-accent-bright text-[11px] uppercase" style={{ letterSpacing: '0.1em' }}>Description</th>
                </tr>
              </thead>
              <tbody>
                {apiExport.parameters.map((param) => (
                  <tr key={param.name} className="border-t border-switch-border">
                    <td className="px-4 py-2.5 font-mono text-switch-text-bright text-[0.8125rem]">
                      {param.name}
                      {param.optional && <span className="text-switch-text-dim">?</span>}
                    </td>
                    <td className="px-4 py-2.5">
                      <code className="font-mono text-switch-secondary-bright text-xs">
                        <TypeText html={param.typeHtml} text={param.type} />
                      </code>
                    </td>
                    <td className="px-4 py-2.5 text-switch-text-dim text-[0.8125rem]">
                      {param.description || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Returns */}
      {apiExport.returnType && (
        <div className="mb-8">
          <SectionHeading>Returns</SectionHeading>
          {apiExport.returnTypeCodeHtml ? (
            <div
              className="prose-content"
              dangerouslySetInnerHTML={{ __html: apiExport.returnTypeCodeHtml }}
            />
          ) : (
            <p className="font-mono text-switch-secondary-bright text-sm">
              <TypeText html={apiExport.returnTypeHtml} text={apiExport.returnType} />
            </p>
          )}
        </div>
      )}

      {/* Type parameters */}
      {apiExport.typeParameters && apiExport.typeParameters.length > 0 && (
        <div className="mb-8">
          <SectionHeading>Type parameters</SectionHeading>
          <ul className="space-y-2">
            {apiExport.typeParameters.map((tp) => (
              <li key={tp.name} className="text-sm">
                <code className="font-mono text-switch-text-bright">{tp.name}</code>
                {tp.constraint && (
                  <span className="text-switch-text-dim">
                    {' '}extends{' '}
                    <code className="font-mono text-switch-secondary-bright">
                      <TypeText html={tp.constraintHtml} text={tp.constraint} />
                    </code>
                  </span>
                )}
                {tp.default && (
                  <span className="text-switch-text-dim">
                    {' '}={' '}
                    <code className="font-mono text-switch-secondary-bright">
                      <TypeText html={tp.defaultHtml} text={tp.default} />
                    </code>
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Properties */}
      {apiExport.properties && apiExport.properties.length > 0 && (
        <div className="mb-8">
          <SectionHeading>Properties</SectionHeading>
          <div className="table-scroll">
            <table className="w-full text-sm border border-switch-border">
              <thead>
                <tr className="border-b border-switch-border">
                  <th className="text-left px-4 py-2.5 text-switch-accent-bright text-[11px] uppercase" style={{ letterSpacing: '0.1em' }}>Name</th>
                  <th className="text-left px-4 py-2.5 text-switch-accent-bright text-[11px] uppercase" style={{ letterSpacing: '0.1em' }}>Type</th>
                  <th className="text-left px-4 py-2.5 text-switch-accent-bright text-[11px] uppercase" style={{ letterSpacing: '0.1em' }}>Description</th>
                </tr>
              </thead>
              <tbody>
                {apiExport.properties.map((prop) => (
                  <tr key={prop.name} className="border-t border-switch-border">
                    <td className="px-4 py-2.5 font-mono text-switch-text-bright text-[0.8125rem]">
                      {prop.readonly && <span className="text-switch-text-dim">readonly </span>}
                      {prop.name}
                      {prop.optional && <span className="text-switch-text-dim">?</span>}
                    </td>
                    <td className="px-4 py-2.5">
                      <code className="font-mono text-switch-secondary-bright text-xs">
                        <TypeText html={prop.typeHtml} text={prop.type} />
                      </code>
                    </td>
                    <td className="px-4 py-2.5 text-switch-text-dim text-[0.8125rem]">
                      {prop.description || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Methods */}
      {apiExport.methods && apiExport.methods.length > 0 && (
        <div className="mb-8">
          <SectionHeading>Methods</SectionHeading>
          <div className="space-y-4">
            {apiExport.methods.map((method) => (
              <div key={method.name} className="border border-switch-border p-4">
                <code className="text-sm font-mono text-switch-text-bright block mb-2">
                  <TypeText html={method.signatureHtml} text={method.signature} />
                </code>
                {method.description && (
                  <p className="text-sm text-switch-text-dim">{method.description}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Examples */}
      {apiExport.examplesHtml && apiExport.examplesHtml.length > 0 ? (
        <div className="mb-8">
          <SectionHeading>Examples</SectionHeading>
          {apiExport.examplesHtml.map((html, i) => (
            <div
              key={i}
              className="prose-content mb-3"
              dangerouslySetInnerHTML={{ __html: html }}
            />
          ))}
        </div>
      ) : apiExport.comment?.examples && apiExport.comment.examples.length > 0 ? (
        <div className="mb-8">
          <SectionHeading>Examples</SectionHeading>
          {apiExport.comment.examples.map((example, i) => (
            <pre
              key={i}
              className="border border-switch-border bg-switch-bg-surface px-4 py-3 mb-3 overflow-x-auto"
            >
              <code className="text-sm text-switch-text-bright font-mono">{example}</code>
            </pre>
          ))}
        </div>
      ) : null}

      {/* Remarks */}
      {apiExport.remarksHtml ? (
        <div className="mb-8">
          <SectionHeading>Remarks</SectionHeading>
          <div className="prose-content" dangerouslySetInnerHTML={{ __html: apiExport.remarksHtml }} />
        </div>
      ) : apiExport.comment?.remarks ? (
        <div className="mb-8">
          <SectionHeading>Remarks</SectionHeading>
          <p className="text-switch-text leading-relaxed">{apiExport.comment.remarks}</p>
        </div>
      ) : null}

      {/* Bottom nav */}
      <div
        data-pagefind-ignore
        className="mt-16 pt-8 border-t border-switch-border flex items-center justify-between"
      >
        <Link
          href="/api"
          className="inline-flex items-center gap-2 text-sm text-switch-text-dim hover:text-switch-accent transition-colors uppercase tracking-wider"
          style={{ letterSpacing: '0.06em' }}
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 17l-5-5m0 0l5-5m-5 5h12" />
          </svg>
          API reference
        </Link>
        <div className="telem-cell text-right">
          <span className="telem-key">Symbol</span>
          <span className="telem-val blue">{apiExport.kind}</span>
        </div>
      </div>
    </div>
  );
}
