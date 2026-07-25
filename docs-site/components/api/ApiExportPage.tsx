import type { LinkedApiExport } from 'vike-plugin-typedoc';
import { Breadcrumb } from '../Breadcrumb';
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

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-9">
      <div className="flex items-center gap-4 mb-4">
        <h2 className="t-eyebrow shrink-0">{title}</h2>
        <span className="flex-1 h-px bg-hairline" />
      </div>
      {children}
    </section>
  );
}

function MemberTable({
  rows,
}: {
  rows: {
    key: string;
    name: React.ReactNode;
    type: React.ReactNode;
    description?: string;
  }[];
}) {
  return (
    <div className="table-scroll">
      <table className="w-full text-sm">
        <thead>
          <tr>
            <th className="api-th">Name</th>
            <th className="api-th">Type</th>
            <th className="api-th">Description</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key}>
              <td className="api-td font-mono text-text">{row.name}</td>
              <td className="api-td">
                <code className="text-xs text-accent">{row.type}</code>
              </td>
              <td className="api-td text-text-3">{row.description || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ApiExportPage({ apiExport }: ApiExportPageProps) {
  return (
    <div style={{ viewTransitionName: 'doc-article' }}>
      <Breadcrumb
        className="mb-7"
        trail={[
          { label: 'Docs', href: '/docs' },
          { label: 'API', href: '/api' },
          { label: apiExport.name },
        ]}
      />

      <div className="flex items-baseline flex-wrap gap-3 mb-8">
        <h1 className="t-title font-mono">{apiExport.name}</h1>
        <span className="t-eyebrow">{apiExport.kind}</span>
      </div>

      {apiExport.comment?.deprecated && (
        <p className="mb-7 well border-l-2 border-l-deny px-4 py-3 text-sm text-text-2">
          <strong className="text-deny">Deprecated.</strong> {apiExport.comment.deprecated}
        </p>
      )}

      {apiExport.signature && (
        <Section title="Signature">
          {apiExport.signatureCodeHtml ? (
            <div
              className="prose-content"
              dangerouslySetInnerHTML={{ __html: apiExport.signatureCodeHtml }}
            />
          ) : (
            <pre className="well px-4 py-3 overflow-x-auto">
              <code className="text-sm text-text">{apiExport.signature}</code>
            </pre>
          )}
        </Section>
      )}

      {(apiExport.descriptionHtml || apiExport.description) && (
        <div className="mb-9">
          {apiExport.descriptionHtml ? (
            <div
              className="prose-content"
              dangerouslySetInnerHTML={{ __html: apiExport.descriptionHtml }}
            />
          ) : (
            <p className="text-text-2 leading-relaxed">{apiExport.description}</p>
          )}
        </div>
      )}

      {apiExport.parameters && apiExport.parameters.length > 0 && (
        <Section title="Parameters">
          <MemberTable
            rows={apiExport.parameters.map((param) => ({
              key: param.name,
              name: (
                <>
                  {param.name}
                  {param.optional && <span className="text-text-3">?</span>}
                </>
              ),
              type: <TypeText html={param.typeHtml} text={param.type} />,
              description: param.description,
            }))}
          />
        </Section>
      )}

      {apiExport.returnType && (
        <Section title="Returns">
          {apiExport.returnTypeCodeHtml ? (
            <div
              className="prose-content"
              dangerouslySetInnerHTML={{ __html: apiExport.returnTypeCodeHtml }}
            />
          ) : (
            <p className="font-mono text-accent text-sm">
              <TypeText html={apiExport.returnTypeHtml} text={apiExport.returnType} />
            </p>
          )}
        </Section>
      )}

      {apiExport.typeParameters && apiExport.typeParameters.length > 0 && (
        <Section title="Type parameters">
          <ul className="grid gap-2">
            {apiExport.typeParameters.map((tp) => (
              <li key={tp.name} className="text-sm">
                <code className="text-text">{tp.name}</code>
                {tp.constraint && (
                  <span className="text-text-3">
                    {' '}
                    extends{' '}
                    <code className="text-accent">
                      <TypeText html={tp.constraintHtml} text={tp.constraint} />
                    </code>
                  </span>
                )}
                {tp.default && (
                  <span className="text-text-3">
                    {' '}
                    ={' '}
                    <code className="text-accent">
                      <TypeText html={tp.defaultHtml} text={tp.default} />
                    </code>
                  </span>
                )}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {apiExport.properties && apiExport.properties.length > 0 && (
        <Section title="Properties">
          <MemberTable
            rows={apiExport.properties.map((prop) => ({
              key: prop.name,
              name: (
                <>
                  {prop.readonly && <span className="text-text-3">readonly </span>}
                  {prop.name}
                  {prop.optional && <span className="text-text-3">?</span>}
                </>
              ),
              type: <TypeText html={prop.typeHtml} text={prop.type} />,
              description: prop.description,
            }))}
          />
        </Section>
      )}

      {apiExport.methods && apiExport.methods.length > 0 && (
        <Section title="Methods">
          <ul className="grid gap-3">
            {apiExport.methods.map((method) => (
              <li key={method.name} className="well p-4">
                <code className="text-sm text-text block mb-2">
                  <TypeText html={method.signatureHtml} text={method.signature} />
                </code>
                {method.description && (
                  <p className="text-sm text-text-3">{method.description}</p>
                )}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {apiExport.examplesHtml && apiExport.examplesHtml.length > 0 ? (
        <Section title="Examples">
          {apiExport.examplesHtml.map((html, i) => (
            <div key={i} className="prose-content mb-3" dangerouslySetInnerHTML={{ __html: html }} />
          ))}
        </Section>
      ) : apiExport.comment?.examples && apiExport.comment.examples.length > 0 ? (
        <Section title="Examples">
          {apiExport.comment.examples.map((example, i) => (
            <pre key={i} className="well px-4 py-3 mb-3 overflow-x-auto">
              <code className="text-sm text-text">{example}</code>
            </pre>
          ))}
        </Section>
      ) : null}

      {apiExport.remarksHtml ? (
        <Section title="Remarks">
          <div
            className="prose-content"
            dangerouslySetInnerHTML={{ __html: apiExport.remarksHtml }}
          />
        </Section>
      ) : apiExport.comment?.remarks ? (
        <Section title="Remarks">
          <p className="text-text-2 leading-relaxed">{apiExport.comment.remarks}</p>
        </Section>
      ) : null}

      <div data-pagefind-ignore className="mt-16 pt-7 border-t border-hairline">
        <Link href="/api" className="text-sm text-text-3 no-underline hover:text-text">
          ← API reference
        </Link>
      </div>
    </div>
  );
}
