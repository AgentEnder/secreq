import { useData } from 'vike-react/useData';
import { applyBaseUrl } from '../../utils/base-url';
import { StatusDot } from '../../components/ui';
import type { SchemasData } from './+data';

export default function SchemasPage() {
  const { schemas } = useData<SchemasData>();

  return (
    <div className="animate-fade-in-up max-w-4xl">
      <div className="flex items-center gap-2 mb-2">
        <StatusDot color="green" />
        <span className="telem-key">Reference</span>
      </div>
      <h1
        className="text-switch-text-bright mb-2"
        style={{
          fontFamily: "'Bebas Neue', sans-serif",
          fontSize: '2.5rem',
          letterSpacing: '0.08em',
        }}
      >
        JSON Schemas
      </h1>
      <p className="text-switch-text-dim text-sm leading-relaxed max-w-xl mb-10">
        Point your editor at these schemas for completion and validation. Add a{' '}
        <code>$schema</code> key to your config, or register the URL in your editor&apos;s
        JSON/JSON5 schema settings.
      </p>

      {schemas.map((schema) => (
        <section key={schema.file} className="mb-14">
          <div className="flex items-center gap-3 mb-3">
            <span className="status-dot amber" />
            <h2
              className="text-switch-text-bright"
              style={{ fontSize: '1.1rem', fontWeight: 700, letterSpacing: '0.02em' }}
            >
              {schema.title}
            </h2>
          </div>
          <p className="text-switch-text-dim text-sm leading-relaxed mb-3">{schema.description}</p>

          <div className="telem-cell mb-4">
            <span className="telem-key">$schema URL</span>
            <a
              href={applyBaseUrl(schema.url)}
              className="telem-val blue"
              style={{ textDecoration: 'none', wordBreak: 'break-all' }}
            >
              {schema.url}
            </a>
          </div>

          <div className="prose-content" dangerouslySetInnerHTML={{ __html: schema.html }} />
        </section>
      ))}
    </div>
  );
}
