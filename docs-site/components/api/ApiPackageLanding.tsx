import type { ApiExportKind, ApiPackage } from 'vike-plugin-typedoc';
import { Link } from '../Link';

export interface ApiPackageLandingProps {
  apiPackage: ApiPackage;
}

const KIND_ORDER: Record<ApiExportKind, number> = {
  function: 0,
  class: 1,
  interface: 2,
  type: 3,
  enum: 4,
  variable: 5,
};

const KIND_LABELS: Record<ApiExportKind, string> = {
  function: 'Functions',
  class: 'Classes',
  interface: 'Interfaces',
  type: 'Types',
  enum: 'Enums',
  variable: 'Variables',
};

export function ApiPackageLanding({ apiPackage }: ApiPackageLandingProps) {
  if (apiPackage.exports.length === 0) {
    return (
      <p className="text-switch-text-dim mt-8">This package exports nothing.</p>
    );
  }

  const byKind = new Map<ApiExportKind, ApiPackage['exports']>();
  for (const exp of apiPackage.exports) {
    const existing = byKind.get(exp.kind);
    if (existing) existing.push(exp);
    else byKind.set(exp.kind, [exp]);
  }

  const sortedKinds = Array.from(byKind.keys()).sort(
    (a, b) => KIND_ORDER[a] - KIND_ORDER[b]
  );

  return (
    <div className="mt-10">
      <div className="flex items-center gap-2 mb-5">
        <span className="w-4 h-px bg-switch-accent/40" />
        <span className="telem-key">Exports</span>
      </div>

      {sortedKinds.map((kind) => {
        const exports = (byKind.get(kind) ?? [])
          .slice()
          .sort((a, b) => a.name.localeCompare(b.name));
        return (
          <section key={kind} className="mb-8">
            <h2
              className="text-switch-secondary-bright mb-3 text-xs font-semibold uppercase"
              style={{ letterSpacing: '0.16em' }}
            >
              {KIND_LABELS[kind]}
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {exports.map((exp) => (
                <Link
                  key={exp.slug}
                  href={exp.path}
                  className="block no-underline border border-switch-border bg-switch-bg-surface/60 hover:border-switch-border-accent hover:bg-switch-bg-surface transition-colors"
                  style={{ padding: '0.75rem 0.9rem' }}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <code className="text-sm font-mono text-switch-text-bright">
                      {exp.name}
                    </code>
                    <span
                      className="text-[10px] text-switch-text-dim uppercase"
                      style={{ letterSpacing: '0.14em' }}
                    >
                      {exp.kind}
                    </span>
                  </div>
                  {exp.description && (
                    <p className="text-xs text-switch-text-dim leading-relaxed line-clamp-2">
                      {exp.description}
                    </p>
                  )}
                </Link>
              ))}
            </div>
          </section>
        );
      })}
    </div>
  );
}
