import type { ApiExportKind, ApiPackage } from 'vike-plugin-typedoc';
import { Link } from '../Link';
import { SectionHeader } from '../ui/SectionHeader';

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
    return <p className="text-text-3 mt-8">This package exports nothing.</p>;
  }

  const byKind = new Map<ApiExportKind, ApiPackage['exports']>();
  for (const exp of apiPackage.exports) {
    const existing = byKind.get(exp.kind);
    if (existing) existing.push(exp);
    else byKind.set(exp.kind, [exp]);
  }

  const sortedKinds = Array.from(byKind.keys()).sort((a, b) => KIND_ORDER[a] - KIND_ORDER[b]);

  return (
    <div className="mt-10 grid gap-9">
      {sortedKinds.map((kind) => {
        const exports = (byKind.get(kind) ?? [])
          .slice()
          .sort((a, b) => a.name.localeCompare(b.name));
        return (
          <section key={kind}>
            <SectionHeader title={KIND_LABELS[kind]} tight />
            <ul className="grid gap-px bg-hairline border border-hairline rounded-lg overflow-hidden md:grid-cols-2">
              {exports.map((exp) => (
                <li key={exp.slug} className="bg-panel">
                  <Link href={exp.path} className="doc-card block no-underline px-4 py-3 h-full">
                    <span className="flex items-baseline gap-2 mb-1">
                      <code className="text-sm text-text">{exp.name}</code>
                      <span className="t-eyebrow">{exp.kind}</span>
                    </span>
                    {exp.description && (
                      <span className="block text-xs leading-relaxed text-text-3 line-clamp-2">
                        {exp.description}
                      </span>
                    )}
                  </Link>
                </li>
              ))}
            </ul>
          </section>
        );
      })}
    </div>
  );
}
