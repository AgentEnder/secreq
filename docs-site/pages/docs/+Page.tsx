import { useData } from 'vike-react/useData';
import { Link } from '../../components/Link';
import { SectionHeader } from '../../components/ui/SectionHeader';
import { sectionAnchor } from '../../docs.nav';
import type { DocsData } from './+data';

export default function DocsPage() {
  const { sections } = useData<DocsData>();

  return (
    <div>
      <header className="mb-12">
        <p className="t-eyebrow mb-4">Documentation</p>
        <h1 className="t-title mb-4">Everything secreq does</h1>
        <p className="t-lede max-w-[54ch]">
          Start with the install guide, then wrap your first CLI. The reference sections cover
          authoring wraps, the providers secreq can read from, and the two agents it can stand in
          for.
        </p>
      </header>

      <div className="grid gap-10">
        {sections.map((section) => (
          <section
            key={section.section}
            id={sectionAnchor(section.section)}
            className="scroll-mt-24"
          >
            <SectionHeader title={section.section} tight />

            <ul className="grid gap-px bg-hairline border border-hairline rounded-lg overflow-hidden sm:grid-cols-2">
              {section.docs.map((doc) => (
                <li key={doc.slug} className="bg-panel">
                  <Link
                    href={`/docs/${doc.slug}`}
                    className="doc-card block no-underline p-5 h-full"
                  >
                    <span className="t-heading block mb-1.5">{doc.label}</span>
                    <span className="block text-sm leading-relaxed text-text-3">{doc.title}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </section>
        ))}

        <section>
          <SectionHeader title="Machine-readable" tight />
          <ul className="grid gap-px bg-hairline border border-hairline rounded-lg overflow-hidden sm:grid-cols-2">
            <li className="bg-panel">
              <Link href="/schemas" className="doc-card block no-underline p-5 h-full">
                <span className="t-heading block mb-1.5">JSON Schemas</span>
                <span className="block text-sm leading-relaxed text-text-3">
                  Point your editor at the <code>wraps.json5</code> and auto-rules schemas for
                  completion and validation as you type.
                </span>
              </Link>
            </li>
            <li className="bg-panel">
              <Link href="/api" className="doc-card block no-underline p-5 h-full">
                <span className="t-heading block mb-1.5">SDK API reference</span>
                <span className="block text-sm leading-relaxed text-text-3">
                  The <code>secreq-rule</code> package, for rules that need more than pattern
                  matching.
                </span>
              </Link>
            </li>
          </ul>
        </section>
      </div>
    </div>
  );
}
