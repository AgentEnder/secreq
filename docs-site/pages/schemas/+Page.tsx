import { useData } from 'vike-react/useData';
import type { SchemaField, SchemaGroup, TypeToken } from '../../server/utils/schema';
import { applyBaseUrl } from '../../utils/base-url';
import type { SchemaDoc, SchemasData } from './+data';

/**
 * The schemas, read rather than quoted.
 *
 * Each file is flattened at build time into its root object plus its named
 * definitions, and every `$ref` becomes a link between them — so `providers`
 * takes you to `Provider` instead of leaving you to find it by eye in 8KB of
 * JSON. The raw document stays one disclosure away, because that is what an
 * editor fetches and what a reader eventually wants to diff.
 */
export default function SchemasPage() {
  const { schemas } = useData<SchemasData>();

  return (
    <div className="max-w-4xl">
      <header className="mb-12">
        <p className="t-eyebrow mb-4">Reference</p>
        <h1 className="t-title mb-4">JSON Schemas</h1>
        <p className="t-lede max-w-[54ch]">
          Point your editor at these and it will complete and validate secreq&apos;s config as
          you type. Add a <code>$schema</code> key to the file, or register the URL in your
          editor&apos;s JSON settings.
        </p>
      </header>

      <div className="grid gap-16">
        {schemas.map((schema) => (
          <SchemaSection key={schema.file} schema={schema} />
        ))}
      </div>
    </div>
  );
}

function SchemaSection({ schema }: { schema: SchemaDoc }) {
  const [root, ...definitions] = schema.groups;
  // Said once for the file when it holds everywhere, and per-object only
  // where it doesn't — otherwise it is the same sentence under every table.
  const allClosed = schema.groups.length > 0 && schema.groups.every((group) => group.closed);

  return (
    <section>
      <h2 className="t-heading mb-2">{schema.title}</h2>
      <p className="text-sm leading-relaxed text-text-2 mb-5 max-w-[60ch]">{schema.description}</p>

      <a
        href={applyBaseUrl(schema.url)}
        className="schema-url well flex items-baseline gap-3 px-3 py-2.5 mb-7 no-underline"
      >
        <span className="t-eyebrow shrink-0">URL</span>
        <span className="font-mono text-xs text-accent break-all">{schema.url}</span>
      </a>

      {definitions.length > 0 && (
        <nav className="flex flex-wrap gap-2 mb-5" aria-label={`${schema.title} definitions`}>
          {definitions.map((group) => (
            <a key={group.anchor} href={`#${group.anchor}`} className="schema-chip">
              {group.name}
            </a>
          ))}
        </nav>
      )}

      {allClosed && (
        <p className="t-meta mb-8">
          Every object below is closed — a key that isn&apos;t listed is a validation error.
        </p>
      )}

      {root && <Group group={root} isRoot showClosed={!allClosed} />}
      {definitions.map((group) => (
        <Group key={group.anchor} group={group} showClosed={!allClosed} />
      ))}

      <details className="schema-raw">
        <summary>Raw schema</summary>
        <div className="prose-content" dangerouslySetInnerHTML={{ __html: schema.rawHtml }} />
      </details>
    </section>
  );
}

function Group({
  group,
  isRoot = false,
  showClosed = false,
}: {
  group: SchemaGroup;
  isRoot?: boolean;
  showClosed?: boolean;
}) {
  const notes = showClosed && group.closed ? [CLOSED_NOTE, ...group.notes] : group.notes;

  return (
    <section id={group.anchor} className="mb-9 scroll-mt-24">
      <div className="flex items-baseline gap-4 mb-3">
        {isRoot ? (
          <h3 className="t-eyebrow shrink-0">Top level</h3>
        ) : (
          <h3 className="schema-def shrink-0">{group.name}</h3>
        )}
        <span className="flex-1 h-px bg-hairline" />
      </div>

      {group.descriptionHtml && (
        <p
          className="text-sm leading-relaxed text-text-2 mb-4 max-w-[68ch]"
          dangerouslySetInnerHTML={{ __html: group.descriptionHtml }}
        />
      )}

      {group.fields.length > 0 && (
        <div className="table-scroll">
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th className="api-th">Key</th>
                <th className="api-th">Type</th>
                <th className="api-th">Description</th>
              </tr>
            </thead>
            <tbody>
              {group.fields.map((field) => (
                <Field key={field.name} field={field} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {notes.length > 0 && (
        <ul className="mt-3 grid gap-1.5">
          {notes.map((note) => (
            <li
              key={note}
              className="t-meta pl-3 border-l border-hairline-strong"
              dangerouslySetInnerHTML={{ __html: note }}
            />
          ))}
        </ul>
      )}
    </section>
  );
}

function Field({ field }: { field: SchemaField }) {
  return (
    <tr>
      <td className="api-td font-mono text-text">
        <span className={field.isPattern ? 'schema-key-pattern' : undefined}>{field.name}</span>
        {field.required && (
          <abbr className="schema-required" title="Required">
            *
          </abbr>
        )}
      </td>
      <td className="api-td">
        <code className="text-xs text-accent">
          {field.type.map((token, index) => (
            <TypeText key={index} token={token} />
          ))}
        </code>
      </td>
      <td className="api-td text-text-3">
        {field.isPattern && <span className="schema-tag">any matching key</span>}
        {field.descriptionHtml ? (
          <span dangerouslySetInnerHTML={{ __html: field.descriptionHtml }} />
        ) : (
          !field.isPattern && field.notes.length === 0 && '—'
        )}
        {field.notes.length > 0 && (
          <span className="schema-notes">
            {field.notes.map((note, index) => (
              <span key={note}>
                {index > 0 && <span aria-hidden="true"> · </span>}
                <span dangerouslySetInnerHTML={{ __html: note }} />
              </span>
            ))}
          </span>
        )}
      </td>
    </tr>
  );
}

const CLOSED_NOTE = 'A key that is not listed here is a validation error.';

/** A `$ref` renders as a jump to that definition's table; plain text otherwise. */
function TypeText({ token }: { token: TypeToken }) {
  if (!token.anchor) return <>{token.text}</>;
  return (
    <a href={`#${token.anchor}`} className="schema-ref">
      {token.text}
    </a>
  );
}
