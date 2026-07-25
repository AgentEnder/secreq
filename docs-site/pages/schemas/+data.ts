import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { renderMarkdown } from '../../server/utils/markdown';
import { parseSchema, type SchemaGroup } from '../../server/utils/schema';

export interface SchemaDoc {
  /** Static URL an editor's `$schema` can point at. */
  url: string;
  file: string;
  title: string;
  description: string;
  /** The root object first, then one entry per named definition. */
  groups: SchemaGroup[];
  /** Syntax-highlighted JSON, kept behind a disclosure. */
  rawHtml: string;
}

export type SchemasData = { schemas: SchemaDoc[] };

const SCHEMAS = [
  {
    file: 'wraps.schema.json',
    title: 'wraps.json5 schema',
    description:
      'The schema for your wrap configuration. Add "$schema" pointing here to get completion and validation while authoring wraps.json5.',
  },
  {
    file: 'auto-rules.schema.json',
    title: 'auto-rules schema',
    description:
      'The schema for programmable auto-rules — the declarative decisions that gate secret release without prompting.',
  },
];

export async function data(): Promise<SchemasData> {
  const docsDir = join(process.cwd(), '..', 'docs');

  const schemas = await Promise.all(
    SCHEMAS.map(async (s) => {
      let groups: SchemaGroup[] = [];
      let rawHtml = '';
      try {
        const raw = await readFile(join(docsDir, s.file), 'utf-8');
        groups = parseSchema(s.file, raw);
        rawHtml = await renderMarkdown('```json\n' + raw.trimEnd() + '\n```');
      } catch {
        rawHtml = '<p>Schema unavailable.</p>';
      }
      return {
        url: `/schemas/${s.file}`,
        file: s.file,
        title: s.title,
        description: s.description,
        groups,
        rawHtml,
      };
    })
  );

  return { schemas };
}
