import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { renderMarkdown } from '../../server/utils/markdown';

export interface SchemaDoc {
  /** Static URL an editor's `$schema` can point at. */
  url: string;
  file: string;
  title: string;
  description: string;
  /** Syntax-highlighted JSON. */
  html: string;
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
      let html = '';
      try {
        const raw = await readFile(join(docsDir, s.file), 'utf-8');
        html = await renderMarkdown('```json\n' + raw.trimEnd() + '\n```');
      } catch {
        html = '<p>Schema unavailable.</p>';
      }
      return {
        url: `/schemas/${s.file}`,
        file: s.file,
        title: s.title,
        description: s.description,
        html,
      };
    })
  );

  return { schemas };
}
