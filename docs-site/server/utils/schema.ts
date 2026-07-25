/**
 * Turn a JSON Schema into something a person can read.
 *
 * The schemas are generated from Rust types, so they are exhaustive and
 * verbose — 8KB of `{"type": "object", "additionalProperties": false, …}` in
 * which the part a reader actually wants, the `description` of each field, is
 * buried as a string value. Printing the file is honest but useless: you
 * cannot find `providers.retrieve_batch` in it without scrolling.
 *
 * So the page reads the schema instead of quoting it. This module flattens it
 * into the shape the docs already use elsewhere — a named group with a table
 * of fields, each with a type, a required flag, and prose — and resolves
 * `$ref` into links between those groups. The raw file is still one click
 * away, and still the thing an editor fetches.
 */

/** One piece of a rendered type expression; `anchor` links to a definition. */
export interface TypeToken {
  text: string;
  anchor?: string;
}

export interface SchemaField {
  name: string;
  /** True when `name` is a key *pattern* rather than a literal key. */
  isPattern: boolean;
  required: boolean;
  type: TypeToken[];
  descriptionHtml: string;
  /** Rendered `default`, `enum` and numeric/length bounds. */
  notes: string[];
}

/** The root object, or one entry from `definitions` — both render the same. */
export interface SchemaGroup {
  name: string;
  anchor: string;
  descriptionHtml: string;
  fields: SchemaField[];
  /** `additionalProperties: false` — an unlisted key is a validation error. */
  closed: boolean;
  /** Constraints that belong to the object rather than to one field. */
  notes: string[];
}

interface JsonSchema {
  $ref?: string;
  type?: string | string[];
  title?: string;
  description?: string;
  properties?: Record<string, JsonSchema>;
  patternProperties?: Record<string, JsonSchema>;
  additionalProperties?: boolean | JsonSchema;
  definitions?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  enum?: unknown[];
  default?: unknown;
  minItems?: number;
  minimum?: number;
  maximum?: number;
  anyOf?: JsonSchema[];
  oneOf?: JsonSchema[];
  allOf?: JsonSchema[];
}

/** Anchor for a definition, unique per schema file. */
export function definitionAnchor(file: string, name: string): string {
  const base = file.replace(/\.schema\.json$/, '').replace(/[^a-z0-9]+/gi, '-');
  return `${base}-${name}`.toLowerCase();
}

export function parseSchema(file: string, raw: string): SchemaGroup[] {
  const schema = JSON.parse(raw) as JsonSchema;
  const anchorFor = (name: string) => definitionAnchor(file, name);

  const groups: SchemaGroup[] = [
    {
      name: schema.title ?? file,
      anchor: anchorFor('root'),
      descriptionHtml: inlineMarkdown(schema.description ?? ''),
      fields: fieldsOf(schema, anchorFor),
      closed: isClosed(schema),
      notes: objectNotes(schema),
    },
  ];

  for (const [name, definition] of Object.entries(schema.definitions ?? {})) {
    groups.push({
      name,
      anchor: anchorFor(name),
      descriptionHtml: inlineMarkdown(definition.description ?? ''),
      fields: fieldsOf(definition, anchorFor),
      closed: isClosed(definition),
      notes: objectNotes(definition),
    });
  }

  return groups;
}

type AnchorFor = (definitionName: string) => string;

function fieldsOf(schema: JsonSchema, anchorFor: AnchorFor): SchemaField[] {
  const required = new Set(schema.required ?? []);
  const fields: SchemaField[] = [];

  for (const [name, property] of Object.entries(schema.properties ?? {})) {
    fields.push({
      name,
      isPattern: false,
      required: required.has(name),
      type: typeTokens(property, anchorFor),
      descriptionHtml: inlineMarkdown(property.description ?? ''),
      notes: fieldNotes(property),
    });
  }

  // A pattern key is a real field — in `wraps.json5` it is *the* field, since
  // every wrapped binary is one — so it lists alongside the named ones rather
  // than as a footnote.
  for (const [pattern, property] of Object.entries(schema.patternProperties ?? {})) {
    fields.push({
      name: pattern,
      isPattern: true,
      required: false,
      type: typeTokens(property, anchorFor),
      descriptionHtml: inlineMarkdown(property.description ?? ''),
      notes: fieldNotes(property),
    });
  }

  return fields;
}

/**
 * Whether an unlisted key is an error here.
 *
 * These schemas are generated from Rust types, so nearly every object is
 * closed — which is why this is a flag and not a note. Printed per object it
 * was the same sentence under every table; the page states it once for the
 * whole file and only calls out the objects that differ.
 */
function isClosed(schema: JsonSchema): boolean {
  return (
    schema.additionalProperties === false && Boolean(schema.properties ?? schema.patternProperties)
  );
}

/**
 * Constraints on the object itself that no field column can carry.
 *
 * `anyOf` branches are alternatives to each other, so they collapse into one
 * sentence — `Provider`'s two branches mean "retrieve or read", not two
 * separate requirements that both have to hold.
 */
function objectNotes(schema: JsonSchema): string[] {
  const branches = (schema.anyOf ?? schema.oneOf ?? [])
    .filter((branch) => branch.required?.length)
    .map((branch) => branch.required!.map((name) => `<code>${escapeHtml(name)}</code>`).join(' + '));

  return branches.length > 0 ? [`Requires ${dedupe(branches).join(' or ')}.`] : [];
}

function fieldNotes(schema: JsonSchema): string[] {
  const notes: string[] = [];

  if (schema.default !== undefined) {
    notes.push(`Default <code>${escapeHtml(JSON.stringify(schema.default))}</code>`);
  }
  if (schema.enum) {
    notes.push(`One of ${schema.enum.map((v) => `<code>${escapeHtml(JSON.stringify(v))}</code>`).join(', ')}`);
  }
  if (schema.minItems !== undefined) {
    notes.push(`At least ${schema.minItems} item${schema.minItems === 1 ? '' : 's'}`);
  }
  if (schema.minimum !== undefined) notes.push(`Minimum ${schema.minimum}`);
  if (schema.maximum !== undefined) notes.push(`Maximum ${schema.maximum}`);

  return notes;
}

/**
 * Render a subschema as a type expression: `string`, `string[]`,
 * `string | null`, `{ [key]: Provider }`, `Wrap`.
 *
 * `$ref` becomes a linkable token so a reader can jump to the definition
 * instead of searching the page for it.
 */
export function typeTokens(schema: JsonSchema | undefined, anchorFor: AnchorFor): TypeToken[] {
  if (!schema) return [{ text: 'any' }];

  if (schema.$ref) {
    const name = schema.$ref.replace(/^#\/definitions\//, '');
    return [{ text: name, anchor: anchorFor(name) }];
  }

  const union = schema.anyOf ?? schema.oneOf ?? schema.allOf;
  if (union && !schema.type) {
    const branches = union.filter((branch) => branch.type || branch.$ref || branch.enum);
    if (branches.length > 0) {
      return joinTokens(
        branches.map((branch) => typeTokens(branch, anchorFor)),
        ' | '
      );
    }
  }

  if (schema.enum && !schema.type) {
    return [{ text: schema.enum.map((value) => JSON.stringify(value)).join(' | ') }];
  }

  if (Array.isArray(schema.type)) {
    return [{ text: schema.type.join(' | ') }];
  }

  if (schema.type === 'array') {
    const inner = typeTokens(schema.items, anchorFor);
    // `(a | b)[]` — parenthesised so the brackets bind to the whole union.
    const needsParens = inner.some((token) => token.text.includes('|'));
    return needsParens
      ? [{ text: '(' }, ...inner, { text: ')[]' }]
      : [...inner, { text: '[]' }];
  }

  if (schema.type === 'object' || schema.properties || schema.additionalProperties) {
    const values = schema.additionalProperties;
    if (values && typeof values === 'object') {
      return [{ text: '{ [key]: ' }, ...typeTokens(values, anchorFor), { text: ' }' }];
    }
    return [{ text: 'object' }];
  }

  return [{ text: schema.type ?? 'any' }];
}

function joinTokens(groups: TypeToken[][], separator: string): TypeToken[] {
  return groups.flatMap((tokens, index) =>
    index === 0 ? tokens : [{ text: separator }, ...tokens]
  );
}

/**
 * The schemas' descriptions are written as prose with backtick code spans —
 * they are Rust doc comments — so they get the same treatment here. Only
 * inline code is honoured; a description is one sentence's worth of text and
 * has no business emitting block elements into a table cell.
 */
export function inlineMarkdown(text: string): string {
  return escapeHtml(text).replace(/`([^`]+)`/g, '<code>$1</code>');
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}
