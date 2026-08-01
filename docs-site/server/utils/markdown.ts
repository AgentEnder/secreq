import rehypeShiki from '@shikijs/rehype';
import { rehypeGithubAlerts } from 'rehype-github-alerts';
import rehypeRaw from 'rehype-raw';
import rehypeSlug from 'rehype-slug';
import rehypeStringify from 'rehype-stringify';
import remarkDirective from 'remark-directive';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import remarkRehype from 'remark-rehype';
import { unified } from 'unified';
import { DOC_SLUGS } from '../../docs.nav';
import { flowHtml } from '../../flow-markup';
import { screenFlowHtml } from '../../screen-flow-markup';
import { termHtml } from '../../term-markup';
import { applyBaseUrl } from '../../utils/base-url';
import { windowHtml } from '../../window-markup';

// Minimal hast node types — avoids depending on the `hast` package directly
interface HastNode {
  type: string;
  tagName?: string;
  properties?: Record<string, unknown>;
  children?: HastNode[];
  value?: string;
}

// Minimal mdast directive node — `remark-directive` shape
interface DirectiveNode {
  type: string;
  name?: string;
  attributes?: Record<string, string | null | undefined>;
  children?: unknown[];
  data?: Record<string, unknown>;
}

/** Walk a hast tree depth-first, calling `fn` on every element node. */
function walkElements(node: HastNode, fn: (el: HastNode) => void) {
  if (node.type === 'element') fn(node);
  for (const child of node.children ?? []) walkElements(child, fn);
}

/**
 * Rehype plugin: counts the cells in the first <tr> of each <table> and
 * injects `style="--cols: N"` so CSS grid/subgrid knows how many column
 * tracks to create — no client-side JS required.
 */
function rehypeTableCols() {
  return (tree: HastNode) => {
    walkElements(tree, (node) => {
      if (node.tagName !== 'table') return;

      let colCount = 0;
      walkElements(node, (child) => {
        if (child.tagName === 'tr' && colCount === 0) {
          colCount =
            child.children?.filter(
              (c) => c.type === 'element' && (c.tagName === 'th' || c.tagName === 'td'),
            ).length ?? 0;
        }
      });

      if (colCount > 0) {
        node.properties ??= {};
        const existing = (node.properties.style as string) ?? '';
        node.properties.style = existing
          ? `${existing}; --cols: ${colCount}`
          : `--cols: ${colCount}`;
      }
    });
  };
}

const REPO = 'https://github.com/AgentEnder/secreq';

/**
 * Rewrite one relative link from a doc's markdown into a URL this site serves.
 *
 * `../docs/*.md` is read verbatim and cross-references itself the way GitHub
 * wants — `[providers](./providers.md)`. The site serves the same page at
 * `/docs/providers`, extension-less, so shipping those hrefs untouched sends
 * a reader to `/docs/providers.md` and a 404. Four shapes exist in the docs
 * and each has exactly one right answer:
 *
 * - `./providers.md#anchor` — a sibling guide → `/docs/providers#anchor`.
 * - `./wraps.schema.json` — published as a static file → `/schemas/…`.
 * - `../dev-docs/architecture.md`, `../CONTRIBUTING.md` — repo files with no
 *   page here → GitHub, `blob` for a file and `tree` for a directory.
 * - `#headless-use` — an in-page anchor, already correct.
 *
 * A `.md` link into `docs/` that names no page in the nav manifest throws and
 * fails the build. That link is broken on the site no matter what this
 * function returns, and a guide pointing at a page nobody publishes should
 * not publish either — same contract `::shot` holds for a missing fixture.
 */
export function resolveDocHref(href: string): string {
  // Absolute URLs, protocol-relative URLs, and bare anchors are already final.
  if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith('//') || href.startsWith('#')) {
    return href;
  }

  const hashAt = href.indexOf('#');
  const path = hashAt === -1 ? href : href.slice(0, hashAt);
  const hash = hashAt === -1 ? '' : href.slice(hashAt);
  if (path === '') return href;

  // Anything above `docs/` is repo furniture the site does not publish.
  if (path.startsWith('../')) {
    const repoPath = path.replace(/^(\.\.\/)+/, '');
    return `${REPO}/${path.endsWith('/') ? 'tree' : 'blob'}/main/${repoPath}${hash}`;
  }

  const relative = path.replace(/^\.\//, '');

  if (relative.endsWith('.md')) {
    const slug = relative.slice(0, -'.md'.length);
    if (!DOC_SLUGS.includes(slug)) {
      throw new Error(
        `[docs-site] "${href}" points at a doc the nav manifest does not publish. ` +
          `Add "${slug}" to docs.nav.ts, or link it on GitHub with a "../docs/" path.`,
      );
    }
    return applyBaseUrl(`/docs/${slug}`) + hash;
  }

  // The schemas ship as static files so an editor's `$schema` can fetch one.
  if (relative.endsWith('.schema.json')) {
    return applyBaseUrl(`/schemas/${relative}`) + hash;
  }

  return href;
}

/** Rehype plugin: apply {@link resolveDocHref} to every link in a doc. */
function rehypeDocLinks() {
  return (tree: HastNode) => {
    walkElements(tree, (node) => {
      if (node.tagName !== 'a' || !node.properties) return;
      const href = node.properties.href;
      if (typeof href === 'string') node.properties.href = resolveDocHref(href);
    });
  };
}

/** Depth-first walk over an mdast tree. */
function walkNodes(node: DirectiveNode, fn: (node: DirectiveNode) => void) {
  fn(node);
  for (const child of (node.children ?? []) as DirectiveNode[]) walkNodes(child, fn);
}

/**
 * Remark plugin: turn `::shot{id=02-single-pending}` into the captured
 * window, rebuilt from its geometry.
 *
 * A guide can then illustrate itself with the same PNG the test harness
 * renders, placed against the paragraph that explains it:
 *
 *   ::shot{id=24-ssh-sign-pending}
 *   ::shot{id=07-audit-tab caption="Optional override"}
 *
 * The caption, window label and light-appearance render all come from the
 * fixture; `caption` is only for the rare case where a guide needs to say
 * something different about an image than the fixture does.
 *
 * ## Why this emits a window rather than the PNG
 *
 * `windowHtml` wraps the exact figure `shotHtml` produces, so the markup a
 * reader without JavaScript receives is unchanged: the published screenshot,
 * same bytes, same caption, same frame. What the wrapper adds is a
 * `<secreq-window>` that fetches the fixture's geometry and rebuilds the
 * window as DOM in front of it.
 *
 * That is worth doing for every guide screenshot, not just the flows that
 * used to be the only caller. The interesting part of these windows is small
 * type — a process chain, a rule's match clause, a row of the audit log —
 * and rebuilt it is text: selectable, indexed by Pagefind, read aloud by a
 * screen reader, and sharp at whatever width the column gives it. One cell
 * of geometry is also a kilobyte or two against tens of kilobytes of PNG,
 * and the renders are lazy, so a figure below the fold usually draws before
 * its screenshot is ever requested.
 *
 * A fixture whose geometry is missing or unfetchable stays the picture; the
 * element leaves the image alone rather than failing.
 *
 * An unknown id throws, failing the build. A guide that references a
 * screenshot which no longer exists should not quietly publish a hole.
 */
function remarkShot() {
  return (tree: DirectiveNode) => {
    walkNodes(tree, (node) => {
      const isDirective =
        node.type === 'leafDirective' ||
        node.type === 'containerDirective' ||
        node.type === 'textDirective';
      if (!isDirective || node.name !== 'shot') return;

      const id = node.attributes?.id;
      if (!id) {
        throw new Error('[docs-site] ::shot directive is missing an id — use ::shot{id=…}');
      }

      const caption = node.attributes?.caption ?? undefined;
      const html = windowHtml(id, caption === undefined ? {} : { caption });

      // Replace the directive with a raw HTML node. `rehypeRaw` later parses
      // it, so the figure lands in the tree as real elements rather than an
      // escaped string.
      node.type = 'html';
      (node as { value?: string }).value = html;
      node.children = [];
      node.attributes = {};
    });
  };
}

/**
 * Remark plugin: turn `::term{id=wrap-gh}` into a replayable recording of
 * a real terminal session, framed exactly as `<Term />` frames one.
 *
 * A guide can then show the interactive path instead of describing it:
 *
 *   ::term{id=wrap-gh}
 *   ::term{id=init caption="Optional override"}
 *
 * The caption and the command in the title bar come from the fixture in
 * `tests/cli_transcripts.rs`; `caption` is only for the rare case where a
 * guide needs to say something different about a session than the fixture
 * does.
 *
 * The command is drawn as a typed shell line above the frames rather than as
 * a label in the title bar, which is `prompt` in `term-markup.ts` and what
 * `::flow` has always asked for. A recording is spawned straight onto a pty
 * with no shell in it, so it opens on the program already running its first
 * question — and a guide was then obliged to put a fenced code block above
 * the player saying what had been run. That block is the guide narrating what
 * the animation should be showing, and it is one more copy of the command to
 * keep in step. With the prompt line, the recording states it itself.
 *
 * An unknown id throws, failing the build — same contract as `::shot`. A
 * guide claiming to demonstrate a flow nobody recorded should not publish.
 */
function remarkTerm() {
  return (tree: DirectiveNode) => {
    walkNodes(tree, (node) => {
      const isDirective =
        node.type === 'leafDirective' ||
        node.type === 'containerDirective' ||
        node.type === 'textDirective';
      if (!isDirective || node.name !== 'term') return;

      const id = node.attributes?.id;
      if (!id) {
        throw new Error('[docs-site] ::term directive is missing an id — use ::term{id=…}');
      }

      const caption = node.attributes?.caption ?? undefined;
      const html = termHtml(id, { prompt: true, ...(caption === undefined ? {} : { caption }) });

      node.type = 'html';
      (node as { value?: string }).value = html;
      node.children = [];
      node.attributes = {};
    });
  };
}

/**
 * Remark plugin: render either a terminal/native-window flow or a browser
 * screen recording.
 *
 * The two halves of that moment are recorded by two harnesses that know
 * nothing about each other, and this is the seam between them:
 *
 *   ::flow{term=run-gh}
 *   ::flow{term=run-gh caption="Optional override"}
 *
 * For a terminal flow, `term` is the only attribute an author supplies, and there is
 * deliberately no way to name the window. Which fixture rises, and when, is
 * recorded in the transcript's own `gui` markers — repeating it here would
 * be a second place for it to be wrong, and the only one no test checks.
 *
 * A recording with no markers throws, as does one whose markers do not pair
 * up; see `flow-markup.ts` for why each of those is worth stopping a build
 * over.
 */
function remarkFlow() {
  return (tree: DirectiveNode) => {
    walkNodes(tree, (node) => {
      const isDirective =
        node.type === 'leafDirective' ||
        node.type === 'containerDirective' ||
        node.type === 'textDirective';
      if (!isDirective || node.name !== 'flow') return;

      const term = node.attributes?.term;
      const screen = node.attributes?.screen;
      if ((term && screen) || (!term && !screen)) {
        throw new Error(
          '[docs-site] ::flow needs exactly one source — use ::flow{term=…} or ::flow{screen=…}',
        );
      }

      const caption = node.attributes?.caption ?? undefined;
      const options = caption === undefined ? {} : { caption };
      const html = term ? flowHtml(term, options) : screenFlowHtml(screen!, options);

      node.type = 'html';
      (node as { value?: string }).value = html;
      node.children = [];
      node.attributes = {};
    });
  };
}

/**
 * Convert a Markdown string to syntax-highlighted HTML.
 *
 * Pipeline: remarkParse -> remarkGfm -> remarkDirective -> remarkShot
 *   -> remarkTerm -> remarkFlow -> remarkRehype -> rehypeRaw -> rehypeSlug
 *   -> rehypeDocLinks -> rehypeGithubAlerts -> @shikijs/rehype
 *   -> rehypeTableCols -> rehypeStringify
 */
export async function renderMarkdown(md: string): Promise<string> {
  const processor = unified()
    .use(remarkParse)
    .use(remarkGfm)
    .use(remarkDirective)
    .use(remarkShot)
    .use(remarkTerm)
    .use(remarkFlow)
    .use(remarkRehype, { allowDangerousHtml: true })
    .use(rehypeRaw)
    .use(rehypeSlug)
    .use(rehypeDocLinks)
    .use(rehypeGithubAlerts, {})
    // Both palettes are emitted as CSS custom properties on every token, so
    // one build of the HTML serves light and dark. `defaultColor: false`
    // suppresses the inline `color:` that would otherwise pin one of them.
    .use(rehypeShiki, {
      themes: { light: 'github-light', dark: 'github-dark' },
      defaultColor: false,
    })
    .use(rehypeTableCols)
    .use(rehypeStringify);

  const file = await processor.process(md);
  return String(file);
}

/**
 * Strip top-level `<h1>` elements from rendered HTML.
 */
export function stripH1(html: string): string {
  return html.replace(/<h1\b[^>]*>[\s\S]*?<\/h1>\s*/gi, '');
}

/**
 * Extract the first Markdown `# H1` heading text (backticks/links stripped).
 * secreq docs carry no frontmatter, so the H1 is the source of the page title.
 */
export function extractH1(md: string): string | null {
  const match = md.match(/^#\s+(.+?)\s*$/m);
  if (!match) return null;
  return match[1]
    .replace(/`/g, '')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .trim();
}
