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

// Minimal hast node types — avoids depending on the `hast` package directly
interface HastNode {
  type: string;
  tagName?: string;
  properties?: Record<string, unknown>;
  children?: HastNode[];
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
              (c) => c.type === 'element' && (c.tagName === 'th' || c.tagName === 'td')
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

/**
 * Convert a Markdown string to syntax-highlighted HTML.
 *
 * Pipeline: remarkParse -> remarkGfm -> remarkDirective -> remarkRehype
 *   -> rehypeRaw -> rehypeSlug -> rehypeGithubAlerts -> @shikijs/rehype
 *   -> rehypeTableCols -> rehypeStringify
 */
export async function renderMarkdown(md: string): Promise<string> {
  const processor = unified()
    .use(remarkParse)
    .use(remarkGfm)
    .use(remarkDirective)
    .use(remarkRehype, { allowDangerousHtml: true })
    .use(rehypeRaw)
    .use(rehypeSlug)
    .use(rehypeGithubAlerts, {})
    .use(rehypeShiki, { theme: 'github-dark' })
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
