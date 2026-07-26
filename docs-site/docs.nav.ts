/**
 * Docs-site-owned navigation manifest.
 *
 * secreq's docs (`../docs/*.md`) are FLAT — no subdirectories, no YAML
 * frontmatter, no `_category_.yml`. Those files are owned by other tickets and
 * treated as read-only prose here. This manifest is the single source of order,
 * grouping, and short sidebar labels. The on-page title is derived from each
 * doc's own `# H1`; `label` is only the compact nav display string.
 */

export interface NavDoc {
  /** Basename of the markdown file in `../docs`, without extension. */
  slug: string;
  /** Short label shown in the sidebar. The page title still comes from the H1. */
  label: string;
}

export interface NavSection {
  section: string;
  docs: NavDoc[];
}

export const DOCS_NAV: NavSection[] = [
  {
    section: 'Getting started',
    docs: [
      { slug: 'install', label: 'Install' },
      { slug: 'getting-started', label: 'Getting started' },
      { slug: 'overview', label: 'Overview' },
    ],
  },
  {
    section: 'Reference',
    docs: [
      { slug: 'cli', label: 'CLI guide' },
      // Generated from the clap tree by
      // `cargo run --example gen-cli-reference`, guarded by
      // `packages/secreq/tests/cli_drift.rs`. It follows the guide because a
      // reader who needs the exhaustive flag list already knows what they are
      // looking for; one arriving cold needs `x` versus `run` explained first.
      { slug: 'cli-reference', label: 'All commands' },
      { slug: 'wraps', label: 'Authoring wraps' },
      { slug: 'providers', label: 'Providers' },
    ],
  },
  {
    section: 'Agents',
    docs: [
      { slug: 'ssh-agent', label: 'SSH agent' },
      { slug: 'secret-agent', label: 'Secret agent' },
      { slug: 'consent-window', label: 'Consent window' },
    ],
  },
  {
    section: 'Advanced',
    docs: [
      { slug: 'wasm-rules', label: 'Programmable rules' },
      { slug: 'platform-support', label: 'Platform support' },
      { slug: 'troubleshooting', label: 'Troubleshooting' },
    ],
  },
];

/** Every doc slug the site renders, in manifest order. */
export const DOC_SLUGS: string[] = DOCS_NAV.flatMap((s) => s.docs.map((d) => d.slug));

/**
 * Anchor id for a section heading on the docs index.
 *
 * Shared with the breadcrumb, whose middle crumb links to `/docs#<anchor>` —
 * they have to agree or the section crumb scrolls nowhere.
 */
export function sectionAnchor(section: string): string {
  return section
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}
