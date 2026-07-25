/**
 * The single renderer for a screenshot figure.
 *
 * Both the `<Shot />` React component and the `::shot{id=…}` markdown
 * directive emit this exact HTML, so a screenshot placed in a guide and one
 * placed on the landing page cannot drift apart in markup, styling, or
 * behaviour. Interactivity needs no separate step: the markup wraps the
 * figure in `<secreq-shot>`, which the browser upgrades wherever it lands,
 * so both callers get it on exactly the same terms.
 *
 * Everything a figure knows about itself is generated. `.generated/shots.json`
 * is built by the `secreq-copy-repo-assets` Vite plugin from the harness's
 * `manifest.json` — window kind, caption, and one render per (OS, appearance)
 * cell — joined to dimensions read out of the PNG headers. There is no
 * hand-maintained list of screenshots anywhere in this site.
 *
 * A figure carries every cell of the grid and lets CSS pick one, keyed off
 * `<html data-os>` and `<html data-theme>`. The hidden renders are
 * `loading="lazy"` and `display:none`, so browsers skip fetching them; the
 * reader downloads the desktop they actually have.
 */

import generated from './.generated/shots.json';
import { applyBaseUrl } from './utils/base-url';

interface ShotRender {
  file: string;
  width: number;
  height: number;
}

interface ShotEntry {
  /** `prompt` | `manager` | `badge`, absent until the harness has run. */
  window?: string;
  /** Authored on the fixture in `tests/ui_screenshots.rs`. */
  caption?: string;
  /** os -> appearance -> render. */
  renders: Record<string, Record<string, ShotRender>>;
}

const SHOTS = generated as unknown as Record<string, ShotEntry>;

/** The cell shown when the reader's own desktop was never rendered. */
const FALLBACK_OS = 'macos';
const FALLBACK_APPEARANCE = 'dark';

/** Every screenshot id available to the site, in filename order. */
export function allShotIds(): string[] {
  return Object.keys(SHOTS).sort();
}

function escapeAttr(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function imgTag(
  render: ShotRender,
  os: string,
  appearance: string,
  alt: string,
  fallback: boolean,
  eager: boolean
): string {
  return [
    '<img class="shot-img"',
    `data-os="${escapeAttr(os)}"`,
    `data-appearance="${escapeAttr(appearance)}"`,
    // Marks the one render that shows when no other cell matches — the
    // no-JS case, and any OS the harness does not render.
    fallback ? 'data-fallback="true"' : '',
    `src="${escapeAttr(applyBaseUrl(`/ui/${render.file}`))}"`,
    `width="${render.width}" height="${render.height}"`,
    `alt="${alt}"`,
    `loading="${eager ? 'eager' : 'lazy'}" decoding="async" />`,
  ]
    .filter(Boolean)
    .join(' ');
}

export interface ShotMarkupOptions {
  /** Overrides the fixture's caption. Pass `''` to drop it entirely. */
  caption?: string;
  /** Skip lazy-loading — use for a screenshot above the fold. */
  eager?: boolean;
}

/**
 * Render the figure for `id`.
 *
 * Throws on an id with no render: a screenshot that silently 404s in a guide
 * is worse than a build that stops, and the failure is nearly always a typo
 * or a fixture that has not been regenerated yet.
 */
export function shotHtml(id: string, options: ShotMarkupOptions = {}): string {
  const entry = SHOTS[id];
  if (!entry || Object.keys(entry.renders).length === 0) {
    // No screenshots at all means the fixtures have never been rendered in
    // this checkout — an environment that is not set up, not a mistake in
    // the page. Warn and leave a visible gap so the site still builds for
    // someone working on prose. One *missing* screenshot among many is a
    // different thing: that is a typo or a rename, and it fails the build.
    if (Object.keys(SHOTS).length === 0) {
      console.warn(
        `[docs-site] No screenshots rendered yet — "${id}" and every other figure ` +
          'will be blank. Run `cargo test --test ui_screenshots -- --ignored ' +
          '--test-threads=1` to generate them.'
      );
      return `<figure class="shot shot-missing"><p>Screenshot <code>${escapeAttr(id)}</code> has not been rendered yet.</p></figure>`;
    }
    throw new Error(
      `[docs-site] No screenshot named "${id}". Expected a fixture of that name in ` +
        'tests/ui_screenshots.rs — regenerate with ' +
        '`cargo test --test ui_screenshots -- --ignored --test-threads=1`.'
    );
  }

  const caption = options.caption ?? entry.caption ?? '';
  const alt = escapeAttr(caption.replace(/<[^>]+>/g, '')) || escapeAttr(id);
  const eager = options.eager ?? false;

  // Exactly one render is the fallback. Prefer the canonical cell, but a
  // fixture that only rendered one corner of the grid still gets one.
  const fallbackOs = entry.renders[FALLBACK_OS] ? FALLBACK_OS : Object.keys(entry.renders)[0];
  const fallbackAppearance = entry.renders[fallbackOs][FALLBACK_APPEARANCE]
    ? FALLBACK_APPEARANCE
    : Object.keys(entry.renders[fallbackOs])[0];

  const cells = Object.entries(entry.renders).flatMap(([os, byAppearance]) =>
    Object.entries(byAppearance).map(([appearance, render]) => ({ os, appearance, render }))
  );

  // The CSS picks a cell by exact (os, appearance) match, so an incomplete
  // grid would render a reader on the missing desktop an empty figure.
  // Catching it here means a stale fixture surfaces during the build rather
  // than on someone else's machine.
  if (cells.length < 6) {
    console.warn(
      `[docs-site] "${id}" has ${cells.length} of 6 renders — readers on the ` +
        'missing desktops will see nothing. Regenerate the fixtures.'
    );
  }

  const images = cells
    .map(({ os, appearance, render }) =>
      imgTag(
        render,
        os,
        appearance,
        alt,
        os === fallbackOs && appearance === fallbackAppearance,
        eager
      )
    )
    .join('');

  // `<secreq-shot>` wraps the figure so the browser upgrades it wherever
  // this string lands — inside a markdown page React never touches, or
  // inside `<Shot />`. It only announces clicks; the viewer is elsewhere.
  return [
    '<secreq-shot>',
    `<figure class="shot" data-window="${escapeAttr(entry.window ?? 'screen')}">`,
    '<button type="button" class="shot-zoom" aria-label="View this screenshot full size">',
    images,
    '</button>',
    caption ? `<figcaption>${caption}</figcaption>` : '',
    '</figure>',
    '</secreq-shot>',
  ].join('');
}
