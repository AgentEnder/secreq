/**
 * Browser-native flow markup.
 *
 * Native consent flows combine a terminal transcript with captured desktop
 * window geometry. The Link UI is already the browser, so reconstructing it
 * as a second miniature app in the docs would be both heavier and less honest.
 * Its harness records the production bundle instead, and this renderer puts
 * those exact bytes behind the same `::flow` Markdown door.
 */

import generated from './.generated/recordings.json';
import { applyBaseUrl } from './utils/base-url';

interface ScreenFlowEntry {
  id: string;
  title: string;
  caption: string;
  width: number;
  height: number;
  video: string;
  poster: string;
}

const RECORDINGS = generated as unknown as Record<string, ScreenFlowEntry>;

function escape(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export interface ScreenFlowMarkupOptions {
  /** Overrides the fixture caption. Pass an empty string to omit it. */
  caption?: string;
}

export function screenFlowHtml(id: string, options: ScreenFlowMarkupOptions = {}): string {
  const entry = RECORDINGS[id];
  if (!entry) {
    throw new Error(
      `[docs-site] No browser recording named "${id}". Expected ` +
        `dev-docs/link-ui-recordings/${id}/recording.json — regenerate with ` +
        '`pnpm --filter @secreq/link-ui record:flows`.',
    );
  }

  const video = escape(applyBaseUrl(`/flows/${entry.video}`));
  const poster = escape(applyBaseUrl(`/flows/${entry.poster}`));
  const title = escape(entry.title);
  const caption = options.caption ?? entry.caption;
  return [
    '<figure class="screen-flow">',
    `<video class="screen-flow-video" controls muted playsinline preload="metadata" poster="${poster}" ` +
      `width="${entry.width}" height="${entry.height}" aria-label="${title}">`,
    `<source src="${video}" type="video/webm">`,
    `<a href="${video}">Watch ${title}</a>`,
    '</video>',
    caption ? `<figcaption>${escape(caption)}</figcaption>` : '',
    '</figure>',
  ].join('');
}
