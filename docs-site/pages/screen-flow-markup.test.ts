import { describe, expect, it } from 'vitest';

import { screenFlowHtml } from '../screen-flow-markup';

describe('screenFlowHtml', () => {
  it('renders the recorded video, poster, dimensions, and fixture caption', () => {
    const html = screenFlowHtml('link-approval');

    expect(html).toContain('class="screen-flow-video"');
    expect(html).toContain('src="/flows/link-approval-flow.webm"');
    expect(html).toContain('poster="/flows/link-approval-poster.png"');
    expect(html).toContain('width="390" height="844"');
    expect(html).toContain('Pair the browser, review the exact request details');
  });

  it('escapes a caption override', () => {
    expect(screenFlowHtml('link-approval', { caption: '<review & approve>' })).toContain(
      '<figcaption>&lt;review &amp; approve&gt;</figcaption>',
    );
  });

  it('fails the build for an unknown recording', () => {
    expect(() => screenFlowHtml('missing')).toThrowError('No browser recording named "missing"');
  });
});
