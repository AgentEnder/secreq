import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildScene, type WindowScene } from './secreq-window-element';

interface LayoutFile {
  variants: Record<string, WindowScene>;
}

const fontsDescriptor = Object.getOwnPropertyDescriptor(document, 'fonts');

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.replaceChildren();
  if (fontsDescriptor) Object.defineProperty(document, 'fonts', fontsDescriptor);
  else Reflect.deleteProperty(document, 'fonts');
});

function fixture(id: string): WindowScene {
  const path = join(process.cwd(), '..', 'dev-docs', 'ui-screenshots', id, 'layout.json');
  const layout = JSON.parse(readFileSync(path, 'utf8')) as LayoutFile;
  return layout.variants['macos-dark'];
}

function fixtureVariant(id: string, variant: string): WindowScene {
  const path = join(process.cwd(), '..', 'dev-docs', 'ui-screenshots', id, 'layout.json');
  const layout = JSON.parse(readFileSync(path, 'utf8')) as LayoutFile;
  return layout.variants[variant];
}

describe('buildScene', () => {
  it('draws the committed rules paths', () => {
    const scene = buildScene(fixture('09-rules-tab-list'));

    expect(scene.querySelectorAll('path')).toHaveLength(2);
    expect(scene.querySelector('path')?.getAttribute('d')).toContain('M 36 315');
  });

  it('draws the committed prompt mesh as a gradient', () => {
    const scene = buildScene(fixture('28-prompt-many-secrets'));

    expect(scene.querySelectorAll('linearGradient')).toHaveLength(1);
    expect(scene.querySelector('rect[fill^="url("]')).not.toBeNull();
  });

  it('keeps the light prompt fade hue while its transparent stop reaches zero opacity', () => {
    const scene = buildScene(fixtureVariant('28-prompt-many-secrets', 'macos-light'));
    const stops = [...scene.querySelectorAll('linearGradient stop')];

    expect(stops).toHaveLength(2);
    expect(stops[0].getAttribute('stop-opacity')).toBe('0');
    expect(stops[0].getAttribute('stop-color')).toBe(stops[1].getAttribute('stop-color'));
    expect(stops[1].getAttribute('stop-opacity')).toBe(String(128 / 255));
  });

  it('recognises an equivalent fan-triangulated fade quad', () => {
    const scene = buildScene({
      size: [10, 10],
      shapes: [
        {
          k: 'mesh',
          clip: [0, 0, 10, 10],
          vertices: [
            [1, 2, '#00000000'],
            [5, 2, '#00000000'],
            [5, 7, '#46505aff'],
            [1, 7, '#46505aff'],
          ],
          indices: [0, 1, 2, 0, 2, 3],
        },
      ],
    } as WindowScene);

    expect(scene.querySelectorAll('linearGradient')).toHaveLength(1);
    expect(scene.querySelector('rect[fill^="url("]')).not.toBeNull();
  });

  it('does not promote triangles sharing a quad edge to a full gradient', () => {
    const scene = buildScene({
      size: [10, 10],
      shapes: [
        {
          k: 'mesh',
          clip: [0, 0, 10, 10],
          vertices: [
            [1, 2, '#00000000'],
            [5, 2, '#00000000'],
            [1, 7, '#46505aff'],
            [5, 7, '#46505aff'],
          ],
          indices: [0, 1, 2, 0, 1, 3],
        },
      ],
    } as WindowScene);

    expect(scene.querySelector('rect[fill^="url("]')).toBeNull();
  });
});

describe('<secreq-window> lifecycle', () => {
  it('returns no viewer scene before geometry lands, then builds a fresh copy', async () => {
    vi.stubGlobal(
      'ResizeObserver',
      class {
        observe() {}
        disconnect() {}
      },
    );
    Object.defineProperty(document, 'fonts', {
      configurable: true,
      value: { load: vi.fn().mockResolvedValue([]) },
    });
    let resolveGeometry: ((scene: WindowScene) => void) | undefined;
    vi.stubGlobal(
      'fetch',
      vi.fn().mockReturnValue(
        new Promise((resolve) => {
          resolveGeometry = (scene) =>
            resolve({
              ok: true,
              json: vi.fn().mockResolvedValue(scene),
            });
        }),
      ),
    );

    const host = document.createElement('secreq-window') as HTMLElement & {
      sceneForViewer(): { element: HTMLElement; size: [number, number] } | null;
    };
    host.setAttribute('shot', 'viewer-copy-test');
    host.setAttribute('variant', 'macos-dark');
    host.innerHTML =
      '<button class="shot-zoom"><img class="shot-img" src="/ui/viewer-copy-test.png" ' +
      'data-fallback="true"></button>';
    document.body.appendChild(host);

    expect(host.sceneForViewer()).toBeNull();
    resolveGeometry?.({ size: [10, 10], shapes: [] } as WindowScene);
    await vi.waitFor(() => expect(host.querySelector('.sqw-scene')).not.toBeNull());

    const viewer = host.sceneForViewer();
    expect(viewer?.element).not.toBe(host.querySelector('.sqw-scene'));
    expect(host.querySelector('.sqw-scene')).not.toBeNull();
  });

  it('observes its existing stage again after reconnecting', async () => {
    const observers: Array<{ disconnect: ReturnType<typeof vi.fn> }> = [];
    vi.stubGlobal(
      'ResizeObserver',
      class {
        disconnect = vi.fn();
        observe = vi.fn();

        constructor() {
          observers.push(this);
        }
      },
    );
    Object.defineProperty(document, 'fonts', {
      configurable: true,
      value: { load: vi.fn().mockResolvedValue([]) },
    });
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({
          size: [10, 10],
          shapes: [],
        }),
      }),
    );

    const window = document.createElement('secreq-window');
    window.setAttribute('shot', 'reconnect-test');
    window.setAttribute('variant', 'macos-dark');
    window.innerHTML =
      '<img class="shot-img" src="/ui/reconnect-test-macos-dark.png" ' +
      'data-fallback="true" data-os="macos" data-appearance="dark">';
    document.body.appendChild(window);
    await vi.waitFor(() => expect(window.querySelector('.sqw-stage')).not.toBeNull());
    expect(observers).toHaveLength(1);

    window.remove();
    expect(observers[0].disconnect).toHaveBeenCalledOnce();
    document.body.appendChild(window);

    await vi.waitFor(() => expect(observers).toHaveLength(2));
  });
});
