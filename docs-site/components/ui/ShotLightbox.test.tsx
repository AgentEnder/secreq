import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ShotLightbox } from './ShotLightbox';
import { SHOT_OPEN_EVENT, type ShotOpenDetail } from './shot-events';

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT =
  true;

class QuietResizeObserver {
  observe() {}
  disconnect() {}
}

describe('<ShotLightbox>', () => {
  let host: HTMLDivElement;
  let root: Root;

  beforeEach(async () => {
    vi.stubGlobal('ResizeObserver', QuietResizeObserver);
    vi.stubGlobal('matchMedia', () => ({ matches: true }));
    HTMLDialogElement.prototype.showModal = function () {
      this.setAttribute('open', '');
    };
    HTMLDialogElement.prototype.close = function () {
      this.removeAttribute('open');
    };
    host = document.createElement('div');
    document.body.appendChild(host);
    root = createRoot(host);
    await act(async () => root.render(<ShotLightbox />));
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    document.body.replaceChildren();
    vi.unstubAllGlobals();
  });

  it('opens a named, parent-capped scene without writing a zero scale', async () => {
    const source = document.createElement('img');
    source.src = '/ui/manager.png';
    source.alt = 'Audit manager window';
    document.body.appendChild(source);
    const element = document.createElement('div');
    element.style.setProperty('--sqw-scale', '1');

    await act(async () => {
      document.dispatchEvent(
        new CustomEvent<ShotOpenDetail>(SHOT_OPEN_EVENT, {
          detail: {
            source,
            caption: 'Every decision.',
            scene: { element, size: [900, 600] },
          },
        }),
      );
    });

    const stage = document.querySelector<HTMLElement>('.sqw-lightbox-stage');
    expect(stage).not.toBeNull();
    expect(stage?.getAttribute('role')).toBe('group');
    expect(stage?.getAttribute('aria-label')).toBe('Audit manager window');
    expect(stage?.style.maxWidth).toBe('100%');
    expect(element.style.getPropertyValue('--sqw-scale')).not.toBe('0');
    expect(stage?.firstElementChild).toBe(element);
    expect(document.querySelector('dialog img')).toBeNull();
  });

  it('keeps the viewer open when a text-selection drag ends on the dialog margin', async () => {
    const source = document.createElement('img');
    source.src = '/ui/manager.png';
    document.body.appendChild(source);
    const element = document.createElement('div');

    await act(async () => {
      document.dispatchEvent(
        new CustomEvent<ShotOpenDetail>(SHOT_OPEN_EVENT, {
          detail: { source, caption: '', scene: { element, size: [900, 600] } },
        }),
      );
    });

    const dialog = document.querySelector('dialog');
    dialog?.dispatchEvent(
      new MouseEvent('pointerdown', { bubbles: true, clientX: 20, clientY: 20 }),
    );
    await act(async () => {
      dialog?.dispatchEvent(new MouseEvent('click', { bubbles: true, clientX: 80, clientY: 20 }));
    });

    expect(document.querySelector('dialog figure')).not.toBeNull();
  });

  it('morphs back to the exact source when two figures share a render', async () => {
    const first = figure('/ui/shared.png');
    const second = figure('/ui/shared.png');
    document.body.append(first.zoom, second.zoom);

    await act(async () => {
      document.dispatchEvent(
        new CustomEvent<ShotOpenDetail>(SHOT_OPEN_EVENT, {
          detail: {
            source: second.image,
            caption: '',
            scene: null,
          },
        }),
      );
    });
    expect(document.querySelector('dialog img')).not.toBeNull();
    expect(document.querySelector('.sqw-lightbox-stage')).toBeNull();
    await act(async () => {
      document
        .querySelector('dialog')
        ?.dispatchEvent(new Event('cancel', { bubbles: true, cancelable: true }));
    });

    expect(first.stage.style.viewTransitionName).toBe('');
    expect(second.stage.style.viewTransitionName).toBe('shot-zoom');
  });
});

function figure(src: string) {
  const zoom = document.createElement('button');
  zoom.className = 'shot-zoom';
  const stage = document.createElement('div');
  stage.className = 'sqw-stage';
  const image = document.createElement('img');
  image.className = 'shot-img';
  image.src = src;
  image.dataset.standing = 'true';
  zoom.append(stage, image);
  return { zoom, stage, image };
}
