import { afterEach, describe, expect, it } from 'vitest';
import { SHOT_OPEN_EVENT, type ShotOpenDetail } from './shot-events';
import './secreq-shot-element';

afterEach(() => document.body.replaceChildren());

describe('<secreq-shot>', () => {
  it('opens the PNG when its window host has not upgraded yet', () => {
    const host = document.createElement('secreq-window');
    host.innerHTML = `
      <secreq-shot>
        <button class="shot-zoom" type="button">
          <img class="shot-img" data-fallback="true" src="/ui/fallback.png" alt="Fallback window">
        </button>
      </secreq-shot>
    `;
    document.body.appendChild(host);
    let detail: ShotOpenDetail | undefined;
    document.addEventListener(
      SHOT_OPEN_EVENT,
      (event) => {
        detail = event.detail;
      },
      { once: true },
    );

    host.querySelector<HTMLButtonElement>('.shot-zoom')?.click();

    expect(detail?.source.alt).toBe('Fallback window');
    expect(detail?.scene).toBeNull();
  });
});
