import { useEffect, useRef, useState } from 'react';
import { AmbientCanvas } from './ambient/AmbientCanvas';
import { useGraph } from './ambient/shared';

/**
 * The layer behind the page: a procedurally generated call graph, drawn
 * faintly, with a pulse travelling up a route now and then — the direction a
 * real request travels, from the process that made it toward whoever decides.
 *
 * The geometry lives in `ambient/graph.ts`, deliberately renderer-agnostic:
 * it was written that way to let a canvas backend and an SVG one be compared
 * on identical input, and it is worth keeping that way.
 *
 * **There used to be two backends.** The SVG one drew an element per edge,
 * node and pulse layer and let CSS animate them. Measured against it at 6×
 * CPU throttle, the two were indistinguishable at rest — browsers optimise
 * declarative animation well — but under the pointer distortion, which
 * rewrites the geometry every frame, SVG cost 14.5ms/frame against canvas's
 * 8.3ms and dropped frames doing it. Rewriting `d` on ~190 paths per frame
 * invalidates style for every one of them; a canvas just draws.
 *
 * Once that was measured the second backend was only a liability: every
 * future change to this layer would have had to be built twice and kept
 * equivalent, and it had already been through bloom, arrival ripples,
 * endpoint styling and planarity in a single sitting. So it is gone.
 *
 * `?ambient=off` turns the layer off — which is also what happens if the
 * browser declines to give us a 2D context. For a decorative background the
 * honest fallback is no background, not a second renderer kept alive as
 * insurance.
 */

type Backend = 'canvas' | 'off';

/**
 * Whether this browser will give us a 2D context at all.
 *
 * It can decline — a blocked canvas, a hardened privacy setting, an
 * exhausted GPU process — and the failure is silent: `getContext` simply
 * returns null. Checking up front means the page drops the background
 * cleanly instead of mounting an element that never paints.
 */
function canvasAvailable(): boolean {
  try {
    return !!document.createElement('canvas').getContext('2d');
  } catch {
    return false;
  }
}

function requestedBackend(): Backend {
  try {
    if (new URLSearchParams(window.location.search).get('ambient') === 'off') return 'off';
  } catch {
    // A malformed query string is not a reason to lose the background.
  }
  return canvasAvailable() ? 'canvas' : 'off';
}

export function Ambient() {
  const ref = useRef<HTMLDivElement>(null);
  const graph = useGraph(ref);
  const [backend, setBackend] = useState<Backend>('canvas');

  // Read in an effect rather than during render: the server has no location,
  // and the canvas is client-only anyway.
  useEffect(() => setBackend(requestedBackend()), []);

  return (
    <>
      {/* Document-anchored, so the wash stays with the hero and the grain
          covers the whole page. The canvas is deliberately *not* in here —
          it is fixed to the viewport, and this element's containment would
          become its containing block. */}
      <div className="ambient" aria-hidden="true" ref={ref}>
        <div className="ambient-wash" />
        <div className="ambient-grain" />
      </div>

      {backend === 'canvas' && graph && <AmbientCanvas graph={graph} />}
    </>
  );
}
