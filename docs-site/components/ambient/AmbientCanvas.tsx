import { useEffect, useRef } from 'react';
import {
  ARRIVAL_FRACTION,
  DASH,
  PULSE_PERIOD,
  PULSE_TRAVEL_FRACTION,
  pulseDelay,
  type Graph,
} from './graph';
import {
  createDistortion,
  interactionAllowed,
  prefersReducedMotion,
  usePalette,
  type Palette,
} from './shared';

/**
 * The canvas backend: one bitmap, one draw call per frame.
 *
 * It replaced an SVG backend that drew an element per edge, node and pulse
 * layer. Every animated element is a style recalculation per frame, and the
 * distortion loop rewriting geometry made that the dominant cost. Here the
 * per-frame work is proportional to what is *on screen* rather than to how
 * many elements exist.
 *
 * Two things follow from that, and are the reason this is not free:
 *
 *   - The bitmap is **viewport-sized and fixed**, never document-sized. A
 *     canvas covering a 15,000px page at 2× would be several hundred
 *     megabytes. So the layer draws the slice currently in view, offset by
 *     the scroll position, and culls everything outside it.
 *   - Nothing here participates in the cascade. Theme colours have to be read
 *     out of CSS custom properties by hand and re-read when the theme flips,
 *     and reduced motion has to be branched on explicitly, where the SVG
 *     backend got both for free.
 *
 * What it gains in exchange, besides the frame budget, is real additive
 * blending — the bloom is accumulated light rather than stacked strokes
 * pretending to be.
 */

/** Bloom passes: width in px, and how much light each contributes. */
const PULSE_LAYERS: [width: number, alpha: number][] = [
  [7, 0.16],
  [3, 0.32],
  [1.4, 1],
];

const ARRIVAL_LAYERS: [width: number, alpha: number][] = [
  [5, 0.3],
  [1.2, 1],
];

export function AmbientCanvas({ graph }: { graph: Graph }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const palette = usePalette();

  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas?.getContext('2d', { alpha: true });
    if (!canvas || !context || !palette) return;

    const field = createDistortion(graph.points);
    const interactive = interactionAllowed();
    const still = prefersReducedMotion();

    /**
     * Where the graph's origin sits in the document.
     *
     * Measured rather than assumed, and only when the page resizes: reading
     * a rect every frame would force a synchronous layout, which is the one
     * thing that would make this slower than the elements it replaces.
     * `scrollY` is free to read by comparison.
     */
    let originDoc = 0;
    let width = 0;
    let height = 0;

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      context.setTransform(dpr, 0, 0, dpr, 0, 0);

      const parent = canvas.parentElement;
      originDoc = parent ? parent.getBoundingClientRect().top + window.scrollY : 0;
    };

    const at = (i: number) => field.at(i);

    /** Walk the route, stroking only the span between two distances. */
    const dashPath = (route: number[], from: number, to: number) => {
      let travelled = 0;
      context.beginPath();
      for (let i = 0; i < route.length - 1; i++) {
        const a = at(route[i]);
        const b = at(route[i + 1]);
        const span = Math.hypot(b.x - a.x, b.y - a.y);
        const end = travelled + span;

        if (end >= from && travelled <= to && span > 0) {
          const t0 = Math.max(0, (from - travelled) / span);
          const t1 = Math.min(1, (to - travelled) / span);
          context.moveTo(a.x + (b.x - a.x) * t0, a.y + (b.y - a.y) * t0);
          context.lineTo(a.x + (b.x - a.x) * t1, a.y + (b.y - a.y) * t1);
        }
        travelled = end;
      }
    };

    const drawGraph = (top: number, bottom: number, colours: Palette) => {
      // Every edge in one path, then one stroke — the whole graph costs two
      // draw calls. Styling each edge separately would have needed an element
      // each, which is exactly what this replaced.
      context.strokeStyle = colours.edge;
      context.lineWidth = 1;
      context.beginPath();
      for (const [from, to] of graph.links) {
        const a = at(from);
        const b = at(to);
        if (Math.max(a.y, b.y) < top || Math.min(a.y, b.y) > bottom) continue;
        context.moveTo(a.x, a.y);
        context.lineTo(b.x, b.y);
      }
      context.stroke();

      // Junctions are filled, endpoints hollow — a node with one edge is the
      // only place a route can begin or end.
      context.fillStyle = colours.node;
      context.strokeStyle = colours.node;
      context.lineWidth = 1.1;
      context.beginPath();
      for (const index of graph.dots) {
        if (graph.degrees[index] === 1) continue;
        const p = at(index);
        if (p.y < top || p.y > bottom) continue;
        context.moveTo(p.x + 2, p.y);
        context.arc(p.x, p.y, 2, 0, Math.PI * 2);
      }
      context.fill();

      context.beginPath();
      for (const index of graph.dots) {
        if (graph.degrees[index] !== 1) continue;
        const p = at(index);
        if (p.y < top || p.y > bottom) continue;
        context.moveTo(p.x + 3, p.y);
        context.arc(p.x, p.y, 3, 0, Math.PI * 2);
      }
      context.stroke();
    };

    /** Fade a pulse in over the first beat and out as it finishes. */
    const pulseOpacity = (fraction: number) => {
      if (fraction < 0.06) return fraction / 0.06;
      if (fraction > 0.46) return Math.max(0, (PULSE_TRAVEL_FRACTION - fraction) / 0.06);
      return 1;
    };

    const drawPulses = (seconds: number, colours: Palette) => {
      // Additive: overlapping passes accumulate into light rather than
      // painting over one another. Stacked strokes can only approximate this.
      context.globalCompositeOperation = 'lighter';
      context.strokeStyle = colours.pulse;
      context.lineCap = 'round';

      graph.pulses.forEach((pulse, i) => {
        const local = (((seconds - pulseDelay(i)) % PULSE_PERIOD) + PULSE_PERIOD) % PULSE_PERIOD;
        const fraction = local / PULSE_PERIOD;
        if (fraction > PULSE_TRAVEL_FRACTION) return;

        const alpha = pulseOpacity(fraction);
        if (alpha <= 0) return;

        const head = (fraction / PULSE_TRAVEL_FRACTION) * pulse.length;
        for (const [lineWidth, weight] of PULSE_LAYERS) {
          context.globalAlpha = alpha * weight;
          context.lineWidth = lineWidth;
          dashPath(pulse.route, head, head + DASH);
          context.stroke();
        }
      });

      for (const arrival of graph.arrivals) {
        const local =
          (((seconds - pulseDelay(arrival.pulse) - arrival.at) % PULSE_PERIOD) + PULSE_PERIOD) %
          PULSE_PERIOD;
        const fraction = local / PULSE_PERIOD;
        if (fraction > ARRIVAL_FRACTION) continue;

        const progress = fraction / ARRIVAL_FRACTION;
        const p = at(arrival.node);
        const radius = 2.4 + progress * 12.6;
        const fade = 1 - progress;

        for (const [lineWidth, weight] of ARRIVAL_LAYERS) {
          context.globalAlpha = fade * weight;
          context.lineWidth = lineWidth;
          context.beginPath();
          context.arc(p.x, p.y, radius, 0, Math.PI * 2);
          context.stroke();
        }

        // The node itself lighting up, before the ring leaves it.
        if (progress < 0.33) {
          context.globalAlpha = 1 - progress / 0.33;
          context.fillStyle = colours.pulse;
          context.beginPath();
          context.arc(p.x, p.y, 2.4, 0, Math.PI * 2);
          context.fill();
        }
      }

      context.globalAlpha = 1;
      context.globalCompositeOperation = 'source-over';
    };

    let frame = 0;
    let running = false;
    const started = performance.now();

    const render = () => {
      if (interactive) field.step();

      const originY = originDoc - window.scrollY;
      context.clearRect(0, 0, width, height);
      context.save();
      context.translate(0, originY);

      // Cull to the visible slice, with a margin so nothing pops at the edge.
      const top = -originY - 40;
      const bottom = top + height + 80;

      drawGraph(top, bottom, palette);
      if (!still) drawPulses((performance.now() - started) / 1000, palette);

      context.restore();

      if (running) frame = requestAnimationFrame(render);
    };

    const start = () => {
      if (running || document.hidden) return;
      running = true;
      frame = requestAnimationFrame(render);
    };

    const stop = () => {
      running = false;
      cancelAnimationFrame(frame);
    };

    const onVisibility = () => (document.hidden ? stop() : start());

    resize();
    if (still) {
      // Nothing animates, so one frame is the whole job — but it still has to
      // be redrawn as the page scrolls under the fixed bitmap.
      render();
      window.addEventListener('scroll', render, { passive: true });
    } else {
      start();
    }

    window.addEventListener('resize', resize);
    document.addEventListener('visibilitychange', onVisibility);

    const unlisten = interactive
      ? field.listen(
          () => ({ left: 0, top: originDoc - window.scrollY }),
          () => {},
        )
      : () => {};

    return () => {
      stop();
      unlisten();
      window.removeEventListener('resize', resize);
      window.removeEventListener('scroll', render);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [graph, palette]);

  return <canvas ref={canvasRef} className="ambient-canvas" aria-hidden="true" />;
}
