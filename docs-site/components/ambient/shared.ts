import { useEffect, useRef, useState } from 'react';
import { buildGraph, type Graph, type Point } from './graph';

/**
 * The parts of the ambient layer that are not about drawing.
 *
 * Measuring the page, generating the graph, and working out how the cursor
 * bends it are identical whichever backend renders the result — so they live
 * here, and the two backends differ only in how they put pixels down.
 */

/* ── Measuring and generating ────────────────────────────────────────── */

/**
 * Build a graph sized to `ref`, and rebuild it when that size really changes.
 *
 * The tolerance matters: a scrollbar appearing or a lazy image landing
 * changes the box by a few pixels, and regrowing the whole graph for that
 * would make the background twitch while the reader is doing nothing.
 */
export function useGraph(ref: React.RefObject<HTMLElement | null>): Graph | null {
  const [graph, setGraph] = useState<Graph | null>(null);

  useEffect(() => {
    const root = ref.current;
    if (!root) return;

    let frame = 0;
    const measure = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const { clientWidth: w, clientHeight: h } = root;
        setGraph((prev) =>
          prev && Math.abs(prev.width - w) < 24 && Math.abs(prev.height - h) < 120
            ? prev
            : buildGraph(w, h),
        );
      });
    };

    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(document.documentElement);
    return () => {
      observer.disconnect();
      cancelAnimationFrame(frame);
    };
  }, [ref]);

  return graph;
}

/* ── Pointer distortion ──────────────────────────────────────────────── */

/**
 * How far the cursor's influence reaches, in px.
 *
 * Has to comfortably exceed the distance between neighbouring nodes, or the
 * radius sits in the gaps and almost nothing is ever in range — which is
 * exactly what happened when this was smaller than one edge length.
 */
const PUSH_RADIUS = 300;

/** How far a node at the very centre of that radius is displaced. */
const PUSH_STRENGTH = 30;

/** How quickly a node eases toward its target each frame. */
const EASE = 0.16;

export interface Distortion {
  /** Per-node displacement, in graph coordinates. Mutated in place. */
  offset: Point[];
  /** A node's current position, displacement included. */
  at(index: number): Point;
  /** Advance one frame. Returns true while anything is still moving. */
  step(): boolean;
  /** Whether the cursor is currently over the page. */
  isLive(): boolean;
  /**
   * Start listening. Returns a teardown; `onWake` fires when a frame is
   * needed.
   *
   * `origin` maps client coordinates into graph coordinates. The SVG backend
   * hands back the element's own rect; the canvas backend synthesises one
   * from the scroll position, because its bitmap is viewport-sized while the
   * graph is document-sized.
   */
  listen(origin: () => { left: number; top: number } | null, onWake: () => void): () => void;
}

/**
 * Bend the graph away from the cursor.
 *
 * The falloff is squared — firm near the cursor, nothing at the rim — and
 * every node eases toward its target rather than snapping, so the graph
 * flexes and recovers. A node the cursor lands exactly on has no direction to
 * be pushed in; leaving it put beats dividing by zero.
 */
export function createDistortion(points: Point[]): Distortion {
  const offset = points.map(() => ({ x: 0, y: 0 }));
  const pointer = { x: -1e5, y: -1e5, live: false };

  return {
    offset,

    at(index) {
      return {
        x: points[index].x + offset[index].x,
        y: points[index].y + offset[index].y,
      };
    },

    isLive: () => pointer.live,

    step() {
      let moving = false;

      for (let i = 0; i < points.length; i++) {
        let targetX = 0;
        let targetY = 0;

        if (pointer.live) {
          const dx = points[i].x - pointer.x;
          const dy = points[i].y - pointer.y;
          const distance = Math.hypot(dx, dy);
          if (distance < PUSH_RADIUS) {
            const force = (1 - distance / PUSH_RADIUS) ** 2 * PUSH_STRENGTH;
            const scale = distance < 0.01 ? 0 : force / distance;
            targetX = dx * scale;
            targetY = dy * scale;
          }
        }

        offset[i].x += (targetX - offset[i].x) * EASE;
        offset[i].y += (targetY - offset[i].y) * EASE;
        if (Math.abs(offset[i].x) > 0.05 || Math.abs(offset[i].y) > 0.05) moving = true;
      }

      return moving;
    },

    listen(origin, onWake) {
      const onMove = (event: PointerEvent) => {
        const box = origin();
        if (!box) return;
        pointer.x = event.clientX - box.left;
        pointer.y = event.clientY - box.top;
        pointer.live = true;
        onWake();
      };

      const onLeave = () => {
        pointer.live = false;
        onWake();
      };

      window.addEventListener('pointermove', onMove, { passive: true });
      window.addEventListener('pointerleave', onLeave);
      window.addEventListener('blur', onLeave);

      return () => {
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerleave', onLeave);
        window.removeEventListener('blur', onLeave);
      };
    },
  };
}

/** Whether this reader gets motion and a real cursor at all. */
export function interactionAllowed(): boolean {
  return (
    window.matchMedia('(pointer: fine)').matches &&
    !window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

export function prefersReducedMotion(): boolean {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/**
 * Read the layer's colours out of CSS.
 *
 * The SVG backend gets these for free by putting class names on elements.
 * Canvas cannot — it paints into a bitmap that knows nothing about the
 * cascade — so it has to resolve the same custom properties itself and
 * re-resolve them whenever the theme attribute flips.
 */
export interface Palette {
  edge: string;
  node: string;
  pulse: string;
}

export function readPalette(): Palette {
  const style = getComputedStyle(document.documentElement);
  const value = (name: string, fallback: string) => style.getPropertyValue(name).trim() || fallback;

  return {
    edge: value('--sq-graph', 'rgba(255,255,255,0.055)'),
    node: value('--sq-graph-node', 'rgba(255,255,255,0.09)'),
    pulse: value('--sq-pulse', 'rgba(53,132,228,0.55)'),
  };
}

/** Re-read the palette whenever the theme attribute changes. */
export function usePalette(): Palette | null {
  const [palette, setPalette] = useState<Palette | null>(null);

  useEffect(() => {
    const sync = () => setPalette(readPalette());
    sync();
    const observer = new MutationObserver(sync);
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme'],
    });
    return () => observer.disconnect();
  }, []);

  return palette;
}

/** A stable ref to the element the graph's coordinates are relative to. */
export function useOrigin<T extends HTMLElement>() {
  return useRef<T>(null);
}
