import { useEffect, useRef, useState } from 'react';

/**
 * The layer behind the page: a call graph, drawn faintly.
 *
 * secreq's entire subject is a request travelling up through processes to
 * reach a decision. So the background generates that shape — procedurally,
 * seeded — and every so often sends a pulse along one route toward the top.
 *
 * It is built in two passes, and the second is what makes it a graph rather
 * than a tree. Growth alone produces branches that diverge and never meet
 * again, which reads as a handful of disconnected forks scattered down the
 * page. The linking pass then joins nodes back together across branches, so
 * routes converge, enclose space, and share junctions — the difference
 * between a scribble and a diagram.
 *
 * The layout is **planar**: no edge may cross another. Every place two lines
 * meet is a real node they both connect to, which matters because the cursor
 * can bend the graph — a crossing has no node to move with it, so anything
 * drawn there gives itself away the moment the geometry shifts.
 *
 * Edges run at arbitrary angles rather than the right angles `pstree` uses.
 * Elbows turned out to be the wrong call: axis-aligned segments read as more
 * of the page's own rules, which is the one thing a background layer must not
 * do. Angles nothing else on the page uses can never be mistaken for
 * structure — which is also why links are barred from running near-horizontal.
 *
 * Everything here is a few percent of contrast against the page. If a reader
 * notices it as an effect rather than as depth, it is too strong.
 */

interface Point {
  x: number;
  y: number;
}

interface Node extends Point {
  parent: number | null;
}

interface Segment {
  a: Point;
  b: Point;
  /** Node indices, so edges meeting at a shared node skip the clearance test. */
  from: number;
  to: number;
}

interface Pulse {
  /** Node indices, low to high — the order the pulse visits them. */
  route: number[];
  /** Total polyline length in px, so the dash can be a fixed size. */
  length: number;
}

interface Graph {
  /** Every node, including the off-screen roots, indexed as the edges refer to them. */
  points: Point[];
  /** Index pairs. Kept as indices so the pointer loop can redraw them. */
  links: [number, number][];
  /** Indices of the nodes that get a dot — the roots sit off-page. */
  dots: number[];
  /**
   * Edge count per node. A node with exactly one is where a route can only
   * begin or end, so it is drawn as an endpoint rather than a junction.
   */
  degrees: number[];
  pulses: Pulse[];
  /**
   * Every time any pulse reaches any node — one entry per crossing, not per
   * node. Keying this by node was a bug worth remembering: a node on two
   * routes kept only the first arrival, so the second pulse would sail
   * through it with nothing happening.
   *
   * `at` is seconds from that pulse's own start, so the whole effect is a
   * CSS animation with a delay rather than anything JavaScript follows.
   */
  arrivals: { node: number; at: number; pulse: number }[];
  width: number;
  height: number;
}

/** Length of the travelling dash, in px. Fixed, so long routes don't get long pulses. */
const DASH = 42;

/** Seconds a pulse spends travelling. Must match the keyframes' travel span. */
const PULSE_TRAVEL = 15 * 0.52;

/* ── Shape constraints ───────────────────────────────────────────────── */

/** Off-vertical, in radians. The floor is what stops an edge reading as a rule. */
const MIN_ANGLE = (24 * Math.PI) / 180;
const MAX_ANGLE = (64 * Math.PI) / 180;

/**
 * How far an edge must stay from every node and edge it does not join.
 *
 * Together with the no-crossings rule this is what makes the graph look
 * drawn rather than accumulated: every meeting of two lines is a real node
 * they both connect to, and everything else keeps a visible distance. Near
 * misses read as mistakes, and crossings read as junctions that aren't —
 * which the cursor exposes the moment it bends one line and not the other.
 */
const CLEARANCE = 19;

/** Attempts before a branch gives up and simply ends. */
const TRIES = 14;

/**
 * How many branches may be live at once.
 *
 * Without this the fork rate compounds: every generation roughly doubles, and
 * a tall page ends up with hundreds of edges — a thicket, not a diagram.
 * Capping the frontier keeps the graph sparse while still letting most nodes
 * fork, because the surplus branches simply end there.
 */
const MAX_FRONTIER = 4;

/**
 * How many extra edges the linking pass may add, as a share of the nodes it
 * has to work with. Too few and the result is still a tree; too many and the
 * enclosed shapes stop reading as routes and start reading as a mesh.
 */
const LINK_RATIO = 0.9;

/** A link may not run within this of horizontal — see the module comment. */
const MIN_LINK_ANGLE = (20 * Math.PI) / 180;

/** Seeded so a resize re-derives the same tree instead of reshuffling it. */
function rng(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/* ── Geometry ────────────────────────────────────────────────────────── */

function cross(o: Point, a: Point, b: Point): number {
  return (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);
}

/** Intersection point of two segments, or null if they do not meet. */
function intersection(a: Point, b: Point, c: Point, d: Point): Point | null {
  const d1 = cross(a, b, c);
  const d2 = cross(a, b, d);
  const d3 = cross(c, d, a);
  const d4 = cross(c, d, b);
  if (d1 * d2 >= 0 || d3 * d4 >= 0) return null;
  const t = d3 / (d3 - d4);
  return { x: a.x + t * (b.x - a.x), y: a.y + t * (b.y - a.y) };
}

function pointToSegment(p: Point, a: Point, b: Point): number {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const len = dx * dx + dy * dy;
  const t = len === 0 ? 0 : Math.max(0, Math.min(1, ((p.x - a.x) * dx + (p.y - a.y) * dy) / len));
  return Math.hypot(p.x - (a.x + t * dx), p.y - (a.y + t * dy));
}

/** Minimum distance between two non-intersecting segments. */
function segmentDistance(a: Point, b: Point, c: Point, d: Point): number {
  return Math.min(
    pointToSegment(a, c, d),
    pointToSegment(b, c, d),
    pointToSegment(c, a, b),
    pointToSegment(d, a, b)
  );
}

/* ── Generation ──────────────────────────────────────────────────────── */

function buildGraph(width: number, height: number): Graph {
  const rand = rng(0x5ec4e9);
  const nodes: Node[] = [];
  const segments: Segment[] = [];

  const add = (x: number, y: number, parent: number | null) => nodes.push({ x, y, parent }) - 1;

  // Short edges are what make it read as a graph rather than as a few long
  // gestures: more nodes, closer together, each with more connections. The
  // budget is total ink, not edge count — a mesh of short segments is
  // quieter than half as many that sweep across the whole viewport.
  const reach = Math.min(width, height) * 0.18;
  const minLen = Math.max(120, reach * 0.7);
  const maxLen = Math.max(minLen + 90, reach * 1.7);

  /**
   * Try to grow one child from `parent`. Returns its index, or null when
   * every attempt crossed an existing edge or crowded one.
   */
  const grow = (parent: number, dir: number): number | null => {
    const p = nodes[parent];

    for (let attempt = 0; attempt < TRIES; attempt++) {
      const angle = MIN_ANGLE + rand() * (MAX_ANGLE - MIN_ANGLE);
      const length = minLen + rand() * (maxLen - minLen);
      const candidate: Point = {
        x: p.x + dir * Math.sin(angle) * length,
        y: p.y + Math.cos(angle) * length,
      };

      if (candidate.x < width * 0.03 || candidate.x > width * 0.97) continue;
      if (candidate.y > height - 20) continue;

      let ok = true;

      for (const seg of segments) {
        // Edges meeting at a shared node are supposed to be close there.
        if (seg.from === parent || seg.to === parent) continue;

        // Planar: no edge may cross another. A crossing has no node, so it
        // cannot move with the graph, and anything drawn there is a lie the
        // cursor uncovers as soon as it distorts one line and not the other.
        if (intersection(p, candidate, seg.a, seg.b)) {
          ok = false;
          break;
        }
        if (segmentDistance(p, candidate, seg.a, seg.b) < CLEARANCE) {
          ok = false;
          break;
        }
      }

      if (ok) {
        for (const node of nodes) {
          if (node === p) continue;
          if (Math.hypot(node.x - candidate.x, node.y - candidate.y) < CLEARANCE * 1.4) {
            ok = false;
            break;
          }
        }
      }

      if (!ok) continue;

      const index = add(candidate.x, candidate.y, parent);
      segments.push({ a: p, b: candidate, from: parent, to: index });
      return index;
    }

    return null;
  };

  /**
   * Thin the frontier down by taking the widest spread rather than the first
   * few.
   *
   * Truncating in insertion order was quietly biasing the whole graph: it
   * favours children of whichever parent happened to be processed first, so
   * generation after generation the survivors drift into the same band and
   * the page ends up with everything happening in one quarter of its width.
   * Sampling the x-sorted candidates keeps both edges of the page in play.
   */
  const spread = (candidates: number[]): number[] => {
    if (candidates.length <= MAX_FRONTIER) return candidates;
    const byX = [...candidates].sort((a, b) => nodes[a].x - nodes[b].x);
    const picked = new Set<number>();
    for (let k = 0; k < MAX_FRONTIER; k++) {
      picked.add(byX[Math.round((k * (byX.length - 1)) / (MAX_FRONTIER - 1))]);
    }
    return [...picked];
  };

  let frontier = [
    add(width * 0.12, -reach * 0.4, null),
    add(width * 0.39, -reach * 0.85, null),
    add(width * 0.63, -reach * 0.55, null),
    add(width * 0.89, -reach * 0.7, null),
  ];

  for (let guard = 0; guard < 40 && frontier.length; guard++) {
    const next: number[] = [];

    for (const parent of frontier) {
      if (nodes[parent].y > height - reach * 0.5) continue;

      // A minority of nodes fork. Every edge still turns — `grow` cannot
      // produce one inside MIN_ANGLE of vertical — so the graph reads as a
      // branching structure without needing many branches to say so.
      const forking = rand() < 0.34 && next.length < MAX_FRONTIER * 2;
      // A branch near an edge of the page is nudged back inward, so a walk
      // that wanders into a margin does not just stall there against the
      // bounds check for the rest of the page.
      const inward = nodes[parent].x < width * 0.5 ? 1 : -1;
      const dirs = forking ? [-1, 1] : [rand() < 0.62 ? inward : -inward];

      for (const dir of dirs) {
        const child = grow(parent, dir);
        if (child !== null) next.push(child);
      }
    }

    frontier = spread(next);
  }

  /* ── Pass two: close the tree into a graph ────────────────────────── */

  const connected = new Set(segments.map((s) => `${Math.min(s.from, s.to)}:${Math.max(s.from, s.to)}`));

  const canLink = (i: number, j: number): boolean => {
    const a = nodes[i];
    const b = nodes[j];
    const key = `${Math.min(i, j)}:${Math.max(i, j)}`;
    if (connected.has(key)) return false;

    const span = Math.hypot(b.x - a.x, b.y - a.y);
    if (span < reach * 0.45 || span > reach * 1.9) return false;
    // Barred from near-horizontal for the same reason edges are barred from
    // near-vertical: it would read as one of the page's own rules.
    if (Math.abs(Math.atan2(b.y - a.y, b.x - a.x)) < MIN_LINK_ANGLE) return false;
    if (Math.abs(Math.PI - Math.abs(Math.atan2(b.y - a.y, b.x - a.x))) < MIN_LINK_ANGLE) return false;

    for (const seg of segments) {
      if (seg.from === i || seg.to === i || seg.from === j || seg.to === j) continue;
      if (intersection(a, b, seg.a, seg.b)) return false;
      if (segmentDistance(a, b, seg.a, seg.b) < CLEARANCE) return false;
    }

    for (let k = 0; k < nodes.length; k++) {
      if (k === i || k === j) continue;
      if (pointToSegment(nodes[k], a, b) < CLEARANCE) return false;
    }

    return true;
  };

  const budget = Math.round(nodes.length * LINK_RATIO);
  for (let added = 0, guard = 0; added < budget && guard < nodes.length * 12; guard++) {
    const i = Math.floor(rand() * nodes.length);
    const j = Math.floor(rand() * nodes.length);
    if (i === j || !canLink(i, j)) continue;

    segments.push({ a: nodes[i], b: nodes[j], from: i, to: j });
    connected.add(`${Math.min(i, j)}:${Math.max(i, j)}`);
    added++;
  }

  /* ── Pulses ──────────────────────────────────────────────────────── */

  const neighbours = nodes.map((): number[] => []);
  for (const seg of segments) {
    neighbours[seg.from].push(seg.to);
    neighbours[seg.to].push(seg.from);
  }

  /**
   * Walk a route from a low node toward the top.
   *
   * The choice among a node's edges is uniform, which matters more than it
   * sounds: an earlier version sorted the options by how steeply they climbed
   * and picked from the best two, so at a node with three or four edges the
   * shallower ones were effectively unreachable and every pulse traced the
   * same near-vertical spine. Choosing evenly is what lets a route actually
   * use the graph.
   *
   * Mostly it climbs, but a fifth of the time it will take a level or
   * slightly lower hop where one exists — enough that a route reads as
   * finding its way through a graph rather than running up a ladder.
   */
  const route = (start: number): number[] => {
    const path = [start];
    const seen = new Set([start]);

    // Capped, and the cap is about speed rather than tidiness: travel time
    // is fixed, so a route spanning the whole document makes the pulse cross
    // a viewport in under a second. A dozen hops reads as a glide.
    for (let step = 0; step < 12; step++) {
      const here = nodes[path[path.length - 1]];
      const options = neighbours[path[path.length - 1]].filter((n) => !seen.has(n));

      const climbing = options.filter((n) => nodes[n].y < here.y);
      const sideways = options.filter(
        (n) => nodes[n].y >= here.y && nodes[n].y < here.y + reach * 0.7
      );

      const pool =
        climbing.length && (rand() < 0.8 || !sideways.length) ? climbing : sideways;
      if (!pool.length) break;

      const next = pool[Math.floor(rand() * pool.length)];
      seen.add(next);
      path.push(next);
    }
    return path;
  };

  /**
   * Pulses start at entry nodes.
   *
   * An entry is a node with exactly one edge, where that edge leads upward —
   * the only places a route can actually begin, and the ones drawn hollow
   * for exactly that reason. Starting anywhere else (this used to pick the
   * lowest nodes on the page) meant the endpoints were labelled as entrances
   * that nothing ever entered from.
   *
   * If a page is too short to produce enough of them, the lowest remaining
   * nodes fill in rather than leaving the page without pulses.
   */
  const isEntry = (i: number) =>
    nodes[i].parent !== null &&
    neighbours[i].length === 1 &&
    nodes[neighbours[i][0]].y < nodes[i].y;

  const byDepth = [...nodes.keys()]
    .filter((i) => nodes[i].parent !== null)
    .sort((a, b) => nodes[b].y - nodes[a].y);

  const entries = byDepth.filter(isEntry);
  const starts = [...entries, ...byDepth.filter((i) => !isEntry(i))].slice(0, 5);

  const pulses: Pulse[] = starts
    .map(route)
    .filter((path) => path.length > 2)
    .map((path) => {
      let length = 0;
      for (let i = 1; i < path.length; i++) {
        length += Math.hypot(
          nodes[path[i]].x - nodes[path[i - 1]].x,
          nodes[path[i]].y - nodes[path[i - 1]].y
        );
      }
      return { route: path, length };
    });

  // Every crossing, from every pulse. One entry per (pulse, node) pair so a
  // node shared by two routes reacts to both.
  const arrivals: { node: number; at: number; pulse: number }[] = [];
  pulses.forEach((pulse, index) => {
    let travelled = 0;
    for (let i = 0; i < pulse.route.length; i++) {
      if (i > 0) {
        travelled += Math.hypot(
          nodes[pulse.route[i]].x - nodes[pulse.route[i - 1]].x,
          nodes[pulse.route[i]].y - nodes[pulse.route[i - 1]].y
        );
      }
      arrivals.push({
        node: pulse.route[i],
        at: (travelled / pulse.length) * PULSE_TRAVEL,
        pulse: index,
      });
    }
  });

  return {
    points: nodes.map(({ x, y }) => ({ x, y })),
    links: segments.map((s) => [s.from, s.to] as [number, number]),
    dots: nodes.map((_, i) => i).filter((i) => nodes[i].parent !== null),
    degrees: neighbours.map((n) => n.length),
    pulses,
    arrivals,
    width,
    height,
  };
}

/* ── Component ───────────────────────────────────────────────────────── */

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

/**
 * Bend the graph away from the cursor.
 *
 * Deliberately not WebGL. Only a handful of nodes are ever inside the radius,
 * so a frame is a few attribute writes on the elements that actually moved —
 * far less work than standing up a second renderer, and it keeps the geometry
 * in the same SVG that the CSS theme and the pulse animations already drive.
 *
 * React renders the graph once; this mutates the DOM directly afterwards.
 * Re-rendering eighty paths through the reconciler at 60fps would be the one
 * way to make a background layer expensive.
 */
function usePointerDistortion(
  svg: React.RefObject<SVGSVGElement | null>,
  graph: Graph | null
) {
  useEffect(() => {
    if (!svg.current || !graph) return;
    if (!window.matchMedia('(pointer: fine)').matches) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    const root = svg.current;
    const edges = [...root.querySelectorAll<SVGPathElement>('.ambient-edge')];
    const dots = [...root.querySelectorAll<SVGGElement>('.ambient-dot')];
    const pulses = [...root.querySelectorAll<SVGPathElement>('.ambient-pulse')];

    // This loop writes `transform` and `d` behind React's back, so React has
    // no idea they were ever touched. If a rebuilt graph reused any of these
    // elements, the stale values would survive alongside freshly-rendered
    // `cx`/`cy` and the nodes would sit off their own edges. The <svg> is
    // keyed to remount on rebuild, and drawing once here normalises whatever
    // the previous run left behind either way.

    // Current displacement per node, eased toward the target every frame so
    // the graph flexes and recovers rather than snapping.
    const offset = graph.points.map(() => ({ x: 0, y: 0 }));
    const pointer = { x: -1e5, y: -1e5, live: false };
    let frame = 0;
    let settling = false;

    const at = (i: number): Point => ({
      x: graph.points[i].x + offset[i].x,
      y: graph.points[i].y + offset[i].y,
    });

    const draw = () => {
      let moving = false;

      graph.points.forEach((point, i) => {
        let targetX = 0;
        let targetY = 0;

        if (pointer.live) {
          const dx = point.x - pointer.x;
          const dy = point.y - pointer.y;
          const distance = Math.hypot(dx, dy);
          if (distance < PUSH_RADIUS) {
            // Squared falloff: firm near the cursor, nothing at the rim.
            const force = (1 - distance / PUSH_RADIUS) ** 2 * PUSH_STRENGTH;
            // A node the cursor lands exactly on has no direction to be
            // pushed in; leaving it put is better than dividing by zero.
            const scale = distance < 0.01 ? 0 : force / distance;
            targetX = dx * scale;
            targetY = dy * scale;
          }
        }

        offset[i].x += (targetX - offset[i].x) * 0.16;
        offset[i].y += (targetY - offset[i].y) * 0.16;
        if (Math.abs(offset[i].x) > 0.05 || Math.abs(offset[i].y) > 0.05) moving = true;
      });

      graph.links.forEach(([from, to], i) => {
        const a = at(from);
        const b = at(to);
        edges[i]?.setAttribute('d', `M${a.x.toFixed(1)} ${a.y.toFixed(1)}L${b.x.toFixed(1)} ${b.y.toFixed(1)}`);
      });

      graph.dots.forEach((index, i) => {
        const shift = offset[index];
        dots[i]?.setAttribute(
          'transform',
          `translate(${shift.x.toFixed(1)} ${shift.y.toFixed(1)})`
        );
      });

      graph.pulses.forEach((pulse, i) => {
        const start = at(pulse.route[0]);
        const d = pulse.route
          .slice(1)
          .reduce((acc, index) => {
            const p = at(index);
            return `${acc}L${p.x.toFixed(1)} ${p.y.toFixed(1)}`;
          }, `M${start.x.toFixed(1)} ${start.y.toFixed(1)}`);
        pulses[i]?.setAttribute('d', d);
      });

      // Keep going while anything is still easing back, so the graph always
      // returns to rest instead of freezing mid-bend when the cursor leaves.
      if (moving || pointer.live) {
        frame = requestAnimationFrame(draw);
      } else {
        settling = false;
      }
    };

    const wake = () => {
      if (settling) return;
      settling = true;
      frame = requestAnimationFrame(draw);
    };

    const onMove = (event: PointerEvent) => {
      const box = root.getBoundingClientRect();
      pointer.x = event.clientX - box.left;
      pointer.y = event.clientY - box.top;
      pointer.live = true;
      wake();
    };

    const onLeave = () => {
      pointer.live = false;
      wake();
    };

    draw();

    window.addEventListener('pointermove', onMove, { passive: true });
    window.addEventListener('pointerleave', onLeave);
    window.addEventListener('blur', onLeave);

    return () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerleave', onLeave);
      window.removeEventListener('blur', onLeave);
      cancelAnimationFrame(frame);
    };
  }, [graph]);
}

/* ── Component ───────────────────────────────────────────────────────── */

export function Ambient() {
  const ref = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [graph, setGraph] = useState<Graph | null>(null);

  useEffect(() => {
    const root = ref.current;
    if (!root) return;

    let frame = 0;
    const measure = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const { clientWidth: w, clientHeight: h } = root;
        // Rebuild only on a real change — a few pixels of scrollbar or a
        // lazy image landing should not regrow the whole graph.
        setGraph((prev) =>
          prev && Math.abs(prev.width - w) < 24 && Math.abs(prev.height - h) < 120
            ? prev
            : buildGraph(w, h)
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
  }, []);

  usePointerDistortion(svgRef, graph);

  return (
    <div className="ambient" aria-hidden="true" ref={ref}>
      <div className="ambient-wash" />

      {graph && (
        <svg
          // Remount rather than reconcile when the graph is rebuilt: the
          // pointer loop mutates these elements directly, and reusing them
          // would carry a previous graph's distortion onto a new one.
          key={`${graph.width}x${graph.height}`}
          ref={svgRef}
          className="ambient-graph"
          width={graph.width}
          height={graph.height}
          viewBox={`0 0 ${graph.width} ${graph.height}`}
          fill="none"
        >
          {graph.links.map(([from, to], i) => {
            const a = graph.points[from];
            const b = graph.points[to];
            return (
              <path
                key={i}
                className="ambient-edge"
                d={`M${a.x.toFixed(1)} ${a.y.toFixed(1)}L${b.x.toFixed(1)} ${b.y.toFixed(1)}`}
              />
            );
          })}


          {graph.dots.map((index, i) => {
            const point = graph.points[index];
            const endpoint = graph.degrees[index] === 1 ? 'true' : undefined;
            const crossings = graph.arrivals.filter((a) => a.node === index);

            // Grouped so the pointer loop can move the node and everything
            // it throws off with a single transform.
            return (
              <g key={i} className="ambient-dot">
                {crossings.map((arrival, k) => (
                  <circle
                    key={k}
                    className="ambient-arrival"
                    cx={point.x}
                    cy={point.y}
                    r="2"
                    // The pulse started at its own negative delay; adding the
                    // travel time to this node lands the effect as it arrives.
                    style={
                      { '--hit': `${pulseDelay(arrival.pulse) + arrival.at}s` } as React.CSSProperties
                    }
                  />
                ))}
                <circle
                  cx={point.x}
                  cy={point.y}
                  r="2"
                  className="ambient-node"
                  data-endpoint={endpoint}
                />
              </g>
            );
          })}

          {graph.pulses.map((pulse, i) => {
            const start = graph.points[pulse.route[0]];
            const d = pulse.route
              .slice(1)
              .reduce(
                (acc, index) =>
                  `${acc}L${graph.points[index].x.toFixed(1)} ${graph.points[index].y.toFixed(1)}`,
                `M${start.x.toFixed(1)} ${start.y.toFixed(1)}`
              );
            return (
              <path
                key={i}
                d={d}
                className="ambient-pulse"
                style={
                  {
                    animationDelay: `${pulseDelay(i)}s`,
                    // A fixed dash with a gap the length of the route means
                    // exactly one segment is visible however long the route is.
                    strokeDasharray: `${DASH} ${pulse.length + DASH}`,
                    '--travel': `${-pulse.length}px`,
                  } as React.CSSProperties
                }
              />
            );
          })}
        </svg>
      )}

      <div className="ambient-grain" />
    </div>
  );
}

/** Staggered starts, so the pulses never set off together. */
function pulseDelay(index: number): number {
  return index * -3.4 - 1.5;
}
