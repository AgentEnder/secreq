/**
 * `<secreq-window>` — a captured consent window, re-drawn as DOM.
 *
 * ## What this is
 *
 * The screenshot harness lays every fixture out twice: once through wgpu,
 * which produces the PNG, and once on the CPU, which produces
 * `dev-docs/ui-screenshots/<id>/layout.json` — the shape stream egui
 * painted, in points, with every text run's position, baseline, size,
 * colour and underline. That file exists to fail CI when the UI moves
 * without a re-render. It is also, it turns out, a complete description
 * of the window: **four kinds of shape** (rect, circle, line, text), no
 * meshes, no textures, no paths. Everything needed to draw the window
 * again is in it.
 *
 * So this element draws it again. The reader gets text they can select,
 * copy, search and hear read aloud, instead of a picture of text — and a
 * later ticket gets a window whose individual rows an animation can
 * reach into, which no PNG will ever offer.
 *
 * ## The markup contract
 *
 * A `<secreq-window>` wraps the **exact figure `::shot` already emits**
 * (see `window-markup.ts`). That is the whole degradation story: with no
 * JavaScript, before the geometry has been fetched, or before the app's
 * own fonts have loaded, the reader is looking at the published
 * screenshot of this very fixture — the same bytes, the same caption, the
 * same frame. The screenshot is hidden only once a faithful replacement
 * is standing in front of it.
 *
 * Deliberately **no shadow DOM**, for the reasons `secreq-terminal-element.ts`
 * sets out at length: the figure is server-rendered light DOM that has to
 * stay visible to the page stylesheet, to Pagefind, and to a reader with
 * scripting off.
 *
 * ## Three things that were learned the hard way
 *
 * - **Text is positioned by its baseline, so it is SVG.** An HTML span can
 *   only be positioned by the top of its box, leaving the browser to
 *   centre the glyphs inside a line box using its own ascent and descent —
 *   wrong by up to a pixel on every line, differently per font size.
 *   `<text y>` *is* the baseline, which is exactly the coordinate egui
 *   records.
 * - **Paint order is document order.** Boxes are absolutely positioned
 *   divs and text is SVG, so a text layer emitted up front is painted
 *   over by every box after it — in the spike that meant a window with no
 *   text in it at all. Rather than lift the text with a z-index and hope
 *   nothing legitimately covers it, the walk below emits shapes in the
 *   order egui painted them, opening a fresh SVG layer whenever a box
 *   interrupts. Positioned siblings paint in tree order, so z-order comes
 *   out right by construction — including the cases where a box really is
 *   meant to be on top, like the auto-deny banner.
 * - **egui's colours are premultiplied; CSS's are not.** `#14141414` is
 *   white at 8%, not near-black at 8%. Handing that hex straight to CSS
 *   turns every hairline on a dark panel inside out.
 */

/** `#rrggbbaa`, **premultiplied** — see [`cssColor`]. */
type Rgba = string;
/** `[width, colour]`. Width is in points; zero means "not painted". */
type Stroke = [number, Rgba];
/** `[min.x, min.y, max.x, max.y]`, in points. */
type Quad = [number, number, number, number];
type Point = [number, number];

interface Clipped {
  /** The rect egui was clipping to when it painted this shape. */
  clip: Quad;
}

interface RectShape extends Clipped {
  k: 'rect';
  rect: Quad;
  fill: Rgba;
  stroke: Stroke;
  /** Whether the stroke sits inside the rect or outside it. */
  stroke_kind: 'Inside' | 'Outside' | 'Middle';
  /** How far a shadow bleeds past the rect. Zero throughout this corpus. */
  blur: number;
  /** `[nw, ne, se, sw]` — the order CSS `border-radius` takes. */
  radius: [number, number, number, number];
}

interface CircleShape extends Clipped {
  k: 'circle';
  center: Point;
  radius: number;
  fill: Rgba;
  stroke: Stroke;
}

interface LineShape extends Clipped {
  k: 'line';
  a: Point;
  b: Point;
  stroke: Stroke;
}

interface TextRun {
  text: string;
  /** `[start, end]` of the run's advance, relative to its row. */
  x: [number, number];
  /** Baseline, relative to the row — not the top of a line box. */
  baseline: number;
  size: number;
  family: 'proportional' | 'monospace';
  color: Rgba;
  /** The mnemonic rule under Approve's `A`. Real UI, not decoration. */
  underline: Stroke;
}

interface TextRow {
  /** The row's box, relative to the galley. */
  rect: Quad;
  runs: TextRun[];
}

interface TextShape extends Clipped {
  k: 'text';
  /** The galley's top-left, in window points. */
  pos: Point;
  underline: Stroke;
  rows: TextRow[];
}

/**
 * A shape kind the capture records by name alone.
 *
 * `ui_layout/mod.rs` deliberately does not pin the geometry of meshes,
 * paths and béziers — nothing in these windows painted one when the
 * capture was written, and recording the kind rather than panicking left
 * the decision about what is worth pinning to whoever introduces the
 * first. A handful of fixtures have since grown one (the audit tab's
 * chevrons, a couple of rule rows), and this element cannot draw what
 * the file does not describe. Those fixtures render with a small piece
 * missing; the rest are complete.
 */
interface OpaqueShape extends Clipped {
  k: 'mesh' | 'path' | 'ellipse' | 'quadratic' | 'cubic' | 'callback' | 'other';
}

type WindowShape = RectShape | CircleShape | LineShape | TextShape | OpaqueShape;

/** One variant of one fixture, as the Vite plugin publishes it. */
export interface WindowScene {
  /** The logical window size in points — 500×470 for a prompt. */
  size: [number, number];
  shapes: WindowShape[];
}

/**
 * The event raised when a control named by the `press` attribute has been
 * found in the geometry: `x` and `y` are its centre as a fraction of the
 * window, so a listener can place something over the figure at any scale
 * without knowing the capture's point size.
 *
 * Deliberately an announcement rather than a drawing, for the same reason
 * `<secreq-terminal>` announces its `gui` markers and draws nothing: the
 * thing that wants to point at Approve is a `::flow`'s pointer, which lives
 * outside this figure entirely, and a window asked to draw one would be a
 * window that had to know what a flow is.
 */
export const PRESS_EVENT = 'secreq-window-press';

export interface PressEventDetail {
  /** The label that was located — the string the `press` attribute named. */
  label: string;
  /** Centre of the label, `0..1` across the window's width. */
  x: number;
  /** Centre of the label, `0..1` down the window's height. */
  y: number;
}

const SVG_NS = 'http://www.w3.org/2000/svg';
const XML_NS = 'http://www.w3.org/XML/1998/namespace';

/** The desktop assumed when nothing has declared one. Matches `::shot`. */
const FALLBACK_VARIANT = 'macos-dark';

/**
 * Fetched scenes, keyed by URL and shared across every element on the page.
 *
 * A page that shows the same window twice — the guide and the flow beside
 * it — should fetch its geometry once, and a reader flipping the OS picker
 * back and forth should not re-fetch what they just had.
 */
const SCENES = new Map<string, Promise<WindowScene>>();

function loadScene(url: string): Promise<WindowScene> {
  let pending = SCENES.get(url);
  if (!pending) {
    pending = fetch(url).then((response) => {
      if (!response.ok) throw new Error(`${url} returned ${response.status}`);
      return response.json() as Promise<WindowScene>;
    });
    SCENES.set(url, pending);
  }
  return pending;
}

/**
 * The app's own faces, loaded once and awaited before anything is drawn.
 *
 * `document.fonts.ready` is not enough on its own: a webfont nothing has
 * used yet is not "pending", so `ready` resolves immediately and the first
 * scene is typeset in whatever the fallback is. Asking for the faces by
 * name is what makes them load at all.
 */
let fontsLoaded: Promise<unknown> | null = null;

function loadFonts(): Promise<unknown> {
  fontsLoaded ??= Promise.all([
    document.fonts.load('12px sqw-proportional'),
    document.fonts.load('12px sqw-monospace'),
  ]);
  return fontsLoaded;
}

/**
 * egui stores colours with alpha already multiplied into the channels;
 * CSS expects them straight. Dividing it back out is the whole conversion
 * — and skipping it is why a 8%-white hairline reads as a black one.
 */
function cssColor(color: Rgba): string {
  const alpha = Number.parseInt(color.slice(7, 9), 16);
  if (alpha === 255) return color.slice(0, 7);
  if (alpha === 0) return 'transparent';
  const straight = (at: number) =>
    Math.min(255, Math.round((Number.parseInt(color.slice(at, at + 2), 16) * 255) / alpha));
  return `rgba(${straight(1)}, ${straight(3)}, ${straight(5)}, ${(alpha / 255).toFixed(4)})`;
}

/** Whether a stroke would put any ink down. */
function paints(stroke: Stroke): boolean {
  return stroke[0] > 0 && !stroke[1].endsWith('00');
}

/**
 * `clip-path` for a box that its clip rect actually cuts, or `''`.
 *
 * CSS insets are measured from the element's own edges, which is why this
 * takes both rects. Most shapes sit well inside their clip — the two
 * scroll viewports are the reason any of them do not — so the common
 * answer is no clip path at all, and one fewer property for the
 * compositor to think about.
 */
function insetClip(rect: Quad, clip: Quad): string {
  const top = Math.max(0, clip[1] - rect[1]);
  const right = Math.max(0, rect[2] - clip[2]);
  const bottom = Math.max(0, rect[3] - clip[3]);
  const left = Math.max(0, clip[0] - rect[0]);
  if (top === 0 && right === 0 && bottom === 0 && left === 0) return '';
  return `inset(${top}px ${right}px ${bottom}px ${left}px)`;
}

/** Whether `box` is wholly inside `clip`, and so needs no clipping at all. */
function within(box: Quad, clip: Quad): boolean {
  return box[0] >= clip[0] && box[1] >= clip[1] && box[2] <= clip[2] && box[3] <= clip[3];
}

/** Distinguishes one scene's `<clipPath>` ids from the next scene's. */
let clipSerial = 0;

/**
 * Draw one captured window into a fresh element.
 *
 * Exported for the same reason the harness's fixtures are: this is the
 * one place that turns geometry into DOM, and a test that drew it a
 * second way would be testing itself.
 */
export function buildScene(scene: WindowScene): HTMLElement {
  const [width, height] = scene.size;
  const root = document.createElement('div');
  root.className = 'sqw-scene';
  root.style.width = `${width}px`;
  root.style.height = `${height}px`;

  // The SVG layer currently open, or null if a box closed it. Shapes are
  // walked in paint order and vectors accumulate into one layer until a
  // box interrupts, so the tree order the browser paints in is the order
  // egui painted in.
  let layer: SVGSVGElement | null = null;
  const vectors = () => {
    if (!layer) {
      layer = document.createElementNS(SVG_NS, 'svg');
      layer.setAttribute('width', String(width));
      layer.setAttribute('height', String(height));
      layer.setAttribute('viewBox', `0 0 ${width} ${height}`);
      root.appendChild(layer);
    }
    return layer;
  };

  for (const shape of scene.shapes) {
    if (shape.k === 'rect') {
      const box = drawRect(shape);
      if (box) {
        layer = null;
        root.appendChild(box);
      }
    } else if (shape.k === 'circle') {
      drawCircle(vectors(), shape);
    } else if (shape.k === 'line') {
      drawLine(vectors(), shape);
    } else if (shape.k === 'text') {
      drawText(vectors(), shape);
    }
    // Anything else is a shape the capture records by name only; see
    // `OpaqueShape`. Nothing to draw, and nothing useful to say about it
    // from here.
  }

  return root;
}

/**
 * A box, or `null` for one that puts no ink down.
 *
 * Two thirds of the rects in a capture are invisible — egui paints a
 * transparent, unstroked rect for every frame and panel it lays out.
 * Dropping them here is not an optimisation so much as an accuracy
 * measure: each one kept would close the open SVG layer and split the
 * text either side of it into two, for nothing.
 */
function drawRect(shape: RectShape): HTMLElement | null {
  const filled = !shape.fill.endsWith('00');
  const stroked = paints(shape.stroke);
  if (!filled && !stroked) return null;

  const [width, color] = shape.stroke;
  // A stroke drawn outside the rect grows the box it is drawn on; one
  // drawn inside is exactly a border-box border. (Outside strokes are
  // all zero-width in today's corpus, so this branch is the field being
  // honoured rather than a case anything currently exercises.)
  const outset = stroked && shape.stroke_kind === 'Outside' ? width : 0;
  const [left, top, right, bottom] = shape.rect;
  const radius = shape.radius.map((corner) => corner + outset);

  const box = document.createElement('div');
  box.style.left = `${left - outset}px`;
  box.style.top = `${top - outset}px`;
  box.style.width = `${right - left + 2 * outset}px`;
  box.style.height = `${bottom - top + 2 * outset}px`;
  box.style.boxSizing = 'border-box';
  if (filled) box.style.background = cssColor(shape.fill);
  if (stroked) box.style.border = `${width}px solid ${cssColor(color)}`;
  if (radius.some((corner) => corner > 0)) {
    box.style.borderRadius = radius.map((corner) => `${corner}px`).join(' ');
  }
  const clip = insetClip(
    [left - outset, top - outset, right + outset, bottom + outset],
    shape.clip,
  );
  if (clip) box.style.clipPath = clip;
  return box;
}

function drawCircle(layer: SVGSVGElement, shape: CircleShape) {
  const circle = document.createElementNS(SVG_NS, 'circle');
  circle.setAttribute('cx', String(shape.center[0]));
  circle.setAttribute('cy', String(shape.center[1]));
  circle.setAttribute('r', String(shape.radius));
  circle.setAttribute('fill', shape.fill.endsWith('00') ? 'none' : cssColor(shape.fill));
  if (paints(shape.stroke)) {
    // epaint straddles a closed path with its stroke, and so does SVG.
    circle.setAttribute('stroke', cssColor(shape.stroke[1]));
    circle.setAttribute('stroke-width', String(shape.stroke[0]));
  }
  const reach = shape.radius + shape.stroke[0] / 2;
  clipTo(
    layer,
    circle,
    [
      shape.center[0] - reach,
      shape.center[1] - reach,
      shape.center[0] + reach,
      shape.center[1] + reach,
    ],
    shape.clip,
  );
  layer.appendChild(circle);
}

function drawLine(layer: SVGSVGElement, shape: LineShape) {
  if (!paints(shape.stroke)) return;
  const line = document.createElementNS(SVG_NS, 'line');
  line.setAttribute('x1', String(shape.a[0]));
  line.setAttribute('y1', String(shape.a[1]));
  line.setAttribute('x2', String(shape.b[0]));
  line.setAttribute('y2', String(shape.b[1]));
  line.setAttribute('stroke', cssColor(shape.stroke[1]));
  line.setAttribute('stroke-width', String(shape.stroke[0]));
  // epaint caps nothing: an open path ends where its last point is, which
  // is what butt caps mean. SVG's default is butt too, but the gate
  // monogram is three separate segments meeting at right angles and it is
  // worth being explicit about why they do not overshoot.
  line.setAttribute('stroke-linecap', 'butt');
  const half = shape.stroke[0] / 2;
  clipTo(
    layer,
    line,
    [
      Math.min(shape.a[0], shape.b[0]) - half,
      Math.min(shape.a[1], shape.b[1]) - half,
      Math.max(shape.a[0], shape.b[0]) + half,
      Math.max(shape.a[1], shape.b[1]) + half,
    ],
    shape.clip,
  );
  layer.appendChild(line);
}

/**
 * One galley: a `<text>` per run, plus a rule under any run that carries
 * a mnemonic underline.
 *
 * Every coordinate is the sum of three the capture keeps apart — the
 * galley's position on the window, the row's position in the galley, and
 * the run's position in the row — because that is how egui builds them
 * and keeping them apart is what makes a re-wrapped paragraph diff as one
 * row rather than as every row after it.
 */
function drawText(layer: SVGSVGElement, shape: TextShape) {
  const [originX, originY] = shape.pos;

  for (const row of shape.rows) {
    const rowX = originX + row.rect[0];
    const rowY = originY + row.rect[1];

    for (const run of row.runs) {
      const text = document.createElementNS(SVG_NS, 'text');
      text.setAttribute('x', String(rowX + run.x[0]));
      text.setAttribute('y', String(rowY + run.baseline));
      text.setAttribute('fill', cssColor(run.color));
      text.setAttribute('font-size', `${run.size}px`);
      text.setAttribute('class', run.family === 'monospace' ? 'sqw-mono' : 'sqw-prop');
      // Runs are split at format boundaries, not at word boundaries, so
      // " wants to use " really does begin and end with the spaces that
      // separate it from the secret name either side. XML would collapse
      // them and the two names would close up against the verb.
      text.setAttributeNS(XML_NS, 'xml:space', 'preserve');
      text.textContent = run.text;
      clipTo(
        layer,
        text,
        [rowX + run.x[0], rowY, rowX + run.x[1], originY + row.rect[3]],
        shape.clip,
      );
      layer.appendChild(text);

      if (paints(run.underline)) {
        const rule = document.createElementNS(SVG_NS, 'line');
        // epaint puts the rule on the baseline's descender line — the
        // bottom of the glyph's logical box, which for a row of one font
        // size is the bottom of the row.
        const y = originY + row.rect[3];
        rule.setAttribute('x1', String(rowX + run.x[0]));
        rule.setAttribute('y1', String(y));
        rule.setAttribute('x2', String(rowX + run.x[1]));
        rule.setAttribute('y2', String(y));
        rule.setAttribute('stroke', cssColor(run.underline[1]));
        rule.setAttribute('stroke-width', String(run.underline[0]));
        layer.appendChild(rule);
      }
    }
  }
}

/**
 * Clip an SVG shape to the rect egui was clipping to, if that rect cuts it.
 *
 * SVG has no inset-clip shorthand, so this costs a `<clipPath>` in the
 * layer's `<defs>` — which is why it is only paid when the shape actually
 * overhangs. A page can hold several windows, so the ids are serialised
 * globally rather than per scene.
 */
function clipTo(layer: SVGSVGElement, node: SVGElement, box: Quad, clip: Quad) {
  if (within(box, clip)) return;

  let defs = layer.querySelector('defs');
  if (!defs) {
    defs = document.createElementNS(SVG_NS, 'defs');
    layer.insertBefore(defs, layer.firstChild);
  }

  const id = `sqw-clip-${(clipSerial += 1)}`;
  const path = document.createElementNS(SVG_NS, 'clipPath');
  path.setAttribute('id', id);
  const rect = document.createElementNS(SVG_NS, 'rect');
  rect.setAttribute('x', String(clip[0]));
  rect.setAttribute('y', String(clip[1]));
  rect.setAttribute('width', String(clip[2] - clip[0]));
  rect.setAttribute('height', String(clip[3] - clip[1]));
  path.appendChild(rect);
  defs.appendChild(path);
  node.setAttribute('clip-path', `url(#${id})`);
}

/**
 * The centre of the row of text reading exactly `label`, in window points.
 *
 * ## Why the text and not the button
 *
 * The obvious target is the control's own rect — the accent-filled box egui
 * paints behind Approve — and it is the wrong one, because on GNOME there
 * isn't one. A libadwaita action bar is two hairlines and two words; the
 * button is a region, not a shape. Every chrome does centre its label in its
 * control, though, so the label's centre *is* the control's centre wherever
 * the control exists: on macOS the word sits at (439.92, 447.50) and the
 * accent rect's centre is (440, 447.5), and Windows agrees to within a fifth
 * of a point. Aiming at the word works on all six cells of the matrix and
 * needs nothing to be true about how the button is drawn.
 *
 * Runs are matched joined, not one at a time, because a mnemonic splits the
 * label: Approve is painted as `A` — carrying the underline — followed by
 * `pprove`. Matching the whole row is also what keeps this from landing on
 * `Open Manager…` when asked for `Open`.
 */
function findLabelCentre(scene: WindowScene, label: string): Point | null {
  for (const shape of scene.shapes) {
    if (shape.k !== 'text') continue;
    for (const row of shape.rows) {
      const runs = row.runs;
      if (runs.length === 0) continue;
      if (
        runs
          .map((run) => run.text)
          .join('')
          .trim() !== label
      )
        continue;

      // The three coordinates the capture keeps apart, summed the way
      // `drawText` sums them: galley origin, row box, run advance.
      const rowX = shape.pos[0] + row.rect[0];
      return [
        rowX + (runs[0].x[0] + runs[runs.length - 1].x[1]) / 2,
        shape.pos[1] + (row.rect[1] + row.rect[3]) / 2,
      ];
    }
  }
  return null;
}

export class SecreqWindow extends HTMLElement {
  /**
   * Which draw is allowed to mount. Bumped on every disconnect and every
   * desktop change, so a fetch that resolves after the reader has flipped
   * the OS picker — or navigated away — returns without touching the DOM.
   * The terminal element uses the same token for the same reason.
   */
  #run = 0;
  /**
   * The `<id>/<variant>` currently standing in the figure, so a desktop
   * change that does not move this window — a theme toggle under a pinned
   * variant — costs nothing. Both halves are in the key: a `::flow` that
   * steps one element through several fixtures changes the id alone.
   */
  #drawn: string | null = null;
  #stage: HTMLElement | null = null;
  #scene: HTMLElement | null = null;
  /**
   * The capture the scene standing in the figure was built from, kept so a
   * question about where something *is* can be answered without refetching
   * or reading it back out of the DOM.
   */
  #geometry: WindowScene | null = null;
  #resize: ResizeObserver | null = null;
  #desktop: MutationObserver | null = null;

  static get observedAttributes() {
    return ['shot', 'variant', 'press'];
  }

  connectedCallback() {
    // The reader's desktop lives on `<html>`, where `+Head.tsx` puts it
    // before first paint and the OS picker and theme toggle move it
    // afterwards. Screenshots follow it through CSS; a scene has to be
    // rebuilt, because it is not the same window.
    this.#desktop = new MutationObserver(() => void this.#draw());
    this.#desktop.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-os', 'data-theme'],
    });
    void this.#draw();
  }

  disconnectedCallback() {
    this.#run += 1;
    this.#desktop?.disconnect();
    this.#desktop = null;
    this.#resize?.disconnect();
    this.#resize = null;
  }

  attributeChangedCallback(name: string) {
    if (!this.isConnected) return;
    // Re-aiming is not re-drawing: the same window can be asked about a
    // different control, and rebuilding several hundred nodes to answer a
    // question about one of them would be absurd. A `press` set before the
    // geometry has landed is not lost — `#draw` announces when it finishes.
    if (name === 'press') this.#announcePress();
    else void this.#draw();
  }

  /** `macos-dark` — pinned on the element, or the reader's own desktop. */
  get #variant(): string {
    const pinned = this.getAttribute('variant');
    if (pinned) return pinned;
    const root = document.documentElement;
    const os = root.dataset.os;
    const theme = root.dataset.theme;
    return os && theme ? `${os}-${theme}` : FALLBACK_VARIANT;
  }

  async #draw() {
    const id = this.getAttribute('shot');
    if (!id) return;

    const variant = this.#variant;
    const wanted = `${id}/${variant}`;
    // Still announced on the early return: a reconnection redraws nothing
    // but leaves whatever was listening for the press target — a `::flow`
    // reattached by a client-side navigation — with no way to hear it again.
    if (wanted === this.#drawn) {
      this.#announcePress();
      return;
    }

    const run = (this.#run += 1);
    let scene: WindowScene;
    try {
      // The fonts are awaited alongside the geometry rather than after
      // it: both have to be in hand before the first glyph is placed, and
      // asking for them in parallel means the screenshot is swapped out
      // once rather than twice.
      [scene] = await Promise.all([loadScene(this.#url(id, variant)), loadFonts()]);
    } catch {
      // The screenshot is still there and still says the right thing, so
      // a window that cannot be rebuilt is a window that stays a picture.
      return;
    }
    if (this.#run !== run || !this.isConnected) return;

    this.#mount(buildScene(scene), scene.size);
    this.#drawn = wanted;
    this.#geometry = scene;
    this.#announcePress();
  }

  /**
   * Say where the control named by `press` is, if anything asked.
   *
   * Silent when nothing asked and when the geometry is not in hand yet —
   * both are ordinary — but loud when a label was asked for and is not in
   * the window, because that is a rename nothing else would catch: the
   * fixture still renders, the flow still plays, and the only symptom is a
   * pointer that never arrives.
   */
  #announcePress() {
    const label = this.getAttribute('press');
    const scene = this.#geometry;
    if (!label || !scene) return;

    const centre = findLabelCentre(scene, label);
    if (!centre) {
      console.warn(
        `[docs-site] <secreq-window shot="${this.getAttribute('shot')}"> paints no control ` +
          `labelled "${label}", so nothing can point at it. Check the label in ` +
          'docs-site/flow-defs.ts against the window, and regenerate the fixtures if the ' +
          'UI has been reworded.',
      );
      return;
    }

    const detail: PressEventDetail = {
      label,
      x: centre[0] / scene.size[0],
      y: centre[1] / scene.size[1],
    };
    this.dispatchEvent(new CustomEvent(PRESS_EVENT, { bubbles: true, composed: true, detail }));
  }

  /**
   * Where the geometry for one cell of the matrix lives.
   *
   * Deliberately the screenshot's own URL with a different extension: the
   * Vite plugin publishes both out of the same fixture folder under the
   * same flat name, so a window and its fallback can never disagree about
   * which render they are.
   */
  #url(id: string, variant: string): string {
    const png = this.querySelector<HTMLImageElement>('.shot-img[data-fallback="true"]');
    const base = png ? png.getAttribute('src')!.replace(/[^/]+$/, '') : '/ui/';
    return `${base}${id}-${variant}.json`;
  }

  /**
   * Stand the scene up in place of the screenshot.
   *
   * The stage is what holds the figure's height once the image inside it
   * is hidden — an absolutely positioned scene contributes none — and
   * `aspect-ratio` from the captured size gives it exactly the height the
   * image was giving it a moment ago, so nothing on the page moves.
   */
  #mount(scene: HTMLElement, [width, height]: [number, number]) {
    if (!this.#stage) {
      const stage = document.createElement('div');
      stage.className = 'sqw-stage';

      const zoom = this.querySelector<HTMLElement>('.shot-zoom');
      if (zoom) {
        zoom.before(stage);
        // Inline, because the rule that shows the reader's own render is
        // a six-attribute selector on `:root` that a class here would
        // lose to. The images stay in the DOM: they are what the figure
        // falls back to, and hiding them is not the same as removing them.
        zoom.style.display = 'none';
      } else {
        this.appendChild(stage);
      }

      this.#stage = stage;
      this.#resize = new ResizeObserver(() => this.#rescale());
      this.#resize.observe(stage);
    }

    this.#stage.style.aspectRatio = `${width} / ${height}`;
    this.#scene?.remove();
    this.#scene = scene;
    this.#stage.appendChild(scene);
    this.#rescale();
  }

  /**
   * Fit the scene to the column.
   *
   * The window is built at its own point size and scaled once as a whole,
   * rather than every coordinate being multiplied on the way in — so the
   * numbers in the DOM are the numbers in the capture, and a scene
   * inspected in devtools can be read against `layout.json` directly.
   */
  #rescale() {
    if (!this.#stage || !this.#scene) return;
    const scene = this.#scene;
    const width = Number.parseFloat(scene.style.width);
    if (!width) return;
    scene.style.setProperty('--sqw-scale', String(this.#stage.clientWidth / width));
  }
}

// Reached only through `secreq-window.ts`, which imports this module
// dynamically in the browser, so `HTMLElement` is always defined by the
// time this file is evaluated.
if (!customElements.get('secreq-window')) {
  customElements.define('secreq-window', SecreqWindow);
}
