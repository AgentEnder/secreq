/**
 * The single renderer for a terminal session.
 *
 * The counterpart to `shot-markup.ts`, and it exists for the same reason:
 * both the `<Term />` React component and the `::term{id=…}` markdown
 * directive emit this exact HTML, so a session shown on the landing page and
 * one shown inside a guide cannot drift apart in markup, styling or
 * behaviour. Playback needs no separate step: the markup wraps the figure
 * in `<secreq-terminal>`, which the browser upgrades wherever it lands.
 *
 * Everything a terminal knows about itself is generated.
 * `.generated/terms.json` is built by the `secreq-copy-repo-assets` Vite
 * plugin from the recordings `tests/cli_transcripts.rs` writes by driving
 * the real binary on a real pty. There is no hand-maintained transcript
 * anywhere in this site — a session that says secreq asks something is a
 * session in which secreq really asked it.
 *
 * ## What gets rendered
 *
 * A recording is a list of steps: `frame` (the screen after a redraw),
 * `type` (text the user typed, and where), `key` (a bare keypress). All of
 * it is rendered server-side into one static block per frame, stacked and
 * shown one at a time. That means the terminal is complete and readable
 * with JavaScript disabled, with `prefers-reduced-motion: reduce`, and in
 * the instant before hydration — the final frame is simply the one on top.
 */

import generated from './.generated/terms.json';

/** One styled run of characters, as recorded by the harness. */
interface Run {
  t: string;
  /** Foreground: `"0".."15"` palette index, or `"#rrggbb"`. */
  f?: string;
  b?: string;
  /** Bitfield: 1 bold, 2 dim, 4 italic, 8 underline, 16 inverse. */
  s?: number;
}

type Line = Run[];

interface FrameStep {
  kind: 'frame';
  lines: Line[];
  /** Extra dwell in ms, for a beat where the real command was working. */
  hold?: number;
}

interface TypeStep {
  kind: 'type';
  text: string;
  row: number;
  col: number;
}

interface KeyStep {
  kind: 'key';
  key: string;
}

type Step = FrameStep | TypeStep | KeyStep;

interface TermEntry {
  id: string;
  /** The command being demonstrated. Shown in the title bar. */
  command: string;
  /** The figcaption, authored on the fixture. */
  caption?: string;
  cols: number;
  steps: Step[];
}

const TERMS = generated as unknown as Record<string, TermEntry>;

/** Every transcript id available to the site, in filename order. */
export function allTermIds(): string[] {
  return Object.keys(TERMS).sort();
}

const STYLE_CLASS: [number, string][] = [
  [1, 'b'],
  [2, 'd'],
  [4, 'i'],
  [8, 'u'],
  [16, 'v'],
];

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Render one run.
 *
 * Palette indices become classes rather than colours: `term.css` resolves
 * `.f3` differently in light and dark, because "ANSI yellow" that reads on
 * a dark panel is illegible on a white one. Only true-colour cells — which
 * a program asked for by exact value — get an inline style.
 */
function runHtml(run: Run): string {
  const classes: string[] = [];
  let style = '';

  if (run.f) {
    if (run.f.startsWith('#')) style += `color:${run.f};`;
    else classes.push(`f${run.f}`);
  }
  if (run.b) {
    if (run.b.startsWith('#')) style += `background:${run.b};`;
    else classes.push(`g${run.b}`);
  }
  for (const [bit, cls] of STYLE_CLASS) {
    if ((run.s ?? 0) & bit) classes.push(cls);
  }

  const text = escapeHtml(run.t);
  if (classes.length === 0 && style === '') return text;

  const attrs = [
    classes.length ? ` class="${classes.join(' ')}"` : '',
    style ? ` style="${style}"` : '',
  ].join('');
  return `<span${attrs}>${text}</span>`;
}

function lineHtml(line: Line): string {
  // An empty line still has to occupy a row, or a session with breathing
  // room in it collapses to a solid block of text.
  if (line.length === 0) return '<span class="term-line"> </span>';
  return `<span class="term-line">${line.map(runHtml).join('')}</span>`;
}

function frameHtml(frame: FrameStep, index: number): string {
  return [
    `<div class="term-frame" data-frame="${index}"${frame.hold ? ` data-hold="${frame.hold}"` : ''}>`,
    frame.lines.map(lineHtml).join(''),
    '</div>',
  ].join('');
}

/**
 * Serialise the typing and keypresses for the player.
 *
 * Frames are already in the DOM; what the player cannot infer is what
 * happened *between* them. This emits that as one JSON attribute rather
 * than a script tag, so the markup stays a single self-contained element
 * that markdown can drop anywhere.
 */
function scriptJson(steps: Step[]): string {
  const script: unknown[] = [];
  let frameIndex = -1;

  for (const step of steps) {
    if (step.kind === 'frame') {
      frameIndex += 1;
      script.push({ k: 'f', i: frameIndex, hold: step.hold });
    } else if (step.kind === 'type') {
      script.push({ k: 't', text: step.text, row: step.row, col: step.col });
    } else {
      script.push({ k: 'k', key: step.key });
    }
  }

  return escapeHtml(JSON.stringify(script));
}

export interface TermMarkupOptions {
  /** Overrides the recording's caption. Pass `''` to drop it entirely. */
  caption?: string;
}

const REPLAY_ICON =
  '<svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" ' +
  'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<path d="M14 8a6 6 0 1 1-1.8-4.3M14 2v4h-4" /></svg>';

/**
 * Render the terminal for `id`.
 *
 * Throws on an unknown id, exactly as `shotHtml` does: a guide that claims
 * to show a session which was never recorded should stop the build, not
 * publish a hole where the demonstration was meant to be.
 */
export function termHtml(id: string, options: TermMarkupOptions = {}): string {
  const entry = TERMS[id];
  if (!entry) {
    throw new Error(
      `[docs-site] No CLI transcript named "${id}". Expected a fixture of that name in ` +
        'tests/cli_transcripts.rs — record it with ' +
        '`cargo test --test cli_transcripts -- --ignored --test-threads=1`.'
    );
  }

  const caption = options.caption ?? entry.caption ?? '';
  const frames = entry.steps.filter((step): step is FrameStep => step.kind === 'frame');

  // `<secreq-terminal>` is the outermost element so it can reach every part
  // it drives — the replay button in the title bar as well as the frames.
  // The browser upgrades it wherever this string lands, which is why the
  // React component and the markdown directive need nothing in common
  // beyond emitting it.
  return [
    '<secreq-terminal>',
    `<figure class="term" style="--term-cols: ${entry.cols}">`,
    '<div class="term-frame-wrap">',
    '<div class="term-bar">',
    `<span class="term-cmd">${escapeHtml(entry.command)}</span>`,
    '<button type="button" class="term-replay">',
    REPLAY_ICON,
    'Replay',
    '</button>',
    '</div>',
    `<div class="term-body" data-script="${scriptJson(entry.steps)}">`,
    frames.map(frameHtml).join(''),
    // The caret is positioned during playback and is inert until then.
    '<span class="term-caret" aria-hidden="true"></span>',
    '</div>',
    '</div>',
    caption ? `<figcaption>${caption}</figcaption>` : '',
    '</figure>',
    '</secreq-terminal>',
  ].join('');
}
