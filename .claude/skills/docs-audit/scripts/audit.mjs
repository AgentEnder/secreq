#!/usr/bin/env node
/**
 * Mechanical sweep over secreq's published prose.
 *
 * Everything here is deterministic and boring on purpose. The judgment —
 * whether a repeated topic is redundancy or deliberate reiteration, whether a
 * page is long because it earns it — belongs to whoever reads the report.
 * What a script is genuinely better at is remembering to look, which is how
 * five undocumented commands and two contradicting pages survived in a tree
 * that is otherwise heavily guarded.
 *
 * This is an advisory report, not a gate. It always exits 0. The things that
 * MUST hold are already enforced by `cargo test` (see SKILL.md); a finding
 * here is a question to answer, not a failure to fix.
 *
 *   node .claude/skills/docs-audit/scripts/audit.mjs [--json]
 */

import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join, basename, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(fileURLToPath(import.meta.url), '..', '..', '..', '..', '..');
const JSON_OUT = process.argv.includes('--json');

const rel = (p) => relative(ROOT, p);
const read = (p) => readFileSync(p, 'utf8');
const exists = (p) => existsSync(join(ROOT, p));

/** Every page the skill considers published prose. */
function pages() {
  const out = [];
  const docs = join(ROOT, 'docs');
  if (existsSync(docs)) {
    for (const f of readdirSync(docs).filter((f) => f.endsWith('.md'))) {
      out.push(join(docs, f));
    }
  }
  for (const p of ['README.md', 'CONTRIBUTING.md', 'packages/secreq-rule/README.md']) {
    if (exists(p)) out.push(join(ROOT, p));
  }
  const dev = join(ROOT, 'dev-docs');
  if (existsSync(dev)) {
    for (const d of readdirSync(dev)) {
      const readme = join(dev, d, 'README.md');
      if (existsSync(readme)) out.push(readme);
    }
  }
  return out;
}

/** Strip fenced code so prose checks don't fire on sample output. */
const prose = (text) => text.replace(/```[\s\S]*?```/g, '');

/** `id`s referenced by ::shot / ::term / ::flow, per kind. */
function directiveRefs(texts) {
  const shot = new Set();
  const term = new Set();
  for (const t of texts) {
    for (const m of t.matchAll(/::(shot|term|flow)\{(?:id|term)=([\w-]+)/g)) {
      (m[1] === 'shot' ? shot : term).add(m[2]);
    }
  }
  return { shot, term };
}

const findings = {};
const add = (key, rows) => {
  if (rows.length) findings[key] = rows;
};

const allPages = pages();
const texts = allPages.map(read);
const refs = directiveRefs(texts);

// ── Fixtures nobody shows ─────────────────────────────────────────────────
// The single highest-yield check. Every one of these is a rendered, committed,
// caption-carrying image that some page is currently describing in words.
const shotsDir = join(ROOT, 'dev-docs/ui-screenshots');
if (existsSync(shotsDir)) {
  const fixtures = readdirSync(shotsDir).filter((d) => statSync(join(shotsDir, d)).isDirectory());
  add('Screenshot fixtures no page references', fixtures.filter((f) => !refs.shot.has(f)).sort());
  add(
    '::shot ids with no fixture (build-breaking)',
    [...refs.shot].filter((id) => !fixtures.includes(id)).sort(),
  );
}

const termDir = join(ROOT, 'dev-docs/cli-transcripts');
if (existsSync(termDir)) {
  const recordings = readdirSync(termDir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => basename(f, '.json'));
  add('Transcripts no page references', recordings.filter((r) => !refs.term.has(r)).sort());
  add(
    '::term/::flow ids with no recording (build-breaking)',
    [...refs.term].filter((id) => !recordings.includes(id)).sort(),
  );
}

// ── Commands prose claims exist ───────────────────────────────────────────
// `docs/cli-reference.md` is generated from clap, so it is the list of verbs
// that actually exist. Prose naming anything else is describing a command the
// binary does not have — which is exactly how `secreq import` and
// `secreq store` outlived the verbs they named.
const refPath = join(ROOT, 'docs/cli-reference.md');
if (existsSync(refPath)) {
  const refText = read(refPath);
  const verbs = new Set();
  for (const m of refText.matchAll(/^#{2,6} `secreq ([a-z][\w -]*)`/gm)) {
    verbs.add(m[1].split(' ')[0]);
  }
  // Aliases are real spellings a reader may be told by a colleague, and the
  // generator prints them as prose rather than as headings. Missing them makes
  // `secreq ui` — which works — look like a command that does not exist.
  for (const m of refText.matchAll(/Also spelled ([^.]+)\./g)) {
    for (const a of m[1].matchAll(/`secreq ([a-z][\w-]*)`/g)) verbs.add(a[1]);
  }
  const knownFlags = new Set();
  for (const m of refText.matchAll(/\| `(-[^`|]+)`/g)) {
    for (const piece of m[1].split(',')) {
      const flag = piece.trim().split(' ')[0];
      if (flag.startsWith('-')) knownFlags.add(flag);
    }
  }

  const badVerbs = [];
  const badFlags = [];
  for (const [i, text] of texts.entries()) {
    if (allPages[i] === refPath) continue;
    for (const m of prose(text).matchAll(/`secreq ([a-z][\w-]*)((?: [^`]*)?)`/g)) {
      if (!verbs.has(m[1])) badVerbs.push(`${rel(allPages[i])}: secreq ${m[1]}`);
      // Only flags written inside a `secreq …` span, so a provider CLI's own
      // flags (`op run --no-masking`) can't be mistaken for ours.
      for (const f of m[2].matchAll(/(--[a-z][\w-]*)/g)) {
        // `--sq-` options are parsed by hand and deliberately absent from the
        // generated reference; see docs/cli.md#the-argv-contract.
        if (f[1].startsWith('--sq-')) continue;
        if (!knownFlags.has(f[1])) badFlags.push(`${rel(allPages[i])}: ${f[1]}`);
      }
    }
  }
  add('Commands named in prose that clap does not define', [...new Set(badVerbs)].sort());
  add('Flags named in prose that clap does not define', [...new Set(badFlags)].sort());

  // ── Flag tables competing with the generated reference ──────────────────
  const dupTables = [];
  for (const [i, text] of texts.entries()) {
    if (allPages[i] === refPath) continue;
    const rows = [...text.matchAll(/^\| `(--[a-z][\w-]*)[^`]*`/gm)]
      .map((m) => m[1])
      .filter((f) => !f.startsWith('--sq-') && knownFlags.has(f));
    if (rows.length >= 3) {
      dupTables.push(`${rel(allPages[i])}: ${rows.length} rows (${rows.slice(0, 4).join(', ')}…)`);
    }
  }
  add('Hand-written flag tables duplicating the generated reference', dupTables);
}

// ── One topic, many pages ─────────────────────────────────────────────────
// Distinctive code spans appearing on three or more pages. Not automatically
// wrong: a flag named in passing where it is relevant is fine. Worth reading
// when the same *explanation* has been written out more than once.
const spanPages = new Map();
for (const [i, text] of texts.entries()) {
  const page = rel(allPages[i]);
  for (const m of new Set([...prose(text).matchAll(/`([^`\n]{4,40})`/g)].map((m) => m[1]))) {
    if (!/^[-$~.\/\w]/.test(m)) continue;
    // A bare single identifier (`secreq`, `pass`, `PATH`) appears everywhere
    // by nature and says nothing about redundancy. What is worth reading is a
    // specific invocation, flag or path — all of which carry a space or
    // punctuation.
    if (!/[ \-\/._]/.test(m)) continue;
    if (!spanPages.has(m)) spanPages.set(m, new Set());
    spanPages.get(m).add(page);
  }
}
add(
  'Topics appearing on 4+ pages',
  [...spanPages.entries()]
    .filter(([, s]) => s.size >= 4)
    .sort((a, b) => b[1].size - a[1].size)
    .slice(0, 15)
    .map(([span, s]) => `${span}  →  ${[...s].map((p) => p.replace(/\.md$/, '')).join(', ')}`),
);

// ── Headings that exist twice ─────────────────────────────────────────────
const headings = new Map();
for (const [i, text] of texts.entries()) {
  for (const m of text.matchAll(/^#{2,3} (.+)$/gm)) {
    const h = m[1].trim().toLowerCase();
    if (!headings.has(h)) headings.set(h, new Set());
    headings.get(h).add(rel(allPages[i]).replace(/\.md$/, ''));
  }
}
add(
  'Same heading on multiple pages',
  [...headings.entries()]
    .filter(([, s]) => s.size > 1)
    .map(([h, s]) => `"${h}"  →  ${[...s].join(', ')}`)
    .sort(),
);

// ── Voice ─────────────────────────────────────────────────────────────────
// Em dashes are reducible debt, not style. Most prose here was agent-written,
// so their prevalence records what a model reaches for by default rather than
// a decision anyone made. Every page carrying them is reported, with the
// bracketing pairs called out separately because those are the worst of it.
const voice = [];
for (const [i, text] of texts.entries()) {
  const p = prose(text);
  const lines = p.split('\n').length;
  const dashes = (p.match(/—/g) || []).length;
  const paired = (p.match(/—[^—\n]{1,80}—/g) || []).length;
  const per100 = ((dashes / lines) * 100).toFixed(0);
  if (dashes > 0) {
    const flag = paired > 0 ? '  ← bracketing pair(s)' : per100 > 4 ? '  ← high' : '';
    voice.push(
      `${String(dashes).padStart(3)} dashes  ${String(per100).padStart(2)}/100 lines  ` +
        `${paired} paired  ${rel(allPages[i])}${flag}`,
    );
  }
}
add(
  'Em dashes (reduce: comma, colon, parens, full stop)',
  voice.sort((a, b) => parseInt(b) - parseInt(a)),
);

// Markers of default-model prose. Each is cheap to spot and cheap to fix;
// see VOICE.md for why each one reads as machine-written.
const TICS = [
  'deliberately',
  'precisely',
  'genuinely',
  'exactly the',
  'on purpose',
  'carefully',
  'thoughtfully',
  'it is worth',
  'worth noting',
  'worth knowing',
];
const BUZZ = [
  'delve',
  'tapestry',
  'paramount',
  'pivotal',
  'leverage',
  'showcase',
  'underscore',
  'seamless',
  'robust',
  'crucial',
  'vital',
  'realm',
  'landscape',
];

const formulas = [];
for (const [i, text] of texts.entries()) {
  const p = prose(text);
  const hits = [];

  if (/\bnot (just |merely |only )?\w[^.\n]{0,50}, but\b/i.test(p)) hits.push('"not X, but Y"');

  const tics = TICS.filter((w) => new RegExp(`\\b${w}`, 'i').test(p));
  if (tics.length) hits.push(`editorialising: ${tics.join(', ')}`);

  const buzz = BUZZ.filter((w) => new RegExp(`\\b${w}`, 'i').test(p));
  if (buzz.length) hits.push(`buzzwords: ${buzz.join(', ')}`);

  const trans = (p.match(/^(Moreover|Furthermore|Consequently|Additionally),/gm) || []).length;
  if (trans) hits.push(`forced transitions ×${trans}`);

  // Rule of three: "a, b, and c" / "a, b and c" in running prose.
  const threes = (p.match(/\b\w+, \w+,? and \w+\b/g) || []).length;
  if (threes >= 3) hits.push(`rule-of-three ×${threes}`);

  // Sentences past ~30 words. Real CLI docs sit at 8–18.
  const sentences = p
    .replace(/\|.*\|/g, '')
    .replace(/[#>*`[\]()]/g, ' ')
    .split(/(?<=[.!?])\s+/)
    .map((s) => s.split(/\s+/).filter(Boolean).length);
  const longSentences = sentences.filter((n) => n > 30).length;
  if (longSentences) hits.push(`sentences >30 words ×${longSentences}`);

  // A closing paragraph that recaps rather than stopping.
  const paras = p.trim().split(/\n\s*\n/);
  const last = paras[paras.length - 1] || '';
  if (
    /^(In (short|summary)|Overall|To sum|Taken together|All told|Ultimately)\b/i.test(last.trim())
  ) {
    hits.push('summarising closer');
  }

  if (hits.length) formulas.push(`${rel(allPages[i])}: ${hits.join('; ')}`);
}
add('Default-model prose (see VOICE.md)', formulas);

// ── Size ──────────────────────────────────────────────────────────────────
add(
  'Longest pages',
  allPages
    .map((p, i) => [rel(p), texts[i].split('\n').length])
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([p, n]) => `${String(n).padStart(4)}  ${p}`),
);

// ── Report ────────────────────────────────────────────────────────────────
if (JSON_OUT) {
  console.log(JSON.stringify(findings, null, 2));
} else {
  const keys = Object.keys(findings);
  if (!keys.length) {
    console.log('No findings.');
  }
  for (const key of keys) {
    console.log(`\n${key.toUpperCase()}  (${findings[key].length})`);
    for (const row of findings[key]) console.log(`  ${row}`);
  }
  console.log(
    '\nAdvisory only. Verify each finding against source before acting — ' +
      'see SKILL.md for what is a real defect and what is house style.',
  );
}
