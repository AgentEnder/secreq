// Typecheck the TypeScript fragments embedded in the docs against the real
// `secreq-rule` typings.
//
// `docs/wasm-rules.md` and `packages/secreq-rule/README.md` teach rule
// authoring with code — `ctx.joinedArgv`, `deny(reason)`, `DecisionKind.Approve`.
// Every one of those names is a promise about the SDK's public surface, and
// prose has no compiler. Renaming a field on `RuleCtx` used to leave five
// snippets quietly describing a package that no longer existed.
//
// So the fences are compiled. Each markdown file becomes one in-memory
// TypeScript program: every `ts` fence is a virtual source file, `secreq-rule`
// resolves to `packages/secreq-rule/index.ts`, and diagnostics are mapped back
// to the line of the markdown you would actually edit. Nothing is written to
// disk — the fragments only ever exist as strings in this process.
//
// This is docs-site holding the same contract for a doc's code that it already
// holds for its prose: a link naming an unpublished page throws, a `::shot`
// naming a missing fixture throws, and now a snippet naming a field the SDK
// dropped fails too.
//
// SCOPE: this validates the fragments against the SDK's *typings*. Rules are
// AssemblyScript, a subset of TypeScript, so a snippet using a regex or a
// closure passes here and still fails for a reader running `secreq-rule-build`.
// Catching those means running `asc`, which means installing the npm island
// that `pnpm-workspace.yaml` deliberately keeps out of this workspace. The
// worked example under `packages/secreq-rule/examples/` is compiled by `asc`
// and covers that half.
//
// Run with `pnpm --filter @secreq/docs-site run typecheck-docs`.

import { readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

/**
 * Markdown files whose `ts` fences are typechecked, repo-root-relative.
 *
 * Add a file here and every `ts` fence in it is checked from that moment on —
 * opting a fence out is explicit (see {@link parseFenceMeta}), so a new snippet
 * is guarded without anyone remembering to ask for it.
 */
const CHECKED_DOCS = ['docs/wasm-rules.md', 'packages/secreq-rule/README.md'];

/** What a fragment's `import … from 'secreq-rule'` resolves to. */
const SDK_ENTRY = join(REPO_ROOT, 'packages/secreq-rule/index.ts');

/**
 * Prepended to any fragment that imports nothing.
 *
 * `docs/wasm-rules.md` states the author's contract as a bare signature —
 * `export function decide(ctx: RuleCtx): Decision;` — and an import line above
 * it would be noise in the prose. A fragment that carries its own imports gets
 * this preamble withheld, so the two never collide.
 */
const SDK_PREAMBLE =
  "import { Caller, RuleCtx, Decision, DecisionKind, approve, pass, deny, prompt } from 'secreq-rule';\n";

/** How many lines {@link SDK_PREAMBLE} adds ahead of the fragment's own code. */
const SDK_PREAMBLE_LINES = 1;

/**
 * Ambient declarations for the as-pect globals the spec fragment calls.
 *
 * The real types ship with `@as-pect/assembly`, which is installed in the
 * example's npm island rather than this workspace — pulling that island in to
 * declare three globals would trade a 5-line file for a dependency graph. The
 * fragment only ever calls `describe`, `it` and `expect(...).toBe(...)`; if it
 * grows past that, this is the thing to extend.
 *
 * Kept as a string rather than a file on disk so it cannot leak into
 * docs-site's own program, where these globals would be nonsense.
 */
const ASPECT_GLOBALS = `
declare function describe(description: string, block: () => void): void;
declare function it(description: string, block: () => void): void;
declare function expect<T>(actual: T): Expectation<T>;
interface Expectation<T> {
  toBe(expected: T, message?: string): void;
}
`;

/** Virtual filename the as-pect globals are mounted at, per document. */
const GLOBALS_FILE = 'as-pect-globals.d.ts';

/** One `ts` fence, lifted out of a markdown file. */
interface Fragment {
  /** Path inside the virtual program, e.g. `assembly/rule.ts`. */
  virtualPath: string;
  /** Fence body, verbatim. */
  code: string;
  /** 1-based markdown line of the ``` that opened the fence. */
  fenceLine: number;
  /** 1-based markdown line of the fragment's first line of code. */
  firstCodeLine: number;
  /** Lines prepended when the fragment is materialized. */
  preambleLines: number;
}

/** A diagnostic, already resolved to a location a human can open. */
interface Finding {
  location: string;
  code: number;
  message: string;
}

/**
 * Parse the words after ```` ```ts ````.
 *
 * - `path=<relative>` names the fragment's file inside the program. Needed only
 *   when another fragment imports it (the spec reaches for `../rule`) or when it
 *   must be a `.d.ts` (a signature with no body is not a valid `.ts`).
 * - `notypecheck` opts the fence out. Reported at the end of the run, because a
 *   snippet nothing checks should be a thing you can see rather than a thing you
 *   discover.
 *
 * Anything else throws. A typo'd option that silently did nothing would read
 * exactly like a fence that was being checked.
 */
function parseFenceMeta(
  meta: string,
  docPath: string,
  fenceLine: number,
): { virtualPath: string | null; checked: boolean } {
  let virtualPath: string | null = null;
  let checked = true;

  for (const token of meta.split(/\s+/).filter(Boolean)) {
    if (token === 'notypecheck') {
      checked = false;
      continue;
    }
    const named = /^path=(.+)$/.exec(token);
    if (!named) {
      throw new Error(
        `${docPath}:${fenceLine}: unknown code-fence option "${token}" — ` +
          `expected path=<file.ts> or notypecheck`,
      );
    }
    virtualPath = named[1];
    if (virtualPath.startsWith('/') || virtualPath.split('/').includes('..')) {
      throw new Error(
        `${docPath}:${fenceLine}: path=${virtualPath} must be a relative path ` +
          `inside the fragment program, with no ".." segments`,
      );
    }
    if (!virtualPath.endsWith('.ts')) {
      throw new Error(`${docPath}:${fenceLine}: path=${virtualPath} must end in .ts or .d.ts`);
    }
  }

  return { virtualPath, checked };
}

/**
 * Pull every `ts` fence out of a markdown document.
 *
 * Fence tracking is stateful rather than a single regex sweep so that a ```` ```sh ````
 * or bare ```` ``` ```` block containing what looks like a fence opener cannot be
 * mistaken for one.
 */
function extractFragments(
  markdown: string,
  docPath: string,
): { fragments: Fragment[]; skipped: number[] } {
  const lines = markdown.split('\n');
  const fragments: Fragment[] = [];
  const skipped: number[] = [];
  let open: { lang: string; meta: string; line: number; body: string[] } | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (open === null) {
      const opener = /^```(\S*)[ \t]*(.*?)\s*$/.exec(line);
      if (opener) open = { lang: opener[1], meta: opener[2], line: i + 1, body: [] };
      continue;
    }

    if (/^```\s*$/.test(line)) {
      if (open.lang === 'ts') {
        const { virtualPath, checked } = parseFenceMeta(open.meta, docPath, open.line);
        if (checked) {
          const code = open.body.join('\n');
          fragments.push({
            // A fence with no `path=` still needs a name. Keying it to the line
            // it came from means the name is self-explanatory if it ever
            // surfaces in a message this script failed to remap.
            virtualPath: virtualPath ?? `fragment-L${open.line}.ts`,
            code,
            fenceLine: open.line,
            firstCodeLine: open.line + 1,
            preambleLines: /^\s*import\s/m.test(code) ? 0 : SDK_PREAMBLE_LINES,
          });
        } else {
          skipped.push(open.line);
        }
      }
      open = null;
      continue;
    }

    open.body.push(line);
  }

  if (open !== null) {
    throw new Error(`${docPath}: unterminated code fence opened at line ${open.line}`);
  }
  return { fragments, skipped };
}

/** The fragment's source as the compiler sees it, preamble included. */
function materialize(fragment: Fragment): string {
  return fragment.preambleLines > 0 ? SDK_PREAMBLE + fragment.code : fragment.code;
}

/**
 * A compiler host that serves the fragments from memory and everything else —
 * the lib files, the SDK sources under `packages/secreq-rule/` — from disk.
 *
 * `directoryExists` has to be answered from the virtual map too, not just
 * `fileExists`: module resolution prunes a candidate directory before it ever
 * asks about a file in it, so a spec fragment reaching for `../rule` fails to
 * resolve while `assembly/rule.ts` sits right there in memory.
 */
function createHost(
  options: ts.CompilerOptions,
  files: Map<string, string>,
  root: string,
): ts.CompilerHost {
  const disk = ts.createCompilerHost(options, true);
  const virtualDirs = new Set<string>();
  for (const fileName of files.keys()) {
    for (let dir = dirname(fileName); dir.startsWith(root); dir = dirname(dir)) {
      virtualDirs.add(dir);
    }
  }

  return {
    ...disk,
    getCurrentDirectory: () => root,
    fileExists: (fileName) => files.has(fileName) || disk.fileExists(fileName),
    readFile: (fileName) => files.get(fileName) ?? disk.readFile(fileName),
    directoryExists: (directoryName) =>
      virtualDirs.has(directoryName) || (disk.directoryExists?.(directoryName) ?? false),
    realpath: (fileName) =>
      files.has(fileName) ? fileName : (disk.realpath?.(fileName) ?? fileName),
    getSourceFile: (fileName, languageVersion, onError, shouldCreate) => {
      const virtual = files.get(fileName);
      if (virtual === undefined) {
        return disk.getSourceFile(fileName, languageVersion, onError, shouldCreate);
      }
      return ts.createSourceFile(fileName, virtual, languageVersion, true);
    },
    writeFile: () => {},
  };
}

/**
 * Compile one document's fragments and return everything wrong with them.
 *
 * All of a document's fragments share a program, which is what lets the spec
 * fragment import the rule fragment the way a reader's package would. Documents
 * do not share one with each other: two guides are free to both describe an
 * `assembly/rule.ts`.
 */
function checkDoc(docPath: string): { findings: Finding[]; fragments: number; skipped: number[] } {
  const markdown = readFileSync(join(REPO_ROOT, docPath), 'utf8');
  const { fragments, skipped } = extractFragments(markdown, docPath);
  if (fragments.length === 0) return { findings: [], fragments: 0, skipped };

  // A directory that does not exist on disk: the fragments are pure strings,
  // and `secreq-rule` resolves through an absolute `paths` entry rather than by
  // walking up out of here.
  const root = join(REPO_ROOT, '.doc-fragments', docPath.replace(/[/\\]/g, '__'));

  const files = new Map<string, string>([[join(root, GLOBALS_FILE), ASPECT_GLOBALS]]);
  const byPath = new Map<string, Fragment>();
  for (const fragment of fragments) {
    const absolute = join(root, fragment.virtualPath);
    if (files.has(absolute)) {
      throw new Error(
        `${docPath}:${fragment.fenceLine}: two fences both claim path=${fragment.virtualPath}`,
      );
    }
    files.set(absolute, materialize(fragment));
    byPath.set(absolute, fragment);
  }

  const options: ts.CompilerOptions = {
    strict: true,
    target: ts.ScriptTarget.ESNext,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    lib: ['lib.esnext.d.ts'],
    types: [],
    noEmit: true,
    // NOT skipLibCheck. A signature-only fragment has to be materialized as a
    // `.d.ts` (a function without a body is not valid `.ts`), and skipLibCheck
    // suppresses errors in every declaration file — so the one fragment that is
    // purely a statement about the SDK's surface would be the one fragment
    // nothing checked. The program is small enough that checking the libs costs
    // nothing worth having.
    skipLibCheck: false,
    baseUrl: root,
    paths: {
      'secreq-rule': [SDK_ENTRY],
      'secreq-rule/testing/assembly': [
        join(REPO_ROOT, 'packages', 'secreq-rule', 'testing', 'assembly.ts'),
      ],
    },
  };

  const program = ts.createProgram([...files.keys()], options, createHost(options, files, root));

  const findings: Finding[] = [];
  for (const diagnostic of ts.getPreEmitDiagnostics(program)) {
    const message = ts.flattenDiagnosticMessageText(diagnostic.messageText, ' ');
    if (!diagnostic.file || diagnostic.start === undefined) {
      findings.push({ location: docPath, code: diagnostic.code, message });
      continue;
    }

    const { line, character } = diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start);
    const fragment = byPath.get(diagnostic.file.fileName);
    if (!fragment) {
      // A real file on disk — the SDK's own sources, reached through the
      // fragments' import. Worth surfacing as itself rather than pretending it
      // came from the markdown.
      const real = relative(REPO_ROOT, diagnostic.file.fileName);
      findings.push({
        location: `${real}:${line + 1}:${character + 1}`,
        code: diagnostic.code,
        message,
      });
      continue;
    }

    // Anything inside the injected preamble has no line in the markdown; the
    // fence opener is the closest honest place to point.
    const markdownLine =
      line < fragment.preambleLines
        ? fragment.fenceLine
        : fragment.firstCodeLine + (line - fragment.preambleLines);
    findings.push({
      location: `${docPath}:${markdownLine}:${character + 1}`,
      code: diagnostic.code,
      message,
    });
  }

  return { findings, fragments: fragments.length, skipped };
}

function main(): void {
  const findings: Finding[] = [];
  let checked = 0;

  for (const docPath of CHECKED_DOCS) {
    let result: ReturnType<typeof checkDoc>;
    try {
      result = checkDoc(docPath);
    } catch (err) {
      // A malformed fence — an unknown option, a `path=` that escapes the
      // program, two fences claiming one path. That is a mistake in the
      // markdown, not a crash in this script, and it should read like one.
      console.error(`error: ${(err as Error).message}`);
      process.exit(1);
    }
    checked += result.fragments;
    findings.push(...result.findings);
    for (const line of result.skipped) {
      console.log(`  note: ${docPath}:${line} opted out with \`notypecheck\``);
    }
  }

  // Every document compiles the SDK for itself, so one broken export in
  // `packages/secreq-rule` is reported once per document. That is the same
  // defect at the same line, and repeating it just buries the fragment errors
  // underneath it.
  const seen = new Set<string>();
  const unique = findings.filter((finding) => {
    const key = `${finding.location} ${finding.code} ${finding.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  if (unique.length > 0) {
    for (const finding of unique) {
      console.error(`${finding.location}  error TS${finding.code}: ${finding.message}`);
    }
    console.error(
      `\n${unique.length} error(s) in the TypeScript fragments. These snippets are ` +
        `compiled against packages/secreq-rule — either the docs or the SDK is wrong.`,
    );
    process.exit(1);
  }

  console.log(
    `typecheck-docs: ${checked} TypeScript fragment(s) across ` +
      `${CHECKED_DOCS.length} file(s) check out against secreq-rule.`,
  );
}

main();
