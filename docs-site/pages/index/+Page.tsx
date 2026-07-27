import { Link } from '../../components/Link';
import { InstallTabs, Interception, SectionHeader, Term, Window } from '../../components/ui';
import type { InstallMethod } from '../../components/ui';

export default function LandingPage() {
  return (
    <>
      <Hero />
      <Path />
      <Capabilities />
      <Setup />
      <Install />
      <Footer />
    </>
  );
}

/* ── Hero ───────────────────────────────────────────────────────────── */

function Hero() {
  return (
    <section className="mx-auto max-w-[1180px] px-5 sm:px-8 pt-14 pb-16 lg:pt-20 lg:pb-24">
      <div className="grid gap-12 lg:grid-cols-[minmax(0,1fr)_minmax(0,460px)] lg:gap-16 items-start">
        <div className="sq-rise">
          <p className="t-eyebrow mb-5">Consent for command-line credentials</p>

          <h1 className="t-display mb-6">
            Nothing leaves
            <br />
            without asking.
          </h1>

          <p className="t-lede max-w-[46ch] mb-5">
            secreq wraps the CLIs you use every day — <code>gh</code>, <code>aws</code>,{' '}
            <code>kubectl</code>, <code>psql</code> — so each invocation pulls its credentials from
            your own secret store. Every release is gated by a prompt that names the process asking,
            and every value is masked on the way back out.
          </p>

          <p className="text-sm leading-relaxed text-text-3 max-w-[46ch] mb-8">
            It is a PATH shim, not a shell alias, so it catches the requests you did not type: an{' '}
            <code>npm</code> postinstall, a Makefile, an agent running in your editor.
          </p>

          <div className="flex flex-wrap gap-3">
            <Link href="/docs/getting-started" className="btn btn-primary no-underline">
              Get started
            </Link>
            <Link href="/docs/overview" className="btn btn-quiet no-underline">
              How it works
            </Link>
          </div>
        </div>

        <div className="sq-rise" style={{ animationDelay: '120ms' }}>
          <Interception />
        </div>
      </div>
    </section>
  );
}

/* ── The path a request takes ───────────────────────────────────────── */

/**
 * These are numbered because they genuinely are a sequence: every request
 * passes through all three, in this order. Nothing else on the page is.
 */
const STEPS = [
  {
    n: '01',
    title: 'The shim catches the call',
    body: 'secreq installs itself ahead of the real binary on your PATH. Every execvp("gh", …) lands here first — including the ones inside npm, make, cargo and your editor, which a shell alias would never see.',
  },
  {
    n: '02',
    title: 'You see who is asking',
    body: 'The prompt walks the process tree and shows it to you: the shell, the script it launched, the binary at the end of the chain. Approval is scoped to that direct parent, so answering yes for your shell does not answer yes for a postinstall hook.',
  },
  {
    n: '03',
    title: 'The value goes out masked',
    body: 'The secret is fetched from your provider, handed to the binary, and redacted from its stdout and stderr. It never lands in your shell history or your scrollback.',
  },
];

function Path() {
  return (
    <section>
      <div className="mx-auto max-w-[1180px] px-5 sm:px-8 py-14 lg:py-20">
        <SectionHeader title="The path a request takes" note="every time" />

        <ol className="grid gap-px bg-hairline border border-hairline rounded-lg overflow-hidden md:grid-cols-3">
          {STEPS.map((step) => (
            <li key={step.n} className="reveal bg-panel p-6 lg:p-7">
              <span className="t-eyebrow block mb-4 text-accent">{step.n}</span>
              <h3 className="t-heading mb-3">{step.title}</h3>
              <p className="text-sm leading-relaxed text-text-2">{step.body}</p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}

/* ── Capabilities, each shown as the screen it actually is ──────────── */

/**
 * These are `<Window />` rather than `<Shot />`: the windows are rebuilt
 * from the captured geometry instead of shown as pictures of themselves.
 *
 * The section's whole claim is that you can see what the product puts in
 * front of you, and at half a column each the interesting part of these
 * screens is small type — a process chain, a rule's match clause, a row of
 * the audit log. Rebuilt, that type is text: it stays sharp, it selects,
 * Pagefind can index it and a screen reader can read it. It also weighs a
 * fraction of the renders it replaces, which matters most on the one page
 * that carries six of them.
 *
 * Three of these fixtures paint a `mesh` or `path` shape that the capture
 * does not pin, so they rebuild with a small icon missing — see
 * `secreq-window-element.ts`. Any one of them can go back to `<Shot />`
 * on its own if that ever reads as a defect rather than as nothing.
 */

interface Capability {
  eyebrow: string;
  title: string;
  body: string;
  shot: string;
  href: string;
  linkText: string;
}

const CAPABILITIES: Capability[] = [
  {
    eyebrow: 'Provenance',
    title: 'The prompt names the caller, not just the command',
    body: 'A credential request tells you nothing on its own — "something wants your GitHub token" is not a question you can answer. secreq reconstructs the process chain that led to the request and puts it in front of you, so the answer is obvious.',
    shot: '03-nested-tree',
    href: '/docs/consent-window',
    linkText: 'The consent window',
  },
  {
    eyebrow: 'Rules',
    title: 'Answer once, not fifty times',
    body: 'Approving the same request all afternoon is how consent prompts become noise you click through. Save a rule and secreq answers for you — matched on the wrap, the arguments and the ancestor process, so it stays narrow.',
    shot: '09-rules-tab-list',
    href: '/docs/consent-window',
    linkText: 'Rules and suggestions',
  },
  {
    eyebrow: 'Audit',
    title: 'A record of every decision',
    body: 'What asked, what it wanted, where from, and how it went — your answers, rule auto-fires, and the requests that were abandoned before you got to them. Searchable across every field at once.',
    shot: '07-audit-tab',
    href: '/docs/consent-window',
    linkText: 'Reading the audit log',
  },
  {
    eyebrow: 'SSH',
    title: 'The same gate in front of your keys',
    body: 'Point SSH_AUTH_SOCK at secreq and it becomes your agent. Each signature shows the key fingerprint and the reason before it happens; the private key is resolved from your provider, used in memory, and zeroized.',
    shot: '24-ssh-sign-pending',
    href: '/docs/ssh-agent',
    linkText: 'The SSH agent',
  },
  {
    eyebrow: 'Sandboxes',
    title: 'Serve secrets to a VM without trusting it',
    body: 'A guest has no host process tree, so there is no caller chain to verify — the scope you declared when you opened the socket is the principal instead. If a guest volunteers a chain, it is shown as a claim and marked unverifiable.',
    shot: '34-agent-scope-pending',
    href: '/docs/secret-agent',
    linkText: 'The secret agent',
  },
  {
    eyebrow: 'Ad hoc',
    title: 'secret:// for any command',
    body: 'secreq run is op run for every store: resolve ambient secret:// references from the environment or an --env-file, then exec your command with the values injected and masked. No wrap required.',
    shot: '28-prompt-many-secrets',
    href: '/docs/cli',
    linkText: 'CLI reference',
  },
];

function Capabilities() {
  return (
    <section>
      <div className="mx-auto max-w-[1180px] px-5 sm:px-8 py-14 lg:py-20">
        <SectionHeader title="What you get" note="click any screen to enlarge" />

        <div className="grid gap-14 lg:gap-20">
          {CAPABILITIES.map((cap, i) => (
            <article
              key={cap.shot}
              className="reveal grid gap-7 lg:grid-cols-2 lg:gap-14 items-center"
            >
              <div className={i % 2 === 1 ? 'lg:order-2' : undefined}>
                <p className="t-eyebrow mb-4">{cap.eyebrow}</p>
                <h3 className="t-title mb-4 max-w-[20ch]">{cap.title}</h3>
                <p className="t-lede max-w-[50ch] mb-5">{cap.body}</p>
                <Link href={cap.href} className="text-sm font-semibold text-accent no-underline">
                  {cap.linkText} →
                </Link>
              </div>

              <div className={i % 2 === 1 ? 'lg:order-1' : undefined}>
                <Window id={cap.shot} />
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ── Setting one up ─────────────────────────────────────────────────── */

/**
 * The other half of the product, and the half a screenshot cannot show.
 *
 * Everything above this is the moment a request gets caught; this is the
 * two minutes before it, and the reason those two minutes are worth
 * showing is that the flow checks its own work as you go. The recording is
 * the real thing — `tests/cli_transcripts.rs` drives the real binary on a
 * pty, so what plays here is what runs on your machine.
 */
function Setup() {
  return (
    <section>
      <div className="mx-auto max-w-[1180px] px-5 sm:px-8 py-14 lg:py-20">
        <SectionHeader title="Setting one up" note="recorded from the real CLI" />

        <div className="grid gap-8 lg:grid-cols-[minmax(0,380px)_minmax(0,1fr)] lg:gap-14 items-start">
          <div>
            <p className="t-eyebrow mb-4">Two minutes</p>
            <h3 className="t-title mb-4 max-w-[18ch]">Answer four questions, get a wrap</h3>
            <p className="t-lede mb-5">
              <code>secreq wrap gh</code> asks what the wrap should do, which provider holds the
              secret, and where. It resolves the locator against your store before writing anything,
              so a mistyped path fails while you are still looking at it — not the first time you
              run <code>gh</code> next week.
            </p>
            <Link
              href="/docs/getting-started"
              className="text-sm font-semibold text-accent no-underline"
            >
              Getting started →
            </Link>
          </div>

          <Term id="wrap-gh" />
        </div>
      </div>
    </section>
  );
}

/* ── Install ────────────────────────────────────────────────────────── */

const INSTALL_METHODS: readonly InstallMethod[] = [
  {
    id: 'script',
    label: 'Script',
    platform: 'macOS, Linux',
    requires: 'curl',
    command: 'curl -fsSL https://secreq.dev/install.sh | sh',
  },
  {
    id: 'brew',
    label: 'Homebrew',
    platform: 'macOS, Linuxbrew',
    requires: 'Homebrew',
    command: 'brew install AgentEnder/secreq/secreq',
  },
  {
    id: 'cargo',
    label: 'Cargo',
    platform: 'Any target',
    requires: 'Rust toolchain',
    command: 'cargo install secreq',
  },
  {
    id: 'clone',
    label: 'From Source',
    platform: 'macOS, Linux',
    requires: 'Rust toolchain',
    command: 'gh repo clone agentender/secreq && cd secreq && bash scripts/install.sh',
  },
  {
    id: 'windows',
    label: 'Windows',
    platform: 'windows',
    requires: '',
    command: 'Coming Soon',
  },
];

function Install() {
  return (
    <section>
      <div className="mx-auto max-w-[1180px] px-5 sm:px-8 py-14 lg:py-20">
        <SectionHeader title="Install" />

        <div className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,340px)] lg:gap-14 items-start">
          <InstallTabs methods={INSTALL_METHODS} />

          <div>
            <h3 className="t-heading mb-3">Then run secreq init</h3>
            <p className="text-sm leading-relaxed text-text-2 mb-4">
              Installing creates no wraps — nothing on your PATH changes until you ask for it.{' '}
              <code>secreq init</code> sets up the shim directory and walks you through your first
              wrap.
            </p>
            <p className="text-sm leading-relaxed text-text-3">
              The full platform matrix and signature verification are in the{' '}
              <Link href="/docs/install" className="text-accent">
                install guide
              </Link>
              .
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ── Footer ─────────────────────────────────────────────────────────── */

function Footer() {
  return (
    <footer className="border-t border-hairline">
      <div className="mx-auto max-w-[1180px] px-5 sm:px-8 py-8 flex flex-wrap items-center gap-x-8 gap-y-4">
        <span className="t-eyebrow">secreq · MIT</span>
        <nav className="flex flex-wrap gap-x-6 gap-y-2 ml-auto text-sm">
          <Link href="/docs" className="text-text-3 no-underline hover:text-text">
            Documentation
          </Link>
          <a
            href="https://github.com/AgentEnder/secreq"
            target="_blank"
            rel="noopener noreferrer"
            className="text-text-3 no-underline hover:text-text"
          >
            GitHub
          </a>
          <a
            href="https://github.com/AgentEnder/secreq/releases"
            target="_blank"
            rel="noopener noreferrer"
            className="text-text-3 no-underline hover:text-text"
          >
            Releases
          </a>
        </nav>
      </div>
    </footer>
  );
}
