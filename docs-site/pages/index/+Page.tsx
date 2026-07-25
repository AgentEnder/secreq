import { Link } from '../../components/Link';
import { StatusDot, TelemCell, SectionHeader, InstallTabs } from '../../components/ui';
import type { InstallMethod } from '../../components/ui';

export default function LandingPage() {
  return (
    <div>
      <HeroSection />
      <WhySection />
      <InstallSection />
      <Footer />
    </div>
  );
}

/* ── HERO ── */

function HeroSection() {
  return (
    <section
      className="hero-section"
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr',
        gap: '3rem',
        padding: '4rem 4rem 3.5rem',
        minHeight: 'calc(100vh - 54px - 44px)',
        alignItems: 'center',
      }}
    >
      {/* Left: text */}
      <div>
        <div className="flex gap-6 mb-8 pb-5" style={{ borderBottom: '1px solid #192838' }}>
          <TelemCell label="STATUS" value="NOMINAL" color="green" />
          <TelemCell label="LICENSE" value="MIT" />
          <TelemCell label="PLATFORM" value="macOS · Linux" color="blue" />
        </div>

        <h1
          className="animate-fade-in-up text-switch-text-bright"
          style={{
            fontFamily: "'Bebas Neue', sans-serif",
            fontSize: '4.5rem',
            letterSpacing: '0.08em',
            lineHeight: 1,
            marginBottom: '0.5rem',
          }}
        >
          sec<span style={{ color: '#d4920a' }}>req</span>
        </h1>

        <div
          className="animate-fade-in-up"
          style={{
            fontSize: '0.78rem',
            fontWeight: 600,
            letterSpacing: '0.22em',
            textTransform: 'uppercase',
            color: '#4a6878',
            marginBottom: '1.5rem',
            animationDelay: '80ms',
          }}
        >
          Per-binary CLI wraps · Provenance-aware consent · Output masking
        </div>

        <p
          className="animate-fade-in-up"
          style={{
            color: '#b0c4d4',
            fontSize: '1rem',
            lineHeight: 1.75,
            marginBottom: '1.5rem',
            maxWidth: '480px',
            animationDelay: '160ms',
          }}
        >
          <strong style={{ color: '#d8eaf5' }}>1Password Shell Plugins, but generic.</strong>{' '}
          Wrap the CLIs you use every day — <code>gh</code>, <code>aws</code>,{' '}
          <code>kubectl</code>, <code>psql</code> — so each invocation pulls its credentials
          from your secret store of choice, with a consent prompt before any release and
          masking on stdout/stderr.
        </p>

        <p
          className="animate-fade-in-up"
          style={{ color: '#7b8ba3', fontSize: '0.86rem', lineHeight: 1.7, marginBottom: '2rem', maxWidth: '480px', animationDelay: '200ms' }}
        >
          It is a <strong style={{ color: '#b0c4d4' }}>per-binary</strong> wrap tool scoped to
          your user account. On the wrap-and-run path, secreq reserves the{' '}
          <code>--sq-</code> prefix for its own options (e.g. <code>--sq-yes</code>,{' '}
          <code>--sq-raw</code>); every other argument forwards untouched to the wrapped binary.
        </p>

        <div className="animate-fade-in-up flex gap-3 items-center" style={{ animationDelay: '240ms' }}>
          <Link
            href="/docs/getting-started"
            className="no-underline"
            style={{
              background: '#d4920a',
              color: '#06090e',
              padding: '0.65rem 1.75rem',
              fontSize: '0.88rem',
              fontWeight: 700,
              letterSpacing: '0.08em',
              display: 'inline-block',
            }}
          >
            Get Started
          </Link>
          <Link
            href="/docs/overview"
            className="no-underline"
            style={{
              background: 'transparent',
              color: '#b0c4d4',
              border: '1px solid #243848',
              padding: '0.65rem 1.75rem',
              fontSize: '0.88rem',
              fontWeight: 500,
              letterSpacing: '0.06em',
              display: 'inline-block',
            }}
          >
            The mental model
          </Link>
        </div>
      </div>

      {/* Right: quick-start terminal */}
      <div className="animate-fade-in-up" style={{ animationDelay: '200ms' }}>
        <QuickStartPanel />
      </div>

      <style>{`
        @media (max-width: 900px) {
          .hero-section {
            grid-template-columns: 1fr !important;
            padding: 2.5rem 1.5rem !important;
            min-height: auto !important;
          }
        }
      `}</style>
    </section>
  );
}

const QUICK_START = [
  { c: 'secreq init', note: 'one-time setup' },
  { c: 'secreq wrap gh --env \\', note: null },
  { c: '  GITHUB_TOKEN=secret://op/Personal/GitHub/credential', note: null },
  { c: '', note: null },
  { c: 'gh repo list', note: 'shim → consent → real gh' },
];

function QuickStartPanel() {
  return (
    <div style={{ border: '1px solid #2a5070' }}>
      <div
        style={{
          background: '#101820',
          borderBottom: '1px solid #192838',
          padding: '0.45rem 1rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <span style={{ fontSize: '0.6rem', fontWeight: 700, letterSpacing: '0.2em', textTransform: 'uppercase', color: '#4a6878' }}>
          Quick start
        </span>
        <div style={{ display: 'flex', gap: '0.4rem' }}>
          <span className="status-dot red" />
          <span className="status-dot amber" />
          <span className="status-dot green" />
        </div>
      </div>
      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '12.5px', background: '#000', color: '#c0caf5', padding: '1rem', lineHeight: 1.7, overflowX: 'auto' }}>
        {QUICK_START.map((line, i) =>
          line.c === '' ? (
            <div key={i} style={{ height: '0.7em' }} />
          ) : (
            <div key={i} className="whitespace-pre">
              {line.c.startsWith('  ') ? (
                <span style={{ color: '#7b8ba3' }}>{line.c}</span>
              ) : (
                <>
                  <span style={{ color: '#4a6878' }}>$ </span>
                  <span style={{ color: '#d8eaf5' }}>{line.c}</span>
                </>
              )}
              {line.note && <span style={{ color: '#4a6878' }}>{'  # ' + line.note}</span>}
            </div>
          )
        )}
      </div>
    </div>
  );
}

/* ── WHY ── */

const WHY = [
  {
    id: '01',
    status: 'green' as const,
    title: 'Multi-provider, in one config',
    description:
      'Mix 1Password, macOS Keychain, pass, and LastPass freely. The 1Password Shell Plugin is 1Password-only; aws-vault is AWS-only; envchain is Keychain-only — secreq covers the union.',
  },
  {
    id: '02',
    status: 'amber' as const,
    title: 'Provenance-aware consent',
    description:
      'Before any provider call you see what is asking — the parent process chain — with a chance to deny. The cache is scoped to the direct parent process, so an approval for gh from your shell does not extend to an npm postinstall hook.',
  },
  {
    id: '03',
    status: 'blue' as const,
    title: 'PATH shim, not shell alias',
    description:
      'Every execvp("gh", …) goes through secreq, including subprocesses of npm, make, cargo, and IDE tooling. A shell alias would miss all of those.',
  },
  {
    id: '04',
    status: 'green' as const,
    title: 'Output masking',
    description:
      'Any value resolved through any provider is redacted on the wrapped binary’s stdout and stderr. --sq-raw opts out for pbcopy-style flows.',
  },
  {
    id: '05',
    status: 'amber' as const,
    title: 'Provenance-aware SSH agent',
    description:
      'Point SSH_AUTH_SOCK at secreq and each key signature is gated by the same consent prompt — you see who is asking before git push signs. The key is resolved from your provider, used in-process, and zeroized.',
  },
  {
    id: '06',
    status: 'blue' as const,
    title: 'secret:// for any command',
    description:
      'secreq run is op run for every store: resolve ambient secret:// refs from the environment or an --env-file, then exec your command with the values injected and masked.',
  },
];

function WhySection() {
  return (
    <section className="why-section" style={{ padding: '3rem 4rem', borderTop: '1px solid #192838' }}>
      <SectionHeader title="Why secreq" right="6 reasons" />
      <div className="stagger-children" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        {WHY.map((w) => (
          <div key={w.id} className="card-glow" style={{ background: '#0b1018', border: '1px solid #192838', padding: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.75rem' }}>
              <StatusDot color={w.status} />
              <span style={{ fontSize: '0.58rem', fontWeight: 700, letterSpacing: '0.2em', textTransform: 'uppercase', color: '#4a6878' }}>
                REASON {w.id}
              </span>
            </div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: '#d8eaf5', marginBottom: '0.5rem', letterSpacing: '0.02em' }}>
              {w.title}
            </div>
            <p style={{ fontSize: '0.86rem', color: '#b0c4d4', lineHeight: 1.7, margin: 0 }}>{w.description}</p>
          </div>
        ))}
      </div>

      <style>{`
        @media (max-width: 900px) {
          .why-section { padding: 2rem 1.5rem !important; }
          .why-section > div[style*="grid"] { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </section>
  );
}

/* ── INSTALL ── */

const INSTALL_METHODS: readonly InstallMethod[] = [
  {
    id: 'script',
    label: 'Script',
    platform: 'macOS / Linux',
    requires: 'curl',
    command: 'curl -fsSL https://secreq.dev/install.sh | sh',
  },
  {
    id: 'brew',
    label: 'Homebrew',
    platform: 'macOS / Linuxbrew',
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
    label: 'From clone',
    platform: 'macOS / Linux',
    requires: 'Rust toolchain',
    command: 'bash scripts/install.sh',
  },
];

function InstallSection() {
  return (
    <section className="install-section" style={{ padding: '3rem 4rem', borderTop: '1px solid #192838' }}>
      <SectionHeader title="Installation" right="run secreq init afterward" />
      <InstallTabs methods={INSTALL_METHODS} />
      <p style={{ color: '#4a6878', fontSize: '0.82rem', marginTop: '1.25rem' }}>
        None of these create any wraps — run{' '}
        <code style={{ color: '#ecb030' }}>secreq init</code> afterward. Full matrix and
        signature verification in the{' '}
        <Link href="/docs/install" style={{ color: '#d4920a' }}>
          install guide
        </Link>
        .
      </p>

      <style>{`
        @media (max-width: 900px) {
          .install-section { padding: 2rem 1.5rem !important; }
        }
      `}</style>
    </section>
  );
}

/* ── FOOTER ── */

function Footer() {
  return (
    <footer
      className="site-footer"
      style={{
        borderTop: '1px solid #192838',
        padding: '1.5rem 4rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '1rem',
        background: '#0b1018',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
        <span style={{ fontFamily: "'Bebas Neue', sans-serif", fontSize: '1.1rem', letterSpacing: '0.08em', color: '#d4920a' }}>
          secreq
        </span>
        <TelemCell label="License" value="MIT" />
      </div>

      <div style={{ display: 'flex', gap: '1.5rem', fontSize: '0.8rem', color: '#4a6878' }}>
        <Link href="/docs" style={{ textDecoration: 'none', color: 'inherit', letterSpacing: '0.04em' }}>
          Documentation
        </Link>
        <a
          href="https://github.com/AgentEnder/secreq"
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: 'inherit', textDecoration: 'none', letterSpacing: '0.04em' }}
        >
          GitHub
        </a>
        <a
          href="https://github.com/AgentEnder/secreq/releases"
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: 'inherit', textDecoration: 'none', letterSpacing: '0.04em' }}
        >
          Releases
        </a>
      </div>

      <style>{`
        @media (max-width: 640px) {
          .site-footer { flex-direction: column !important; padding: 1.5rem !important; text-align: center; }
        }
      `}</style>
    </footer>
  );
}
