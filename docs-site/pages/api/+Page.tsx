import { useApiPackage } from 'vike-plugin-typedoc/client';
import { Link } from '../../components/Link';
import { ApiPackageLanding } from '../../components/api/ApiPackageLanding';

const GITHUB_TREE =
  'https://github.com/AgentEnder/secreq/tree/main/packages/secreq-rule';

export default function ApiIndexPage() {
  const { apiPackage, packageName } = useApiPackage();

  return (
    <div className="flex gap-10 animate-fade-in">
      <article className="flex-1 min-w-0" data-pagefind-body>
        {/* Breadcrumb */}
        <nav
          data-pagefind-ignore
          className="inline-flex items-center gap-2 text-[11px] text-switch-text-dim mb-8 px-3 py-1.5 border border-switch-border bg-switch-bg-surface uppercase tracking-wider"
          style={{ letterSpacing: '0.06em' }}
        >
          <span className="status-dot blue" />
          <Link href="/docs" className="hover:text-switch-accent transition-colors">
            Docs
          </Link>
          <svg
            className="w-3 h-3 text-switch-border-light"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
          <span className="text-switch-text font-medium">SDK API reference</span>
        </nav>

        <h1
          className="text-switch-text-bright mb-2"
          style={{
            fontFamily: "'Bebas Neue', sans-serif",
            fontSize: 'clamp(2rem, 5vw, 3rem)',
            letterSpacing: '0.08em',
          }}
        >
          {packageName} SDK
        </h1>

        <div
          className="h-px mb-8"
          style={{
            background:
              'linear-gradient(to right, #d4920a 0%, rgba(212,146,10,0.15) 40%, transparent 100%)',
          }}
        />

        <p className="text-switch-text mb-4 max-w-2xl leading-relaxed">
          The <code className="font-mono text-switch-accent-bright">{packageName}</code>{' '}
          AssemblyScript SDK is the authoring surface for a programmable{' '}
          <Link href="/docs/wasm-rules" className="text-switch-accent hover:text-switch-accent-bright">
            wasm auto-rule
          </Link>
          . A rule is a single AssemblyScript file that exports a{' '}
          <code className="font-mono text-switch-accent-bright">decide(ctx: RuleCtx): Decision</code>{' '}
          function: inspect the ask through the{' '}
          <Link href="/api/rule-ctx" className="text-switch-accent hover:text-switch-accent-bright">
            RuleCtx
          </Link>{' '}
          it is handed, then return{' '}
          <Link href="/api/approve" className="text-switch-accent hover:text-switch-accent-bright">
            approve()
          </Link>
          ,{' '}
          <Link href="/api/pass" className="text-switch-accent hover:text-switch-accent-bright">
            pass()
          </Link>
          , or{' '}
          <Link href="/api/deny" className="text-switch-accent hover:text-switch-accent-bright">
            deny(reason)
          </Link>
          .
        </p>

        <div className="mb-2 flex flex-wrap items-center gap-3 text-xs text-switch-text-dim">
          <a
            href={GITHUB_TREE}
            target="_blank"
            rel="noopener noreferrer"
            className="text-switch-accent hover:text-switch-accent-bright underline"
          >
            Source on GitHub
          </a>
          <span aria-hidden>·</span>
          <span className="font-mono">import from "secreq-rule"</span>
        </div>

        {apiPackage ? (
          <ApiPackageLanding apiPackage={apiPackage} />
        ) : (
          <p className="text-switch-text-dim mt-8">
            API data is unavailable — run the <code>typedoc</code> extract step before building.
          </p>
        )}
      </article>
    </div>
  );
}
