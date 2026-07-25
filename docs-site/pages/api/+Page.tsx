import { useApiPackage } from 'vike-plugin-typedoc/client';
import { Breadcrumb } from '../../components/Breadcrumb';
import { Link } from '../../components/Link';
import { ApiPackageLanding } from '../../components/api/ApiPackageLanding';

const GITHUB_TREE = 'https://github.com/AgentEnder/secreq/tree/main/packages/secreq-rule';

export default function ApiIndexPage() {
  const { apiPackage, packageName } = useApiPackage();

  return (
    <article className="min-w-0" data-pagefind-body style={{ viewTransitionName: 'doc-article' }}>
      <Breadcrumb
        className="mb-7"
        trail={[{ label: 'Docs', href: '/docs' }, { label: 'SDK API reference' }]}
      />

      <h1 className="t-title mb-5">{packageName}</h1>

      <p className="t-lede max-w-[62ch] mb-4">
        The AssemblyScript SDK for writing a{' '}
        <Link href="/docs/wasm-rules" className="text-accent">
          programmable rule
        </Link>{' '}
        — for the decisions that pattern matching cannot express. A rule is one file exporting{' '}
        <code>decide(ctx: RuleCtx): Decision</code>: read the request through the{' '}
        <Link href="/api/rule-ctx" className="text-accent">
          RuleCtx
        </Link>{' '}
        you are handed, then return{' '}
        <Link href="/api/approve" className="text-accent">
          approve()
        </Link>
        ,{' '}
        <Link href="/api/pass" className="text-accent">
          pass()
        </Link>{' '}
        to leave it to the human, or{' '}
        <Link href="/api/deny" className="text-accent">
          deny(reason)
        </Link>
        .
      </p>

      <p className="flex flex-wrap items-center gap-3 t-meta">
        <span>import from &quot;{packageName}&quot;</span>
        <span aria-hidden="true">·</span>
        <a href={GITHUB_TREE} target="_blank" rel="noopener noreferrer" className="text-accent">
          Source on GitHub
        </a>
      </p>

      {apiPackage ? (
        <ApiPackageLanding apiPackage={apiPackage} />
      ) : (
        <p className="text-text-3 mt-8">
          The API reference has not been generated. Run the <code>typedoc</code> extract step
          before building.
        </p>
      )}
    </article>
  );
}
