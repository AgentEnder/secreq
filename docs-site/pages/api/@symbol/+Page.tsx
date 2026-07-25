import { useEffect } from 'react';
import { useApiExport } from 'vike-plugin-typedoc/client';
import { Link } from '../../../components/Link';
import { ApiExportPage } from '../../../components/api/ApiExportPage';

export default function SymbolDetailPage() {
  const { apiExport: exp } = useApiExport();

  // Attach copy buttons to every rendered signature/example <pre>, matching
  // the behavior of the prose doc pages.
  useEffect(() => {
    document.querySelectorAll<HTMLPreElement>('.prose-content pre').forEach((pre) => {
      if (pre.querySelector('.copy-btn')) return;
      const btn = document.createElement('button');
      btn.className = 'copy-btn';
      btn.textContent = 'Copy';
      btn.addEventListener('click', async () => {
        const code = pre.querySelector('code');
        const text = (code ?? pre).innerText;
        await navigator.clipboard.writeText(text);
        btn.textContent = 'Copied!';
        setTimeout(() => {
          btn.textContent = 'Copy';
        }, 1500);
      });
      pre.appendChild(btn);
    });
  }, [exp?.slug]);

  if (!exp) {
    return (
      <div className="text-center py-24 animate-fade-in">
        <h1
          className="text-switch-text-bright mb-2"
          style={{
            fontFamily: "'Bebas Neue', sans-serif",
            fontSize: '2rem',
            letterSpacing: '0.08em',
          }}
        >
          Symbol Not Found
        </h1>
        <p className="text-switch-text-dim mb-6 text-sm">
          The requested API symbol could not be found.
        </p>
        <Link
          href="/api"
          className="inline-flex items-center gap-2 text-switch-accent hover:text-switch-accent-bright transition-colors text-sm uppercase tracking-wider"
          style={{ letterSpacing: '0.06em' }}
        >
          Back to API reference
        </Link>
      </div>
    );
  }

  return (
    <div className="flex gap-10 animate-fade-in">
      <article className="flex-1 min-w-0" data-pagefind-body>
        <ApiExportPage apiExport={exp} />
      </article>
    </div>
  );
}
