import { useEffect } from 'react';
import { useApiExport } from 'vike-plugin-typedoc/client';
import { Link } from '../../../components/Link';
import { ApiExportPage } from '../../../components/api/ApiExportPage';

export default function SymbolDetailPage() {
  const { apiExport: exp } = useApiExport();

  // Signatures and examples get the same copy button the prose pages give
  // their code blocks.
  useEffect(() => {
    document.querySelectorAll<HTMLPreElement>('.prose-content pre').forEach((pre) => {
      if (pre.querySelector('.copy-btn')) return;

      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'copy-btn';
      button.textContent = 'Copy';
      button.addEventListener('click', async () => {
        await navigator.clipboard.writeText((pre.querySelector('code') ?? pre).innerText);
        button.textContent = 'Copied';
        button.dataset.copied = 'true';
        setTimeout(() => {
          button.textContent = 'Copy';
          delete button.dataset.copied;
        }, 1600);
      });
      pre.appendChild(button);
    });
  }, [exp?.slug]);

  if (!exp) {
    return (
      <div className="py-24 text-center">
        <h1 className="t-title mb-3">No such symbol</h1>
        <p className="text-sm text-text-3 mb-6">
          That API symbol does not exist. It may have been renamed or removed.
        </p>
        <Link href="/api" className="btn btn-quiet no-underline">
          Browse the API reference
        </Link>
      </div>
    );
  }

  return <ApiExportPage apiExport={exp} />;
}
