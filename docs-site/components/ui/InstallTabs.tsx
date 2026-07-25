import { useState } from 'react';

/**
 * Install methods, one command at a time.
 *
 * The commands differ by platform and picking the wrong one is the most
 * common install mistake, so each method states what it runs on and what it
 * needs first, right under the command it would have you paste.
 *
 * A long command scrolls sideways rather than wrapping, so the `$` keeps its
 * column and the box keeps its height. The bar it scrolls with is thinned to
 * a hairline in CSS — default scrollbar furniture in a one-line well is
 * taller than the gap it has to live in.
 */
export interface InstallMethod {
  id: string;
  label: string;
  platform: string;
  requires: string;
  command: string;
}

export function InstallTabs({ methods }: { methods: readonly InstallMethod[] }) {
  const [activeId, setActiveId] = useState(methods[0]?.id);
  const method = methods.find((m) => m.id === activeId) ?? methods[0];

  return (
    <div className="panel overflow-hidden">
      <div
        role="tablist"
        aria-label="Install method"
        className="flex flex-wrap border-b border-hairline"
      >
        {methods.map((m) => (
          <button
            key={m.id}
            role="tab"
            type="button"
            aria-selected={m.id === method.id}
            data-active={m.id === method.id}
            className="install-tab"
            onClick={() => setActiveId(m.id)}
          >
            {m.label}
          </button>
        ))}
      </div>

      <div className="p-4 sm:p-5">
        <div className="flex items-center gap-3 bg-well border border-hairline rounded-lg px-3 py-2.5">
          <span className="text-text-3 font-mono text-sm shrink-0" aria-hidden="true">
            $
          </span>
          <code className="install-cmd flex-1 min-w-0 text-sm text-text">{method.command}</code>
          <CopyButton text={method.command} />
        </div>

        <dl className="flex flex-wrap gap-x-8 gap-y-3 mt-4">
          <Fact label="Platform" value={method.platform} />
          <Fact label="Requires" value={method.requires} />
        </dl>
      </div>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="t-eyebrow mb-1.5">{label}</dt>
      <dd className="t-meta text-text-2">{value}</dd>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  return (
    <button
      type="button"
      onClick={() => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1600);
      }}
      className="copy-inline shrink-0"
      data-copied={copied}
    >
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}
