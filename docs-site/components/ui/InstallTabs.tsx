import { useState } from 'react';
import { StatusDot } from './StatusDot';
import { TelemCell } from './TelemCell';

/**
 * InstallTabs — Tabbed install method display.
 * Active tab merges visually into the code block below (raised-border trick).
 *
 * Usage:
 *   <InstallTabs methods={INSTALL_METHODS} />
 */
export interface InstallMethod {
  id: string;
  label: string;
  platform: string;
  requires: string;
  command: string;
}

export function InstallTabs({ methods }: { methods: readonly InstallMethod[] }) {
  const [activeIndex, setActiveIndex] = useState(0);
  const method = methods[activeIndex];

  return (
    <div>
      {/* Tab row */}
      <div style={{ display: 'flex', borderBottom: '1px solid #192838' }}>
        {methods.map((m, i) => (
          <button
            key={m.id}
            className="install-tab"
            data-active={i === activeIndex}
            onClick={() => setActiveIndex(i)}
          >
            {m.label}
          </button>
        ))}
      </div>

      {/* Code block — border-top removed to merge with active tab */}
      <div
        style={{
          background: '#020810',
          border: '1px solid #192838',
          borderTop: 'none',
          overflow: 'hidden',
        }}
      >
        {/* Code block header */}
        <div
          style={{
            background: '#101820',
            borderBottom: '1px solid #192838',
            padding: '0.35rem 1rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <span
            style={{
              fontFamily: "'Space Grotesk', sans-serif",
              fontSize: '0.6rem',
              fontWeight: 700,
              letterSpacing: '0.18em',
              textTransform: 'uppercase',
              color: '#4a6878',
            }}
          >
            Shell
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <StatusDot color="green" />
            <span
              style={{
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: '0.6rem',
                color: '#4a6878',
                letterSpacing: '0.1em',
              }}
            >
              VERIFIED
            </span>
          </div>
        </div>

        {/* Command */}
        <pre
          style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '0.82rem',
            color: '#d4920a',
            lineHeight: 1.6,
            margin: 0,
            padding: '1rem 1.25rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <span style={{ color: '#4a6878' }}>$</span>
          <span style={{ flex: 1 }}>{method.command}</span>
          <CopyButton text={method.command} />
        </pre>
      </div>

      {/* Meta row */}
      <div style={{ display: 'flex', gap: '2rem', marginTop: '0.85rem' }}>
        <TelemCell label="Platform" value={method.platform} color="dim" />
        <TelemCell label="Requires" value={method.requires} color="dim" />
        <TelemCell label="Latest" value="v0.3.0" />
      </div>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      aria-label="Copy to clipboard"
      style={{
        padding: '1px 8px',
        background: '#101820',
        border: '1px solid #192838',
        color: copied ? '#28b060' : '#4a6878',
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: '0.72rem',
        cursor: 'pointer',
        transition: 'color 0.12s',
        flexShrink: 0,
      }}
    >
      {copied ? 'copied' : 'copy'}
    </button>
  );
}
