import { useEffect, useState } from 'react';

type Os = 'macos' | 'windows' | 'gnome';

const OPTIONS: { id: Os; label: string; hint: string }[] = [
  { id: 'macos', label: 'macOS', hint: 'Sheet, right-aligned buttons' },
  { id: 'windows', label: 'Windows', hint: 'ContentDialog, affirmative first' },
  { id: 'gnome', label: 'Linux', hint: 'GNOME AdwMessageDialog' },
];

/**
 * Which desktop's screenshots to show.
 *
 * secreq's windows are natively themed, so the same request looks different
 * on each OS. The page detects the reader's own desktop (see `+Head.tsx`)
 * and this switches it — for someone on a Mac reading about the Linux box
 * they deploy to, or anyone who just wants to see the other two.
 *
 * Renders nothing until mounted: the value lives on `<html data-os>`, set
 * before paint, and a server-rendered guess would visibly correct itself.
 */
export function OsPicker() {
  const [os, setOs] = useState<Os | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    setOs((document.documentElement.dataset.os as Os) ?? 'macos');
  }, []);

  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => {
      if (!(event.target as HTMLElement).closest('.os-picker')) setOpen(false);
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', escape);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', escape);
    };
  }, [open]);

  const choose = (next: Os) => {
    document.documentElement.dataset.os = next;
    try {
      localStorage.setItem('sq-os', next);
    } catch {
      // Storage blocked — the switch still works, it just won't be remembered.
    }
    setOs(next);
    setOpen(false);
  };

  if (!os) return <span className="w-8 h-8 shrink-0" aria-hidden="true" />;

  const current = OPTIONS.find((o) => o.id === os) ?? OPTIONS[0];

  return (
    <div className="os-picker relative shrink-0">
      <button
        type="button"
        className="icon-btn"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-haspopup="menu"
        aria-label={`Screenshots are showing ${current.label}. Change platform.`}
        title={`Screenshots: ${current.label}`}
      >
        <OsGlyph os={os} />
      </button>

      {open && (
        <div role="menu" className="os-menu">
          <p className="t-eyebrow px-3 pt-2.5 pb-1.5">Show screenshots for</p>
          {OPTIONS.map((option) => (
            <button
              key={option.id}
              type="button"
              role="menuitemradio"
              aria-checked={option.id === os}
              className="os-menu-item"
              data-active={option.id === os}
              onClick={() => choose(option.id)}
            >
              <OsGlyph os={option.id} />
              <span className="min-w-0">
                <span className="block text-sm text-text">{option.label}</span>
                <span className="block text-xs text-text-3">{option.hint}</span>
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Neutral geometric marks rather than vendor logos — the docs describe the
 * window idiom each platform uses, and shipping trademarked glyphs to say
 * so would be both a licensing question and a bigger claim than intended.
 */
function OsGlyph({ os }: { os: Os }) {
  const common = {
    width: 15,
    height: 15,
    viewBox: '0 0 16 16',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.5,
    strokeLinejoin: 'round' as const,
    'aria-hidden': true,
  };

  if (os === 'windows') {
    // Four panes: the ContentDialog's equal-weight grid.
    return (
      <svg {...common}>
        <rect x="2" y="2" width="5" height="5" rx="0.5" />
        <rect x="9" y="2" width="5" height="5" rx="0.5" />
        <rect x="2" y="9" width="5" height="5" rx="0.5" />
        <rect x="9" y="9" width="5" height="5" rx="0.5" />
      </svg>
    );
  }
  if (os === 'gnome') {
    // Headerbar over a body: the Adwaita split.
    return (
      <svg {...common}>
        <rect x="2" y="3" width="12" height="10" rx="2" />
        <path d="M2 6.5h12" />
      </svg>
    );
  }
  // A sheet with its traffic-light corner.
  return (
    <svg {...common}>
      <rect x="2" y="3" width="12" height="10" rx="2.5" />
      <circle cx="4.6" cy="5.6" r="0.85" fill="currentColor" stroke="none" />
    </svg>
  );
}
