import { useEffect, useState } from 'react';

type Theme = 'light' | 'dark';

/**
 * Follow the OS, until the reader says otherwise.
 *
 * The initial value is written to `<html data-theme>` by the inline script in
 * `+Head.tsx`, before paint. This component only reads that back and lets the
 * reader override it — which is also why it renders nothing until mounted:
 * a server-rendered icon would be a coin flip against the reader's actual OS
 * setting, and would visibly correct itself on hydration.
 */
export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme | null>(null);

  useEffect(() => {
    setTheme((document.documentElement.dataset.theme as Theme) ?? 'dark');
  }, []);

  const toggle = () => {
    const next: Theme = theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem('sq-theme', next);
    } catch {
      // A reader with storage blocked still gets the switch, just not the memory of it.
    }
    setTheme(next);
  };

  if (!theme) return <span className="w-8 h-8 shrink-0" aria-hidden="true" />;

  return (
    <button
      type="button"
      onClick={toggle}
      className="icon-btn shrink-0"
      aria-label={theme === 'light' ? 'Use the dark theme' : 'Use the light theme'}
    >
      {theme === 'light' ? (
        <svg
          width="15"
          height="15"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.9"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
        </svg>
      ) : (
        <svg
          width="15"
          height="15"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.9"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
        </svg>
      )}
    </button>
  );
}
