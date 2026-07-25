import { useCallback, useEffect, useRef, useState } from 'react';
import { applyBaseUrl } from '../utils/base-url';

interface SearchResult {
  id: string;
  url: string;
  title: string;
  excerpt: string;
}

interface PagefindSearchResponse {
  results: Array<{
    id: string;
    data: () => Promise<{
      url: string;
      meta: { title?: string };
      excerpt: string;
    }>;
  }>;
}

interface PagefindModule {
  search: (query: string) => Promise<PagefindSearchResponse>;
  debouncedSearch: (
    query: string,
    options?: { debounceTimeoutMs?: number }
  ) => Promise<PagefindSearchResponse>;
}

declare global {
  interface Window {
    pagefind?: PagefindModule;
  }
}

export function PagefindSearch() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [pagefindReady, setPagefindReady] = useState(false);
  const [pagefindError, setPagefindError] = useState(false);

  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const url = applyBaseUrl('/pagefind/pagefind.js');
        const pf = await import(/* @vite-ignore */ url);
        window.pagefind = pf as PagefindModule;
        setPagefindReady(true);
      } catch {
        console.debug('Pagefind not available — run build first');
        setPagefindError(true);
      }
    };
    load();
  }, []);

  const handleSearch = useCallback(
    async (q: string) => {
      setQuery(q);
      setSelectedIndex(0);
      if (!q.trim()) {
        setResults([]);
        setIsOpen(false);
        return;
      }
      if (!pagefindReady || !window.pagefind) {
        setIsOpen(true);
        return;
      }
      setIsLoading(true);
      setIsOpen(true);
      try {
        const response = await window.pagefind.debouncedSearch(q, { debounceTimeoutMs: 150 });
        if (!response?.results) { setResults([]); return; }
        const loaded = await Promise.all(
          response.results.slice(0, 8).map(async (r) => {
            const data = await r.data();
            return { id: r.id, url: data.url, title: data.meta?.title ?? 'Untitled', excerpt: data.excerpt };
          })
        );
        setResults(loaded);
      } catch {
        setResults([]);
      } finally {
        setIsLoading(false);
      }
    },
    [pagefindReady]
  );

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
        setIsOpen(true);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, []);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelectedIndex((p) => Math.min(p + 1, results.length - 1));
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelectedIndex((p) => Math.max(p - 1, 0));
        break;
      case 'Enter':
        e.preventDefault();
        if (results[selectedIndex]) {
          window.location.href = results[selectedIndex].url;
          setIsOpen(false);
        }
        break;
      case 'Escape':
        e.preventDefault();
        setIsOpen(false);
        inputRef.current?.blur();
        break;
    }
  };

  useEffect(() => {
    if (resultsRef.current && results.length > 0) {
      const el = resultsRef.current.children[selectedIndex] as HTMLElement;
      el?.scrollIntoView({ block: 'nearest' });
    }
  }, [selectedIndex, results.length]);

  return (
    <div ref={containerRef} className="relative">
      {/* Input */}
      <div className="relative">
        <svg
          className="absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none"
          style={{ width: '0.75rem', height: '0.75rem', color: '#4a6878' }}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <input
          ref={inputRef}
          type="text"
          value={query}
          onChange={(e) => handleSearch(e.target.value)}
          onFocus={() => query && setIsOpen(true)}
          onKeyDown={handleKeyDown}
          placeholder="Search docs..."
          style={{
            width: '11rem',
            paddingLeft: '2rem',
            paddingRight: '3rem',
            paddingTop: '0.3rem',
            paddingBottom: '0.3rem',
            fontSize: '0.75rem',
            fontFamily: "'Space Grotesk', sans-serif",
            background: '#0b1018',
            border: '1px solid #192838',
            color: '#b0c4d4',
            outline: 'none',
            transition: 'border-color 0.15s',
          }}
          onFocusCapture={(e) => { (e.target as HTMLElement).style.borderColor = '#2a5070'; }}
          onBlurCapture={(e) => { (e.target as HTMLElement).style.borderColor = '#192838'; }}
        />
        <kbd
          style={{
            position: 'absolute',
            right: '0.5rem',
            top: '50%',
            transform: 'translateY(-50%)',
            fontSize: '0.55rem',
            fontFamily: "'JetBrains Mono', monospace",
            color: '#4a6878',
            background: '#101820',
            border: '1px solid #243848',
            padding: '1px 4px',
            pointerEvents: 'none',
          }}
        >
          ⌘K
        </kbd>
      </div>

      {/* Dropdown */}
      {isOpen && (
        <div
          style={{
            position: 'absolute',
            top: 'calc(100% + 6px)',
            right: 0,
            zIndex: 50,
            width: '22rem',
            maxHeight: '24rem',
            overflowY: 'auto',
            background: '#0d1520',
            border: '1px solid #2a5070',
            boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
          }}
        >
          {pagefindError ? (
            <div style={{ padding: '1rem', textAlign: 'center' }}>
              <div style={{ color: '#d4920a', fontSize: '0.8rem', marginBottom: '0.25rem' }}>Search unavailable</div>
              <div style={{ color: '#4a6878', fontSize: '0.72rem' }}>
                Run <code style={{ color: '#ecb030' }}>pnpm build</code> to enable search.
              </div>
            </div>
          ) : isLoading ? (
            <div style={{ padding: '1.5rem', textAlign: 'center', color: '#4a6878', fontSize: '0.8rem' }}>
              Searching…
            </div>
          ) : results.length > 0 ? (
            <>
              <div style={{ padding: '0.35rem 0.75rem', fontSize: '0.55rem', fontWeight: 700, letterSpacing: '0.15em', textTransform: 'uppercase', color: '#4a6878', borderBottom: '1px solid #192838' }}>
                {results.length} result{results.length !== 1 ? 's' : ''}
              </div>
              <div ref={resultsRef}>
                {results.map((result, i) => (
                  <button
                    key={result.id}
                    onClick={() => { window.location.href = result.url; setIsOpen(false); }}
                    onMouseEnter={() => setSelectedIndex(i)}
                    style={{
                      display: 'block',
                      width: '100%',
                      textAlign: 'left',
                      padding: '0.6rem 0.75rem',
                      borderBottom: '1px solid #192838',
                      background: i === selectedIndex ? 'rgba(212,146,10,0.08)' : 'transparent',
                      cursor: 'pointer',
                      transition: 'background 0.1s',
                    }}
                  >
                    <div style={{ fontSize: '0.82rem', fontWeight: 500, color: i === selectedIndex ? '#d8eaf5' : '#b0c4d4', marginBottom: '0.2rem' }}>
                      {result.title}
                    </div>
                    <div
                      style={{ fontSize: '0.72rem', color: '#4a6878', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}
                      dangerouslySetInnerHTML={{ __html: result.excerpt }}
                    />
                  </button>
                ))}
              </div>
              <div style={{ padding: '0.35rem 0.75rem', fontSize: '0.55rem', color: '#4a6878', borderTop: '1px solid #192838', display: 'flex', gap: '0.75rem', fontFamily: "'JetBrains Mono', monospace" }}>
                <span><kbd style={{ padding: '1px 3px', background: '#101820', border: '1px solid #243848' }}>↑↓</kbd> nav</span>
                <span><kbd style={{ padding: '1px 3px', background: '#101820', border: '1px solid #243848' }}>↵</kbd> open</span>
                <span><kbd style={{ padding: '1px 3px', background: '#101820', border: '1px solid #243848' }}>esc</kbd> close</span>
              </div>
            </>
          ) : query ? (
            <div style={{ padding: '1.5rem', textAlign: 'center', color: '#4a6878', fontSize: '0.8rem' }}>
              No results for &ldquo;{query}&rdquo;
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}
