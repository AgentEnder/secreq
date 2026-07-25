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
          className="absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none w-3.5 h-3.5 text-text-3"
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <input
          ref={inputRef}
          type="search"
          value={query}
          onChange={(e) => handleSearch(e.target.value)}
          onFocus={() => query && setIsOpen(true)}
          onKeyDown={handleKeyDown}
          placeholder="Search the docs"
          aria-label="Search the docs"
          className="search-input"
        />
        <kbd className="key absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none hidden lg:block">
          ⌘K
        </kbd>
      </div>

      {isOpen && (
        <div className="search-results">
          {pagefindError ? (
            <p className="p-4 text-center text-sm text-text-2">
              Search needs a production build. Run <code>pnpm build</code> to generate the index.
            </p>
          ) : isLoading ? (
            <p className="p-6 text-center text-sm text-text-3">Searching…</p>
          ) : results.length > 0 ? (
            <>
              <p className="t-eyebrow px-3 py-2 border-b border-hairline">
                {results.length} result{results.length !== 1 ? 's' : ''}
              </p>
              <div ref={resultsRef}>
                {results.map((result, i) => (
                  <button
                    key={result.id}
                    type="button"
                    onClick={() => {
                      window.location.href = result.url;
                      setIsOpen(false);
                    }}
                    onMouseEnter={() => setSelectedIndex(i)}
                    className="search-hit"
                    data-selected={i === selectedIndex}
                  >
                    <span className="block text-sm font-semibold text-text mb-0.5">
                      {result.title}
                    </span>
                    <span
                      className="search-excerpt"
                      dangerouslySetInnerHTML={{ __html: result.excerpt }}
                    />
                  </button>
                ))}
              </div>
              <p className="flex gap-4 px-3 py-2 border-t border-hairline t-meta">
                <span>
                  <kbd className="key">↑↓</kbd> move
                </span>
                <span>
                  <kbd className="key">↵</kbd> open
                </span>
                <span>
                  <kbd className="key">esc</kbd> close
                </span>
              </p>
            </>
          ) : query ? (
            <p className="p-6 text-center text-sm text-text-3">
              Nothing matches &ldquo;{query}&rdquo;.
            </p>
          ) : null}
        </div>
      )}
    </div>
  );
}
