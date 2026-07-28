import React, { useEffect, useState } from 'react';
import { usePageContext } from 'vike-react/usePageContext';
import { Link } from '../components/Link';
import { Ambient } from '../components/Ambient';
import { OsPicker } from '../components/OsPicker';
import { PagefindSearch } from '../components/PagefindSearch';
import { ThemeToggle } from '../components/ThemeToggle';
import { ShotLightbox } from '../components/ui';
import type { NavigationItem } from '../server/utils/docs';

const GITHUB_URL = 'https://github.com/AgentEnder/secreq';

const NAV = [
  { label: 'Docs', href: '/docs' },
  { label: 'API', href: '/api' },
  { label: 'Schemas', href: '/schemas' },
];

export default function Layout({ children }: { children: React.ReactNode }) {
  const pageContext = usePageContext();
  const pathname = pageContext.urlPathname;
  const navigation: NavigationItem[] =
    ((pageContext as unknown as Record<string, unknown>).navigation as NavigationItem[]) ?? [];

  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    setMenuOpen(false);
  }, [pathname]);

  const isLanding = pathname === '/' || pathname === '';
  const showRail = !isLanding && navigation.length > 0;

  return (
    // No background here on purpose: `html` already paints the page colour,
    // and a background on this wrapper would cover the `z-index: -1` ambient
    // layer, which sits between the two. `shell` leaves the gap the fixed
    // header no longer occupies in flow.
    <div className="shell min-h-screen text-text-2 relative">
      <Ambient />

      <header className="shell-header" data-pagefind-ignore>
        <div className="flex items-center h-full gap-2 px-4 sm:px-6">
          <Link href="/" className="brand">
            {/*
              The Gate Monogram, the same mark the app paints in its window
              headers. Geometry is the master at dev-docs/brand/logo.svg
              verbatim; the viewBox is cropped to the ink so the mark fills
              its 22px box. The trailing circle is the hover ping — a
              second dot that scales out from under the first.
            */}
            <svg className="brand-mark" viewBox="6 6 52 52" aria-hidden="true">
              <circle className="brand-ping" cx="32" cy="32" r="7" />
              <g className="brand-gate" fill="none" strokeWidth="7" strokeLinejoin="miter">
                <path d="M23 10 H13 V54 H23" />
                <path d="M41 10 H51 V54 H41" />
              </g>
              <circle className="brand-secret" cx="32" cy="32" r="7" />
            </svg>
            secreq
          </Link>

          <nav className="hidden md:flex items-stretch h-full ml-6">
            {NAV.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className="nav-link no-underline"
                data-active={pathname.startsWith(link.href)}
              >
                {link.label}
              </Link>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-1.5">
            <div className="hidden sm:block w-44 lg:w-56">
              <PagefindSearch />
            </div>

            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="icon-btn"
              aria-label="secreq on GitHub"
            >
              <svg
                width="16"
                height="16"
                viewBox="0 0 16 16"
                fill="currentColor"
                aria-hidden="true"
              >
                <path d="M8 0a8 8 0 0 0-2.5 15.6c.4.07.55-.17.55-.38v-1.35C3.84 14.3 3.4 13 3.4 13c-.36-.9-.87-1.15-.87-1.15-.71-.48.05-.47.05-.47.79.05 1.2.81 1.2.81.7 1.2 1.83.85 2.28.65.07-.5.27-.85.5-1.05-1.74-.2-3.56-.87-3.56-3.87 0-.85.3-1.55.8-2.1-.08-.2-.35-1 .08-2.07 0 0 .65-.21 2.14.8a7.4 7.4 0 0 1 3.9 0c1.49-1.01 2.14-.8 2.14-.8.43 1.07.16 1.87.08 2.07.5.55.8 1.25.8 2.1 0 3.01-1.83 3.67-3.57 3.86.28.24.53.72.53 1.45v2.15c0 .21.14.46.55.38A8 8 0 0 0 8 0z" />
              </svg>
            </a>

            <OsPicker />
            <ThemeToggle />

            <button
              type="button"
              className="icon-btn md:hidden"
              onClick={() => setMenuOpen(!menuOpen)}
              aria-expanded={menuOpen}
              aria-label={menuOpen ? 'Close the menu' : 'Open the menu'}
            >
              <svg
                width="18"
                height="18"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                aria-hidden="true"
              >
                {menuOpen ? (
                  <path d="M6 18 18 6M6 6l12 12" />
                ) : (
                  <path d="M4 7h16M4 12h16M4 17h16" />
                )}
              </svg>
            </button>
          </div>
        </div>
      </header>

      {menuOpen && (
        <div
          className="fixed inset-0 top-14 z-30 md:hidden bg-bg overflow-y-auto"
          data-pagefind-ignore
        >
          <nav className="border-b border-hairline py-2">
            {NAV.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className="rail-link no-underline"
                data-active={pathname.startsWith(link.href)}
              >
                {link.label}
              </Link>
            ))}
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="rail-link no-underline"
            >
              GitHub
            </a>
          </nav>
          <div className="sm:hidden px-4 py-3 border-b border-hairline">
            <PagefindSearch />
          </div>
          {navigation.length > 0 && <Rail navigation={navigation} pathname={pathname} />}
        </div>
      )}

      {showRail ? (
        <div className="doc-layout">
          <div
            className="rail-wrap hidden md:block border-r border-hairline overflow-y-auto"
            data-pagefind-ignore
          >
            <Rail navigation={navigation} pathname={pathname} />
          </div>
          <main className="min-w-0 px-5 py-9 md:px-10 md:py-12">{children}</main>
        </div>
      ) : (
        <main>{children}</main>
      )}

      {/* One viewer for the whole app. It portals to <body> and answers
          `secreq:shot-open` from any screenshot on the page, including the
          ones markdown injects as raw HTML. */}
      <ShotLightbox />
    </div>
  );
}

function Rail({ navigation, pathname }: { navigation: NavigationItem[]; pathname: string }) {
  return (
    <nav className="rail">
      {navigation.map((item) => (
        <div key={item.title} className="rail-group">
          {item.children ? (
            <>
              <span className="rail-group-label">{item.title}</span>
              {item.children.map((child) => (
                <RailLink key={child.path ?? child.title} item={child} pathname={pathname} />
              ))}
            </>
          ) : (
            <RailLink item={item} pathname={pathname} />
          )}
        </div>
      ))}
    </nav>
  );
}

function RailLink({ item, pathname }: { item: NavigationItem; pathname: string }) {
  const active = item.path ? pathname === item.path || pathname.startsWith(item.path + '/') : false;
  return (
    <Link href={item.path ?? '#'} className="rail-link no-underline" data-active={active}>
      {item.title}
    </Link>
  );
}
