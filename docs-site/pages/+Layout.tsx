import React, { useEffect, useState } from 'react';
import { usePageContext } from 'vike-react/usePageContext';
import { Link } from '../components/Link';
import { PagefindSearch } from '../components/PagefindSearch';
import type { NavigationItem } from '../server/utils/docs';

const GITHUB_URL = 'https://github.com/AgentEnder/secreq';

export default function Layout({ children }: { children: React.ReactNode }) {
  const pageContext = usePageContext();
  const pathname = pageContext.urlPathname;
  const navigation: NavigationItem[] =
    ((pageContext as unknown as Record<string, unknown>).navigation as NavigationItem[]) ?? [];

  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const isLandingPage = pathname === '/' || pathname === '';
  const showSidebar = !isLandingPage && navigation.length > 0;

  useEffect(() => {
    setMobileMenuOpen(false);
  }, [pathname]);

  return (
    <div className="min-h-screen bg-switch-bg bg-grid-pattern text-switch-text" style={{ paddingBottom: '44px' }}>
      {/* Header */}
      <header
        className="sticky top-0 z-40 border-b border-switch-border"
        style={{ background: '#0d1520', height: '54px' }}
        data-pagefind-ignore
      >
        <div className="flex items-center h-full px-6 gap-5">
          <div className="hidden md:flex items-center gap-5 pr-5 border-r border-switch-border shrink-0">
            <div className="telem-cell">
              <span className="telem-key">STATUS</span>
              <span className="telem-val green flex items-center gap-1">
                <span className="status-dot green" />
                NOMINAL
              </span>
            </div>
            <div className="telem-cell">
              <span className="telem-key">PLATFORM</span>
              <span className="telem-val" style={{ color: '#50a0e0' }}>
                UNIX
              </span>
            </div>
          </div>

          {/* Logo */}
          <Link href="/" className="flex items-center gap-2 no-underline shrink-0" style={{ marginRight: 'auto' }}>
            <span
              className="text-white font-bold"
              style={{ background: '#d4920a', fontSize: '0.55rem', letterSpacing: '0.1em', padding: '2px 6px', color: '#06090e' }}
            >
              SQ
            </span>
            <span
              className="text-switch-text-bright"
              style={{ fontFamily: "'Bebas Neue', sans-serif", fontSize: '1.4rem', letterSpacing: '0.1em' }}
            >
              sec<span style={{ color: '#d4920a' }}>req</span>
            </span>
          </Link>

          {/* Nav links */}
          <nav className="hidden md:flex items-stretch h-full">
            {[{ label: 'Docs', href: '/docs' }, { label: 'Schemas', href: '/schemas' }].map((link) => (
              <Link
                key={link.href}
                href={link.href}
                active={pathname.startsWith(link.href)}
                className="flex items-center px-4 text-sm font-medium transition-colors border-l border-switch-border hover:text-switch-text-bright"
                style={{
                  color: pathname.startsWith(link.href) ? '#d8eaf5' : '#4a6878',
                  letterSpacing: '0.04em',
                  height: '54px',
                }}
              >
                {link.label}
              </Link>
            ))}
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center px-4 text-sm font-medium transition-colors border-l border-r border-switch-border hover:text-switch-text-bright"
              style={{ color: '#4a6878', letterSpacing: '0.04em', height: '54px' }}
            >
              GitHub
            </a>
          </nav>

          <div className="hidden md:block" style={{ marginLeft: '0.5rem' }}>
            <PagefindSearch />
          </div>

          {/* Mobile menu toggle */}
          <button
            className="md:hidden p-1.5 text-switch-text-dim hover:text-switch-text transition-colors"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle menu"
          >
            {mobileMenuOpen ? (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            ) : (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            )}
          </button>
        </div>
      </header>

      {/* Mobile nav overlay */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-30 bg-black/60 md:hidden" onClick={() => setMobileMenuOpen(false)}>
          <div
            className="absolute top-[54px] left-0 right-0 border-b border-switch-border animate-fade-in"
            style={{ background: '#0d1520' }}
            onClick={(e) => e.stopPropagation()}
          >
            <nav className="px-5 py-3 border-b border-switch-border space-y-1">
              <Link
                href="/docs"
                active={pathname.startsWith('/docs')}
                className="block py-2 px-3 text-sm font-medium text-switch-text-dim hover:text-switch-text hover:bg-switch-bg-raised transition-all"
              >
                Docs
              </Link>
              <Link
                href="/schemas"
                active={pathname.startsWith('/schemas')}
                className="block py-2 px-3 text-sm font-medium text-switch-text-dim hover:text-switch-text hover:bg-switch-bg-raised transition-all"
              >
                Schemas
              </Link>
              <a
                href={GITHUB_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="block py-2 px-3 text-sm font-medium text-switch-text-dim hover:text-switch-text hover:bg-switch-bg-raised transition-all"
              >
                GitHub
              </a>
            </nav>
            {navigation.length > 0 && (
              <div className="px-5 py-4">
                <SidebarContent navigation={navigation} pathname={pathname} />
              </div>
            )}
          </div>
        </div>
      )}

      {/* Body */}
      {showSidebar ? (
        <div className="doc-layout">
          <aside
            className="hidden md:block border-r border-switch-border overflow-y-auto bg-switch-bg-raised/50"
            style={{ position: 'sticky', top: '54px', height: 'calc(100vh - 54px - 44px)' }}
            data-pagefind-ignore
          >
            <SidebarContent navigation={navigation} pathname={pathname} />
          </aside>

          <main className="min-w-0 px-5 py-6 md:px-10 md:py-10">{children}</main>
        </div>
      ) : (
        <main>{children}</main>
      )}

      <BottomNav pathname={pathname} />
    </div>
  );
}

function BottomNav({ pathname }: { pathname: string }) {
  const isLanding = pathname === '/' || pathname === '';
  const isDocs = pathname.startsWith('/docs');

  return (
    <nav className="nav-bar-bottom" data-pagefind-ignore>
      <div className="nav-bar-section">
        <span className="nav-bar-label">Pages</span>
        <Link href="/" className={`nav-page-link${isLanding ? ' active' : ''}`}>
          Home
        </Link>
        <Link href="/docs" className={`nav-page-link${isDocs ? ' active' : ''}`}>
          Docs
        </Link>
        <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer" className="nav-page-link hidden sm:inline">
          GitHub
        </a>
      </div>

      <div className="nav-bar-section">
        <div className="telem-cell">
          <span className="telem-key">Project</span>
          <span className="telem-val" style={{ color: '#50a0e0' }}>
            secreq
          </span>
        </div>
      </div>
    </nav>
  );
}

function SidebarContent({ navigation, pathname }: { navigation: NavigationItem[]; pathname: string }) {
  return (
    <nav style={{ padding: '1.5rem 0' }}>
      {navigation.map((item) => (
        <SidebarItem key={item.title} item={item} pathname={pathname} />
      ))}
    </nav>
  );
}

function SidebarItem({ item, pathname }: { item: NavigationItem; pathname: string }) {
  const hasChildren = item.children && item.children.length > 0;
  const isActive = item.path ? pathname === item.path : false;
  const hasActiveChild = item.children?.some(
    (child) => child.path && (pathname === child.path || pathname.startsWith(child.path + '/'))
  );

  const [open, setOpen] = useState(isActive || !!hasActiveChild);

  if (!hasChildren) {
    return (
      <Link
        href={item.path ?? '#'}
        active={isActive}
        className="flex items-center gap-2.5 text-sm font-medium transition-all"
        style={{
          padding: '0.35rem 1.25rem',
          color: isActive ? '#d4920a' : '#4a6878',
          background: isActive ? 'rgba(212,146,10,0.12)' : 'transparent',
          borderLeft: isActive ? '2px solid #d4920a' : '2px solid transparent',
          paddingLeft: isActive ? 'calc(1.25rem - 2px)' : '1.25rem',
          textDecoration: 'none',
        }}
      >
        {item.title}
      </Link>
    );
  }

  const groupActive = isActive || !!hasActiveChild;

  return (
    <div>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0.35rem 1rem 0.35rem 1.25rem',
          background: groupActive ? 'rgba(46,128,192,0.06)' : 'rgba(255,255,255,0.02)',
          borderLeft: groupActive ? '2px solid #2e80c0' : '2px solid #192838',
          cursor: 'pointer',
        }}
        onClick={() => setOpen(!open)}
        role="button"
        aria-expanded={open}
      >
        <span
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            fontSize: '0.55rem',
            fontWeight: 700,
            letterSpacing: '0.2em',
            textTransform: 'uppercase',
            color: groupActive ? '#50a0e0' : '#4a6878',
          }}
        >
          <span className="status-dot blue" />
          {item.path ? (
            <a href={item.path} style={{ color: 'inherit', textDecoration: 'none' }} onClick={(e) => e.stopPropagation()}>
              {item.title}
            </a>
          ) : (
            item.title
          )}
        </span>
        <svg
          style={{
            width: '0.6rem',
            height: '0.6rem',
            flexShrink: 0,
            color: '#4a6878',
            transform: open ? 'rotate(180deg)' : 'rotate(0deg)',
            transition: 'transform 0.2s',
          }}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </div>

      {open && (
        <div className="animate-fade-in" style={{ borderLeft: '1px solid #192838', marginLeft: '1.25rem', paddingBottom: '0.25rem' }}>
          {item.children!.map((child) => {
            const childActive = child.path
              ? pathname === child.path || pathname.startsWith(child.path + '/')
              : false;
            return (
              <Link
                key={child.path ?? child.title}
                href={child.path ?? '#'}
                active={childActive}
                className="flex items-center text-sm font-medium transition-all"
                style={{
                  padding: '0.3rem 1rem',
                  color: childActive ? '#d4920a' : '#4a6878',
                  background: childActive ? 'rgba(212,146,10,0.10)' : 'transparent',
                  borderLeft: childActive ? '2px solid #d4920a' : '2px solid transparent',
                  paddingLeft: childActive ? 'calc(1rem - 2px)' : '1rem',
                  textDecoration: 'none',
                }}
              >
                {child.title}
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
