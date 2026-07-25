import { applyBaseUrl } from '../utils/base-url';
import './tailwind.css';

/**
 * Resolve the reader's desktop before first paint.
 *
 * secreq has no theme setting and no OS setting — its windows are natively
 * themed and follow the host — so the docs take the same two signals and
 * show the screenshots that match. A reader on Windows sees the Windows
 * ContentDialog, not a macOS sheet they will never encounter.
 *
 * Both are overridable, and a stored override wins: someone may be reading
 * on a Mac about a Linux box. Running synchronously in <head> is what keeps
 * a light-mode reader from being flashed a dark page, and keeps the
 * screenshots from visibly swapping after hydration.
 */
const DESKTOP_INIT = `
(function () {
  var root = document.documentElement;
  try {
    var stored = localStorage.getItem('sq-theme');
    root.dataset.theme = stored || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  } catch (e) {
    root.dataset.theme = 'dark';
  }
  try {
    var storedOs = localStorage.getItem('sq-os');
    if (storedOs) { root.dataset.os = storedOs; return; }
    var hint = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '';
    var ua = navigator.userAgent || '';
    var probe = (hint + ' ' + ua).toLowerCase();
    // Order matters: an iPhone UA contains "mac", and an Android UA contains
    // "linux", so the mobile cases have to be settled first. Neither runs
    // secreq, so they get the desktop chrome their vendor is closest to.
    root.dataset.os =
      /android/.test(probe) ? 'gnome'
      : /iphone|ipad|ipod|mac/.test(probe) ? 'macos'
      : /win/.test(probe) ? 'windows'
      : /linux|x11|cros|bsd/.test(probe) ? 'gnome'
      : 'macos';
  } catch (e) {
    root.dataset.os = 'macos';
  }
})();
`;

export function Head() {
  return (
    <>
      <link rel="icon" type="image/svg+xml" href={applyBaseUrl('/favicon.svg')} />
      <meta name="color-scheme" content="dark light" />
      <link rel="preconnect" href="https://fonts.googleapis.com" />
      <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
      <link
        href="https://fonts.googleapis.com/css2?family=Instrument+Sans:ital,wght@0,400..700;1,400..700&family=JetBrains+Mono:wght@400;500;600&family=Martian+Mono:wght@400..700&display=swap"
        rel="stylesheet"
      />
      <script dangerouslySetInnerHTML={{ __html: DESKTOP_INIT }} />
    </>
  );
}
