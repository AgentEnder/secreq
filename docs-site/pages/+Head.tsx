import { applyBaseUrl } from '../utils/base-url';
import './tailwind.css';

export function Head() {
  return (
    <>
      <link rel="icon" type="image/svg+xml" href={applyBaseUrl('/favicon.svg')} />
      <meta name="theme-color" content="#06090e" />
      <link rel="preconnect" href="https://fonts.googleapis.com" />
      <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
      <link
        href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap"
        rel="stylesheet"
      />
    </>
  );
}
