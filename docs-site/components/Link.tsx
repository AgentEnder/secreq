import type { AnchorHTMLAttributes, ReactNode } from 'react';
import { applyBaseUrl } from '../utils/base-url';

interface LinkProps extends AnchorHTMLAttributes<HTMLAnchorElement> {
  children: ReactNode;
}

/**
 * An internal link with the site's base URL applied.
 *
 * Styling is deliberately not its business — it used to inject its own
 * colour and hover classes, which meant every caller had to fight them back
 * off. Callers now say what a link looks like where they use it.
 */
export function Link({ children, href, ...props }: LinkProps) {
  return (
    <a href={href ? applyBaseUrl(href) : href} {...props}>
      {children}
    </a>
  );
}
