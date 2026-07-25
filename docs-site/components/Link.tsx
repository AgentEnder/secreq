import type { AnchorHTMLAttributes, ReactNode } from 'react';
import { applyBaseUrl } from '../utils/base-url';

interface LinkProps extends AnchorHTMLAttributes<HTMLAnchorElement> {
  children: ReactNode;
  active?: boolean;
}

export function Link({
  children,
  active,
  href,
  className = '',
  ...props
}: LinkProps) {
  return (
    <a
      href={href ? applyBaseUrl(href) : href}
      className={`transition-all duration-200 ${active ? 'text-switch-accent font-medium' : 'text-switch-text-dim hover:text-switch-text'} ${className.includes('no-underline') ? '' : 'hover:text-switch-accent'} ${className}`}
      {...props}
    >
      {children}
    </a>
  );
}
