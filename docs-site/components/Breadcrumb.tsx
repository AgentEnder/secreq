import { Link } from './Link';

export interface Crumb {
  label: string;
  /** Omit on the current page — the tip of the trail is never a link. */
  href?: string;
}

/**
 * The trail above a page title.
 *
 * It exists as a component because the hand-written version was pasted into
 * three pages and each copy got the same two things wrong. It collapses a
 * crumb that only repeats the one before it — every doc named after its own
 * section rendered `Getting started / Getting started` — and it marks the last
 * crumb as the current page instead of styling it like one more link. The tip
 * sits a step below the `h1` it introduces; the trail is orientation, not a
 * second headline.
 */
export function Breadcrumb({ trail, className }: { trail: Crumb[]; className?: string }) {
  const crumbs = collapseRepeats(trail);
  if (crumbs.length === 0) return null;

  return (
    <nav
      aria-label="Breadcrumb"
      className={className ? `crumbs ${className}` : 'crumbs'}
      data-pagefind-ignore
    >
      <ol>
        {crumbs.map((crumb, index) => {
          const isTip = index === crumbs.length - 1;
          return (
            <li key={`${crumb.label}-${index}`}>
              {index > 0 && (
                <span className="crumb-sep" aria-hidden="true">
                  /
                </span>
              )}
              {crumb.href && !isTip ? (
                <Link href={crumb.href}>{crumb.label}</Link>
              ) : (
                <span aria-current={isTip ? 'page' : undefined}>{crumb.label}</span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

/**
 * Drop a crumb whose label repeats its predecessor's, keeping the later one:
 * the survivor is the page itself, and a page does not link to its own name.
 */
function collapseRepeats(trail: Crumb[]): Crumb[] {
  return trail.filter((crumb, index) => {
    const next = trail[index + 1];
    return !next || !sameLabel(crumb.label, next.label);
  });
}

function sameLabel(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}
