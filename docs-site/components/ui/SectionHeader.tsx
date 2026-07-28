/**
 * A section's label, set as an eyebrow with a rule running out from it.
 *
 *   <SectionHeader title="How it works" note="three moving parts" />
 *
 * `tight` is the index-page spacing. A listing page stacks several of
 * these straight onto card grids, where the landing page's airier gap
 * reads as a break between sections rather than a label above one.
 */
export function SectionHeader({
  title,
  note,
  tight,
}: {
  title: string;
  note?: string;
  tight?: boolean;
}) {
  return (
    <div className={`flex items-center gap-4 ${tight ? 'mb-4' : 'mb-8'}`}>
      <h2 className="t-eyebrow shrink-0">{title}</h2>
      <span className="section-rule" />
      {note && <span className="t-eyebrow shrink-0 hidden sm:block">{note}</span>}
    </div>
  );
}
