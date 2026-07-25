/**
 * A section's label, set as an eyebrow with a rule running out from it.
 *
 *   <SectionHeader title="How it works" note="three moving parts" />
 */
export function SectionHeader({ title, note }: { title: string; note?: string }) {
  return (
    <div className="flex items-center gap-4 mb-8">
      <h2 className="t-eyebrow shrink-0">{title}</h2>
      <span className="flex-1 h-px bg-hairline" />
      {note && <span className="t-eyebrow shrink-0 hidden sm:block">{note}</span>}
    </div>
  );
}
