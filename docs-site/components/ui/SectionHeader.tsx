/**
 * SectionHeader — Mission Control section label with extending horizontal rule.
 * Matches the .features-section-header / .install-section-header pattern from theme-4.
 *
 * Usage:
 *   <SectionHeader title="Subsystems" />
 *   <SectionHeader title="Installation" right={<span>4 methods</span>} />
 */
export function SectionHeader({
  title,
  right,
}: {
  title: string;
  right?: React.ReactNode;
}) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '1.5rem',
        marginBottom: '2rem',
      }}
    >
      <h2
        style={{
          fontFamily: "'Space Grotesk', sans-serif",
          fontSize: '0.7rem',
          fontWeight: 700,
          letterSpacing: '0.3em',
          textTransform: 'uppercase',
          color: '#4a6878',
          whiteSpace: 'nowrap',
          margin: 0,
        }}
      >
        {title}
      </h2>
      <div style={{ flex: 1, height: '1px', background: '#192838' }} />
      {right && (
        <span
          style={{
            fontSize: '0.6rem',
            fontWeight: 600,
            letterSpacing: '0.15em',
            textTransform: 'uppercase',
            color: '#4a6878',
          }}
        >
          {right}
        </span>
      )}
    </div>
  );
}
