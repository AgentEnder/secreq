/**
 * StatusDot — Colored indicator dot with semantic glow.
 * Color is semantic: green=nominal, amber=warning/primary, blue=info, red=error.
 */
export type DotColor = 'green' | 'amber' | 'blue' | 'red';

const STYLES: Record<DotColor, { background: string; boxShadow: string }> = {
  green: { background: '#28b060', boxShadow: '0 0 4px rgba(40,176,96,0.6)' },
  amber: { background: '#d4920a', boxShadow: '0 0 4px rgba(212,146,10,0.6)' },
  blue:  { background: '#2e80c0', boxShadow: '0 0 4px rgba(46,128,192,0.6)' },
  red:   { background: '#b83030', boxShadow: '0 0 4px rgba(184,48,48,0.6)' },
};

export function StatusDot({ color = 'green' }: { color?: DotColor }) {
  const s = STYLES[color];
  return (
    <span
      style={{
        display: 'inline-block',
        width: 6,
        height: 6,
        borderRadius: '50%',
        flexShrink: 0,
        ...s,
      }}
    />
  );
}
