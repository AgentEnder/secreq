/**
 * TelemCell — Mission Control telemetry display.
 * Stacks a tiny uppercase label over a monospaced value.
 *
 * Usage:
 *   <TelemCell label="STATUS" value="NOMINAL" color="green" />
 */
export type TelemColor = 'amber' | 'green' | 'blue' | 'red' | 'dim';

const COLOR_MAP: Record<TelemColor, string> = {
  amber: '#d4920a',
  green: '#28b060',
  blue:  '#50a0e0',
  red:   '#b83030',
  dim:   '#4a6878',
};

export function TelemCell({
  label,
  value,
  color = 'amber',
}: {
  label: string;
  value: React.ReactNode;
  color?: TelemColor;
}) {
  return (
    <div className="telem-cell">
      <span className="telem-key">{label}</span>
      <span
        className="telem-val"
        style={{ color: COLOR_MAP[color] }}
      >
        {value}
      </span>
    </div>
  );
}
