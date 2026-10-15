import { pretty } from '../lib/json';

interface Props {
  value: unknown;
  /** Max height in px before the block scrolls. */
  maxHeight?: number;
  className?: string;
}

export default function JsonBlock({ value, maxHeight = 260, className = '' }: Props) {
  return (
    <pre className={`json ${className}`} style={{ maxHeight }}>
      {pretty(value)}
    </pre>
  );
}
