import type { JsonObject, JsonValue } from '../events';

export function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function asObject(value: unknown): JsonObject {
  return isObject(value) ? value : {};
}

export function asArray(value: unknown): JsonValue[] {
  return Array.isArray(value) ? (value as JsonValue[]) : [];
}

export function asObjectArray(value: unknown): JsonObject[] {
  return asArray(value).filter(isObject);
}

export function asString(value: unknown, fallback = ''): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return fallback;
}

export function asNullableString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

export function asNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

export function asNullableNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

export function asBoolean(value: unknown, fallback = false): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

export function asStringArray(value: unknown): string[] {
  return asArray(value).filter((item): item is string => typeof item === 'string');
}

export function asNumberRecord(value: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [key, item] of Object.entries(asObject(value))) {
    if (typeof item === 'number') out[key] = item;
  }
  return out;
}

export function pretty(value: unknown): string {
  try {
    const text = JSON.stringify(value, null, 2);
    return text === undefined ? 'undefined' : text;
  } catch {
    return String(value);
  }
}

export function formatScore(value: number | null | undefined, digits = 4): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return value.toFixed(digits);
}

export function formatMs(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  if (value >= 1000) return `${(value / 1000).toFixed(2)} s`;
  return `${value.toFixed(value < 10 ? 1 : 0)} ms`;
}

export function formatEpoch(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  const ms = value > 1e12 ? value : value * 1000;
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatCount(value: number): string {
  return new Intl.NumberFormat().format(value);
}
