import { Buffer } from 'node:buffer';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

export function parseArgs(argv: string[]): {
  positionals: string[];
  flags: Map<string, string[]>;
} {
  const flags = new Map<string, string[]>();
  const positionals: string[] = [];

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i]!;
    if (!token.startsWith('--')) {
      positionals.push(token);
      continue;
    }

    const key = token.slice(2);
    const values: string[] = [];
    while (i + 1 < argv.length && !argv[i + 1]!.startsWith('--')) {
      values.push(argv[i + 1]!);
      i += 1;
    }
    flags.set(key, values.length > 0 ? values : ['true']);
  }

  return { positionals, flags };
}

export function requireFlag(flags: Map<string, string[]>, name: string): string {
  const values = flags.get(name);
  if (!values || values.length === 0) {
    throw new Error(`Missing required --${name} argument.`);
  }
  return values[0]!;
}

export function optionalFlag(flags: Map<string, string[]>, name: string): string | undefined {
  return flags.get(name)?.[0];
}

export async function readJson<T>(pathname: string): Promise<T> {
  const raw = await readFile(pathname, 'utf-8');
  return JSON.parse(raw) as T;
}

export function jsonReplacer(_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? value.toString() : value;
}

export function stringifyJson(value: unknown): string {
  return JSON.stringify(value, jsonReplacer, 2);
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(value, Object.keys(value as Record<string, unknown>).sort(), 2);
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

export function hexToUint64Limbs(hex: string): [bigint, bigint, bigint, bigint] {
  const normalized = hex.replace(/^0x/, '').padStart(64, '0');
  const limbs: bigint[] = [];
  for (let index = 0; index < 4; index += 1) {
    const start = index * 16;
    limbs.push(BigInt(`0x${normalized.slice(start, start + 16)}`));
  }
  return limbs as [bigint, bigint, bigint, bigint];
}

export function ensureHex32(value: string): string {
  const normalized = value.trim().replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new Error(`Expected a 32-byte hex string, got '${value}'.`);
  }
  return normalized;
}

export function bytesToHex(value: Uint8Array): string {
  return Buffer.from(value).toString('hex');
}

export function valueToUint64Limbs(value: unknown): [bigint, bigint, bigint, bigint] {
  if (value instanceof Uint8Array) {
    return hexToUint64Limbs(bytesToHex(value));
  }
  if (Array.isArray(value) && value.every((entry) => typeof entry === 'number')) {
    return hexToUint64Limbs(bytesToHex(Uint8Array.from(value)));
  }
  if (typeof value === 'string') {
    return hexToUint64Limbs(ensureHex32(value));
  }
  throw new Error(`Cannot convert value to 32-byte commitment limbs: ${String(value)}.`);
}

export function asBigInt(value: unknown): bigint {
  if (typeof value === 'bigint') {
    return value;
  }
  if (typeof value === 'number') {
    return BigInt(value);
  }
  if (typeof value === 'boolean') {
    return value ? 1n : 0n;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) {
      return 0n;
    }
    return trimmed.startsWith('0x') ? BigInt(trimmed) : BigInt(trimmed);
  }
  throw new Error(`Cannot convert value to bigint: ${String(value)}.`);
}

export function asBoolean(value: unknown): boolean {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'bigint') {
    return value !== 0n;
  }
  if (typeof value === 'number') {
    return value !== 0;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim().toLowerCase();
    if (trimmed === 'true') {
      return true;
    }
    if (trimmed === 'false' || trimmed === '') {
      return false;
    }
    return asBigInt(trimmed) !== 0n;
  }
  return Boolean(value);
}

function normalizeStateValue(value: unknown): unknown {
  if (value instanceof Uint8Array) {
    return `0x${bytesToHex(value)}`;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => normalizeStateValue(entry));
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, normalizeStateValue(entry)]),
    );
  }
  return value;
}

export function normalizeStateSnapshot(
  snapshot: Record<string, unknown>,
): Record<string, unknown> {
  return normalizeStateValue(snapshot) as Record<string, unknown>;
}
