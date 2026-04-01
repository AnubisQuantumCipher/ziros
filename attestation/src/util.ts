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
